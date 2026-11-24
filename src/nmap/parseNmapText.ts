import type { NmapHost, NmapOsMatch, NmapPort, NmapScan, NmapScript, NmapTraceHop } from '../model/types';
import { mergeHostRecords } from './mergeScanHosts';
import { normalizeTargets, parseTargets } from './targets';
import { stampHosts } from './scanFormat';

/**
 * nmap's two plain-text outputs: grepable (`-oG`), which is a machine format with
 * one tab-separated line per host, and normal (`-oN`), the report people paste into
 * tickets. Neither carries as much as XML, so whatever cannot be read is reported
 * as a warning rather than invented.
 */

export type TextScan = { scan: NmapScan; warnings: string[] };

const GREPABLE_INITIATED = /^#\s*Nmap\s+(\S+)\s+scan initiated (.*) as:\s*(.+)$/i;
const GREPABLE_DONE = /^#\s*Nmap done at (.*?)\s*--\s*(.+)$/i;
const NORMAL_START = /^Starting Nmap\s+(\S+)\s+\([^)]*\)\s+at\s+(.+)$/i;
const NORMAL_REPORT = /^Nmap scan report for\s+(.+)$/i;
const NORMAL_DONE = /^Nmap done:\s*(.+)$/i;
const PORT_ROW = /^(\d{1,5})\/(tcp|udp|sctp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/i;
const TRACE_ROW = /^(\d{1,3})\s+(?:([\d.]+)\s+ms\s+)?(\S+)\s*$/;
const MAC_LINE = /^MAC Address:\s*([0-9A-Fa-f:.-]+)(?:\s*\(([^)]*)\))?/;
const HOST_STATE = /^Host (?:is up|seems down)/i;
const NOT_SHOWN = /^Not shown:|^Ignored State:/i;

const isoDate = (value: string | undefined): string | undefined => {
  if (!value) return undefined;
  const parsed = Date.parse(value.trim());
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : undefined;
};

/** `OpenSSH 9.6 (protocol 2.0)` → product, version and the rest. */
function detailFields(detail: string | undefined): Partial<NmapPort> {
  const text = (detail ?? '').trim();
  if (!text) return {};
  const words = text.split(/\s+/);
  const versionAt = words.findIndex((word) => /^v?\d[\w.+-]*$/i.test(word));
  if (versionAt === 0) {
    return { version: words[0], ...(words.length > 1 ? { extrainfo: words.slice(1).join(' ') } : {}) };
  }
  if (versionAt > 0) {
    return {
      product: words.slice(0, versionAt).join(' '),
      version: words[versionAt],
      ...(words.length > versionAt + 1 ? { extrainfo: words.slice(versionAt + 1).join(' ') } : {}),
    };
  }
  return { product: text };
}

/** A `-oN` port row's service and version columns. */
function serviceFields(service: string, detail: string | undefined): Partial<NmapPort> {
  // `-oN` marks an uncertain service with a trailing “?”; it is still that service.
  const name = service?.replace(/\?$/, '');
  return { ...(name && name !== 'unknown' ? { service: name } : {}), ...detailFields(detail) };
}

const scriptFrom = (id: string, lines: string[]): NmapScript | null => {
  const output = lines
    .map((line) => line.replace(/^\|_?\s?/, '').trimEnd())
    .filter((line) => line.length > 0)
    .join('\n');
  return output ? { id, output } : null;
};

function hostId(ip: string, index: number): string {
  return `host-${ip.replace(/[^0-9a-zA-Z]+/g, '-')}-${index}`;
}

/** `10.0.0.1/open/tcp//ssh//OpenSSH 9.6/` → a port record. */
function grepablePort(token: string): NmapPort | null {
  const fields = token.split('/');
  const port = Number(fields[0]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  const state = fields[1] || 'unknown';
  const protocol = fields[2] || 'tcp';
  const service = fields[4] || undefined;
  return {
    port,
    protocol,
    state,
    ...(service ? { service } : {}),
    // The seventh field is the whole version string ("Samba 4.19"), not just a number.
    ...detailFields(fields[6]),
    scripts: [],
  };
}

export function parseGrepable(text: string, fileName: string): TextScan {
  const warnings: string[] = [];
  let args: string | undefined;
  let version: string | undefined;
  let startedAt: string | undefined;
  let summary: string | undefined;

  const hosts: NmapHost[] = [];
  let current: NmapHost | null = null;
  let index = 0;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (!line) continue;

    const initiated = GREPABLE_INITIATED.exec(line);
    if (initiated) {
      version = initiated[1];
      startedAt = isoDate(initiated[2]);
      args = initiated[3].trim();
      continue;
    }
    const done = GREPABLE_DONE.exec(line);
    if (done) {
      summary = done[2].trim();
      continue;
    }
    if (line.startsWith('#')) {
      if (!/^#\s*Ports scanned:/i.test(line) && !/^#\s*Nmap done at/i.test(line)) {
        warnings.push(line.replace(/^#\s*/, '').slice(0, 120));
      }
      continue;
    }

    if (line.startsWith('Host:')) {
      const [head, ...rest] = line.split('\t');
      const report = /^Host:\s*(\S+)(?:\s*\(([^)]*)\))?/i.exec(head);
      if (!report) {
        warnings.push(line.slice(0, 120));
        continue;
      }
      const ip = report[1];
      const name = report[2]?.trim();
      const fields = new Map<string, string>();
      for (const field of rest) {
        const [key, ...value] = field.split(':');
        if (key) fields.set(key.trim().toLowerCase(), value.join(':').trim());
      }
      const state = (fields.get('status') ?? 'Up').toLowerCase();
      const ports: NmapPort[] = [];
      const portText = fields.get('ports') ?? '';
      for (const token of portText.split(/\s*,\s*/)) {
        if (!token) continue;
        const port = grepablePort(token);
        if (port) ports.push(port);
        else warnings.push(`Unreadable port “${token.slice(0, 40)}” on ${ip}`);
      }
      const os: NmapOsMatch[] = [];
      const osText = fields.get('os');
      if (osText) osText.split(/\s*,\s*/).forEach((name, position) => {
        if (name) os.push({ name, accuracy: Math.max(50, 100 - position * 5) });
      });

      // nmap writes two lines per host – one with `Status:`, one with `Ports:` – so
      // the second line completes the first host rather than starting a new one.
      const record: NmapHost = {
        id: hostId(ip, index),
        ip,
        hostnames: name && !name.startsWith('(') ? [name] : [],
        status: state === 'up' ? 'up' : 'down',
        os,
        ports: ports.sort((a, b) => a.port - b.port),
        portsScanned: ports.length > 0,
        scripts: [],
        hops: [],
      };
      const existing = hosts.findIndex((host) => host.ip === ip);
      if (existing !== -1) {
        // Same merge rule as the XML reader: ports are unioned, not replaced.
        hosts[existing] = mergeHostRecords(hosts[existing], record);
        current = hosts[existing];
        continue;
      }

      index += 1;
      current = record;
      hosts.push(current);
      continue;
    }

    const mac = MAC_LINE.exec(line);
    if (mac && current) {
      current.mac = mac[1].toUpperCase();
      if (mac[2]) current.vendor = mac[2].trim();
      continue;
    }

    if (!/^#/.test(line) && current && line.includes(':')) {
      warnings.push(`Unreadable line: ${line.slice(0, 120)}`);
    }
  }

  if (hosts.length === 0) {
    warnings.push('No “Host:” lines were found – is this really nmap -oG output?');
  }
  const targets = normalizeTargets(parseTargets(args));
  const scan: NmapScan = {
    fileName,
    ...(args ? { args } : {}),
    ...(version ? { version } : {}),
    ...(targets.length > 0 ? { targets } : {}),
    ...(startedAt ? { startedAt } : {}),
    ...(summary ? { summary } : {}),
    hosts: stampHosts(hosts, fileName, startedAt),
  };
  return { scan, warnings: [...new Set(warnings)].slice(0, 6) };
}

export function parseNormal(text: string, fileName: string): TextScan {
  const warnings: string[] = [];
  let version: string | undefined;
  let startedAt: string | undefined;
  let summary: string | undefined;

  const hosts: NmapHost[] = [];
  let current: NmapHost | null = null;
  let lastPort: NmapPort | null = null;
  let lastScript: { id: string; lines: string[]; target: NmapPort | 'host' } | null = null;
  let inTrace = false;
  let hops: NmapTraceHop[] = [];

  const flushScript = () => {
    if (!lastScript) return;
    const script = scriptFrom(lastScript.id, lastScript.lines);
    if (script) {
      if (lastScript.target === 'host') current?.scripts.push(script);
      else lastScript.target.scripts.push(script);
    }
    lastScript = null;
  };

  const flushTrace = () => {
    if (current && hops.length > 0) {
      current.hops = hops.map((hop) => hop.ip);
    } else if (hops.length > 0 && hosts.length > 0) {
      hosts[hosts.length - 1].hops = hops.map((hop) => hop.ip);
    }
    hops = [];
    inTrace = false;
  };

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (!line.trim()) {
      flushScript();
      continue;
    }

    const start = NORMAL_START.exec(line);
    if (start) {
      version = start[1];
      startedAt = isoDate(start[2].replace(/\s+UTC$/, ''));
      continue;
    }
    const done = NORMAL_DONE.exec(line);
    if (done) {
      summary = done[1].trim();
      continue;
    }

    const report = NORMAL_REPORT.exec(line);
    if (report) {
      flushScript();
      flushTrace();
      const reportText = report[1].trim();
      const named = /^(.*?)\s*\(([^)]+)\)$/.exec(reportText);
      const ip = named ? named[2] : reportText;
      const hostname = named ? named[1] : '';
      current = {
        id: hostId(ip, hosts.length),
        ip,
        hostnames: hostname ? [hostname] : [],
        status: 'up',
        os: [],
        ports: [],
        portsScanned: false,
        scripts: [],
        hops: [],
      };
      hosts.push(current);
      lastPort = null;
      continue;
    }

    if (!current) continue;

    if (HOST_STATE.test(line)) {
      if (/seems down/i.test(line)) current.status = 'down';
      continue;
    }
    if (NOT_SHOWN.test(line)) continue;

    if (/^TRACEROUTE/i.test(line)) {
      flushScript();
      inTrace = true;
      continue;
    }
    if (inTrace) {
      if (/^HOP\b/i.test(line)) continue;
      const hop = TRACE_ROW.exec(line);
      if (hop && hop[3] && hop[3] !== '-') {
        hops.push({ ip: hop[3], ttl: Number(hop[1]), ...(hop[2] ? { rtt: Number(hop[2]) } : {}) });
      } else if (!/^\s*\d/.test(line)) {
        inTrace = false;
      }
      continue;
    }

    const mac = MAC_LINE.exec(line);
    if (mac) {
      current.mac = mac[1].toUpperCase();
      if (mac[2]) current.vendor = mac[2].trim();
      continue;
    }

    const portRow = PORT_ROW.exec(line);
    if (portRow) {
      flushScript();
      const [, count, protocol, state, service, rest] = portRow;
      const port: NmapPort = {
        port: Number(count),
        protocol: protocol.toLowerCase(),
        state,
        ...serviceFields(service, rest),
        scripts: [],
      };
      current.ports.push(port);
      current.portsScanned = true;
      lastPort = port;
      continue;
    }

    const scriptLine = /^\|_?\s*([\w.-]+):\s*(.*)$/.exec(line);
    if (scriptLine) {
      flushScript();
      lastScript = { id: scriptLine[1], lines: [scriptLine[2] ?? ''], target: lastPort ?? 'host' };
      continue;
    }
    if (/^\|/.test(line) && lastScript) {
      lastScript.lines.push(line);
      continue;
    }

    const osDetails = /^OS details:\s*(.+)$/i.exec(line);
    if (osDetails) {
      current.os.unshift({ name: osDetails[1].trim(), accuracy: 90 });
      continue;
    }
    const running = /^Running:\s*(.+)$/i.exec(line);
    if (running && current.os.length === 0) current.os.push({ name: running[1].trim(), accuracy: 70 });
    if (/^Device type:|^OS CPE:|^Service Info:|^Aggressive OS guesses:/i.test(line)) continue;
  }

  flushScript();
  flushTrace();
  if (hosts.length === 0) {
    warnings.push('No “Nmap scan report for” blocks were found – is this really nmap -oN output?');
  }

  return {
    scan: {
      fileName,
      ...(version ? { version } : {}),
      ...(startedAt ? { startedAt } : {}),
      ...(summary ? { summary } : {}),
      hosts: stampHosts(
        hosts.map((host) => ({ ...host, ports: host.ports.sort((a, b) => a.port - b.port) })),
        fileName,
        startedAt,
      ),
    },
    warnings: [...new Set(warnings)].slice(0, 6),
  };
}
