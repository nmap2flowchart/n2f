export type NmapScript = {
  id: string;
  output: string;
};

/** How a finding is rated, worst first. */
export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** One vulnerability an NSE script reported. */
export type VulnRef = {
  /** A CVE id when the script names one, else the script id. */
  id: string;
  cvss?: number;
  severity: VulnSeverity;
  /** The NSE script that reported it. */
  script: string;
  /** What the script called it, when that is more than the id. */
  title?: string;
};

export type NmapOsClass = {
  /** nmap's own device category: router, switch, WAP, firewall, printer, phone… */
  type: string;
  vendor?: string;
  osfamily?: string;
  osgen?: string;
  accuracy: number;
};

export type NmapPort = {
  port: number;
  protocol: string;
  state: string;
  service?: string;
  product?: string;
  version?: string;
  extrainfo?: string;
  /** `-sV`'s device category for the service, e.g. `router`, `printer`, `webcam`. */
  devicetype?: string;
  /** `-sV`'s guess at the platform behind the banner, e.g. `Linux`, `Windows`. */
  ostype?: string;
  /** CPE identifiers from `<service><cpe>`, e.g. `cpe:/o:microsoft:windows`. */
  cpe?: string[];
  scripts: NmapScript[];
  /** ISO time of the first scan that reported this port (any state). */
  firstSeen?: string;
  /** ISO time of the last scan that reported it, in `state`. */
  lastSeen?: string;
  /** The state this port had in the scan before the one that set `state`. */
  previousState?: string;
};

export type NmapOsMatch = {
  name: string;
  accuracy: number;
  /** `<osclass>` children of this guess – the category nmap assigned, with its own accuracy. */
  classes?: NmapOsClass[];
};

export type NmapMac = {
  addr: string;
  vendor?: string;
};

export type NmapTraceHop = {
  ip: string;
  ttl: number;
  rtt?: number;
  host?: string;
};

export type NmapHost = {
  id: string;
  ip: string;
  ipv6?: string;
  addresses?: string[];
  mac?: string;
  vendor?: string;
  macs?: NmapMac[];
  hostnames: string[];
  status: string;
  os: NmapOsMatch[];
  ports: NmapPort[];
  portsScanned?: boolean;
  scripts: NmapScript[];
  hops: string[];
  /** ISO time of the scan that last confirmed this host. */
  seenAt?: string;
  /** The scan file that last confirmed it, shown in the inspector. */
  scanFile?: string;
  /** Vulnerabilities the scan's NSE scripts reported. */
  vulns?: VulnRef[];
};

export type NmapScan = {
  fileName: string;
  args?: string;
  version?: string;
  /** `nmap`, `masscan`, or whatever wrote the file. */
  scanner?: string;
  /** Which of nmap's output shapes this came from. */
  format?: 'xml' | 'grepable' | 'normal';
  /** Where the scan was pointed, taken from the command line and `<target>`. */
  targets?: string[];
  startedAt?: string;
  elapsedSeconds?: number;
  /** nmap's own closing line, e.g. `… 1024 IP addresses (0 hosts up) scanned in 827.34 seconds`. */
  summary?: string;
  hosts: NmapHost[];
  trace?: NmapTraceHop[];
  /**
   * What the reader had to work around: a repaired or salvaged XML file, dropped
   * blocks, unreadable lines. The import preview lists them before committing.
   */
  warnings?: string[];
  /** True when the file was not read as written – repaired or partly salvaged. */
  recovered?: boolean;
};

export type Workspace = {
  version: 1;
  scan: NmapScan;
  positions: [string, { x: number; y: number }][];
  collapsed: string[];
};

/**
 * Open ports for a host, computed once. Host records are replaced rather than
 * mutated when the inspector edits them, so the cache key stays valid, and a card
 * that renders, exports and is scored in the same frame pays for the filter once.
 */
const openPortsCache = new WeakMap<NmapHost, NmapPort[]>();

export function openPorts(host: NmapHost): NmapPort[] {
  const cached = openPortsCache.get(host);
  if (cached) return cached;
  const open = host.ports.filter((p) => p.state === 'open' || p.state === 'open|filtered');
  openPortsCache.set(host, open);
  return open;
}

export function discoveryOnly(host: NmapHost): boolean {
  return host.portsScanned === false;
}

export function portSummaryOr(host: NmapHost, fallback: string, limit = 6): string {
  const summary = portSummary(host, limit);
  if (summary) return summary;
  return discoveryOnly(host) ? fallback : 'no open ports';
}

export function hostLabel(host: NmapHost): string {
  return host.hostnames.find((name) => name.trim()) ?? host.mac ?? 'unnamed host';
}

export function serviceLabel(port: NmapPort): string {
  if (port.product) {
    return [port.product, port.version].filter(Boolean).join(' ');
  }
  return port.service ?? 'unknown';
}

export function portSummary(host: NmapHost, limit = 6): string {
  const open = openPorts(host);
  const shown = open.slice(0, limit).map((p) => (p.service ? `${p.port}/${p.service}` : `${p.port}`));
  const rest = open.length - shown.length;
  if (rest > 0) shown.push(`+${rest}`);
  return shown.join(', ');
}
