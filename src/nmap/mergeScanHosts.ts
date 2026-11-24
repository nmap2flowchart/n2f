import type { NmapHost, NmapOsMatch, NmapPort, NmapScript } from '../model/types';

/**
 * Two records for one address become one card.
 *
 * Masscan writes a `<host>` element per open port, so a host with three ports arrives
 * as three records; nmap itself can repeat an address (a `<hosthint>` plus the real
 * `<host>`, two runs concatenated, `-oG` writing `Status:` and `Ports:` on separate
 * lines). Dropping every repeat after the first – which is what the XML reader used
 * to do – quietly loses ports, and a scan that looks half empty.
 *
 * The rule is a union per field, with the richer record winning where they disagree.
 */

/** Masscan writes empty attributes (`<service name="">`); they are not values. */
function clean(value: string | undefined): string | undefined {
  return value && value.length > 0 ? value : undefined;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

const stateRank = (port: NmapPort) => (port.state === 'open' ? 0 : port.state === 'closed' ? 1 : 2);

function mergePorts(a: NmapPort[], b: NmapPort[]): NmapPort[] {
  const byKey = new Map<string, NmapPort>();
  const order: string[] = [];

  for (const port of [...a, ...b]) {
    const key = `${port.protocol}:${port.port}`;
    const seen = byKey.get(key);
    if (!seen) {
      byKey.set(key, port);
      order.push(key);
      continue;
    }
    // An open port beats a filtered or closed one; between equals, the record with
    // more to say about the service wins field by field.
    const primary = stateRank(port) < stateRank(seen) ? port : seen;
    const secondary = primary === port ? seen : port;
    const richer = port.service || port.product ? port : seen;
    byKey.set(key, {
      ...richer,
      state: primary.state,
      service: clean(richer.service) ?? clean(richer === port ? seen.service : port.service),
      product: clean(richer.product) ?? clean(richer === port ? seen.product : port.product),
      version: clean(richer.version) ?? clean(richer === port ? seen.version : port.version),
      extrainfo: clean(richer.extrainfo) ?? clean(richer === port ? seen.extrainfo : port.extrainfo),
      devicetype: clean(richer.devicetype) ?? clean(richer === port ? seen.devicetype : port.devicetype),
      ostype: clean(richer.ostype) ?? clean(richer === port ? seen.ostype : port.ostype),
      cpe: richer.cpe && richer.cpe.length > 0 ? richer.cpe : secondary.cpe,
      scripts: mergeScripts(primary.scripts, secondary.scripts),
      firstSeen: primary.firstSeen ?? secondary.firstSeen,
      lastSeen: primary.lastSeen ?? secondary.lastSeen,
      ...(primary.previousState ?? secondary.previousState
        ? { previousState: primary.previousState ?? secondary.previousState }
        : {}),
    });
  }

  return order.map((key) => byKey.get(key) as NmapPort).sort((left, right) => left.port - right.port);
}

function mergeScripts(a: NmapScript[], b: NmapScript[]): NmapScript[] {
  if (b.length === 0) return a;
  if (a.length === 0) return b;
  const byId = new Map<string, NmapScript>();
  for (const script of [...a, ...b]) {
    const seen = byId.get(script.id);
    if (!seen || (seen.output.length === 0 && script.output.length > 0)) byId.set(script.id, script);
  }
  return [...byId.values()];
}

function mergeOs(a: NmapOsMatch[], b: NmapOsMatch[]): NmapOsMatch[] {
  if (b.length === 0) return a;
  if (a.length === 0) return b;
  const byName = new Map<string, NmapOsMatch>();
  for (const match of [...a, ...b]) {
    const seen = byName.get(match.name);
    if (!seen || match.accuracy > seen.accuracy) byName.set(match.name, match);
  }
  return [...byName.values()].sort((left, right) => right.accuracy - left.accuracy);
}

/** The identity of a record: its IPv4 address, its IPv6 address, or the first one. */
export function hostIdentity(host: Pick<NmapHost, 'ip' | 'ipv6'>): string {
  return host.ip;
}

export function mergeHostRecords(first: NmapHost, incoming: NmapHost): NmapHost {
  return {
    ...first,
    ip: first.ip,
    ipv6: first.ipv6 ?? incoming.ipv6,
    addresses: unique([...(first.addresses ?? []), ...(incoming.addresses ?? [])]),
    mac: first.mac ?? incoming.mac,
    vendor: first.vendor ?? incoming.vendor,
    macs: (() => {
      const merged = [...(first.macs ?? []), ...(incoming.macs ?? [])];
      const byAddr = new Map(merged.map((entry) => [entry.addr, entry]));
      return byAddr.size > 1 ? [...byAddr.values()] : first.macs ?? incoming.macs;
    })(),
    hostnames: unique([...first.hostnames, ...incoming.hostnames]),
    status: first.status === 'up' || incoming.status === 'up' ? 'up' : first.status,
    os: mergeOs(first.os, incoming.os),
    ports: mergePorts(first.ports, incoming.ports),
    portsScanned: first.portsScanned || incoming.portsScanned,
    scripts: mergeScripts(first.scripts, incoming.scripts),
    hops: first.hops.length > 0 ? first.hops : incoming.hops,
    seenAt: first.seenAt ?? incoming.seenAt,
    scanFile: first.scanFile ?? incoming.scanFile,
    vulns: first.vulns && first.vulns.length > 0 ? first.vulns : incoming.vulns,
  };
}

/**
 * Collapse a reader's per-record output into one entry per address, keeping the order
 * the records arrived in so a diagram does not shuffle between imports.
 */
export function mergeHostList(hosts: NmapHost[]): NmapHost[] {
  const byIdentity = new Map<string, NmapHost>();
  const order: string[] = [];
  for (const host of hosts) {
    const key = hostIdentity(host);
    const seen = byIdentity.get(key);
    if (!seen) {
      byIdentity.set(key, host);
      order.push(key);
      continue;
    }
    byIdentity.set(key, mergeHostRecords(seen, host));
  }
  return order.map((key) => byIdentity.get(key) as NmapHost);
}
