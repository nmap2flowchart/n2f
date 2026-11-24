import type { NmapHost, NmapScan } from '../model/types';

export const HOST_W = 216;
export const HOST_H = 96;
export const HOP_W = 156;
export const HOP_H = 54;
export const ORIGIN_W = 268;
export const ORIGIN_H = 68;
export const NOTE_W = 224;
export const NOTE_H = 150;

const PAD = 24;
const HEADER_H = 44;
const H_GAP = 16;
const V_GAP = 14;
const SUBNET_GAP = 36;
const MAX_ROW_W = 1760;
const MAX_COLS = 4;

export type PlacedHost = { host: NmapHost; x: number; y: number };
export type PlacedSubnet = {
  cidr: string;
  x: number;
  y: number;
  w: number;
  h: number;
  hosts: PlacedHost[];
};
export type PlacedHop = { ip: string; depth: number; x: number; y: number; hostname?: string };

export type ScanLayout = {
  origin: { x: number; y: number };
  subnets: PlacedSubnet[];
  hops: PlacedHop[];
  width: number;
  height: number;
};

/** How many address bits a section frame groups by. */
export type HostGrouping = { ipv4?: number; ipv6?: number };

export const DEFAULT_IPV4_PREFIX = 24;
export const DEFAULT_IPV6_PREFIX = 64;

function ipv4Parts(ip: string): number[] | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
  return octets;
}

/** Expand `2001:db8::1` to its eight 16-bit groups, or `null` when it is not one. */
function ipv6Groups(ip: string): number[] | null {
  const value = ip.split('%')[0];
  if (!value.includes(':')) return null;
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const parse = (part: string | undefined) =>
    (part ?? '')
      .split(':')
      .filter((group) => group.length > 0)
      .map((group) => (/^[0-9a-fA-F]{1,4}$/.test(group) ? Number.parseInt(group, 16) : Number.NaN));

  if (halves.length === 2) {
    const left = parse(halves[0]);
    const right = parse(halves[1]);
    if ([...left, ...right].some((group) => Number.isNaN(group))) return null;
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;
    return [...left, ...Array.from({ length: fill }, () => 0), ...right];
  }
  const groups = parse(value);
  return groups.length === 8 && !groups.some((group) => Number.isNaN(group)) ? groups : null;
}

/** `2001:db8:0:1:0:0:0:1` → `2001:db8:0:1::1`, the form nmap prints. */
function formatIpv6(groups: number[]): string {
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  for (let index = 0; index <= groups.length; index += 1) {
    if (index < groups.length && groups[index] === 0) {
      if (runStart === -1) runStart = index;
      continue;
    }
    if (runStart !== -1) {
      const length = index - runStart;
      if (length > bestLength) {
        bestStart = runStart;
        bestLength = length;
      }
      runStart = -1;
    }
  }
  const text = groups.map((group) => group.toString(16)).join(':');
  if (bestLength < 2) return text;
  const head = groups.slice(0, bestStart).map((group) => group.toString(16)).join(':');
  const tail = groups
    .slice(bestStart + bestLength)
    .map((group) => group.toString(16))
    .join(':');
  return `${head}::${tail}`;
}

export function ipv4PrefixOf(ip: string, prefix = DEFAULT_IPV4_PREFIX): string {
  const octets = ipv4Parts(ip);
  if (!octets) return 'unrouted';
  const bits = Math.max(0, Math.min(32, Math.round(prefix)));
  const value = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const network = (value & mask) >>> 0;
  return `${(network >>> 24) & 255}.${(network >>> 16) & 255}.${(network >>> 8) & 255}.${network & 255}/${bits}`;
}

export function ipv6PrefixOf(ip: string, prefix = DEFAULT_IPV6_PREFIX): string {
  const groups = ipv6Groups(ip);
  if (!groups) return 'unrouted';
  const bits = Math.max(0, Math.min(128, Math.round(prefix)));
  const masked = groups.map((group, index) => {
    const before = index * 16;
    if (before >= bits) return 0;
    const remaining = bits - before;
    if (remaining >= 16) return group;
    return (group & ((0xffff << (16 - remaining)) & 0xffff)) >>> 0;
  });
  return `${formatIpv6(masked)}/${bits}`;
}

export function compareIp(a: string, b: string): number {
  const leftV6 = a.includes(':');
  const rightV6 = b.includes(':');
  if (leftV6 !== rightV6) return leftV6 ? 1 : -1;

  if (leftV6) {
    const left = ipv6Groups(a);
    const right = ipv6Groups(b);
    if (left && right) {
      for (let index = 0; index < 8; index += 1) {
        const diff = left[index] - right[index];
        if (diff !== 0) return diff;
      }
      return 0;
    }
    return a.localeCompare(b);
  }

  const left = ipv4Parts(a);
  const right = ipv4Parts(b);
  if (left && right) {
    for (let index = 0; index < 4; index += 1) {
      const diff = left[index] - right[index];
      if (diff !== 0) return diff;
    }
    return 0;
  }
  return a.localeCompare(b);
}

export function subnetOf(ip: string, grouping?: HostGrouping): string {
  if (ip.includes(':')) {
    return ipv6PrefixOf(ip, grouping?.ipv6 ?? DEFAULT_IPV6_PREFIX);
  }
  if (ipv4Parts(ip)) return ipv4PrefixOf(ip, grouping?.ipv4 ?? DEFAULT_IPV4_PREFIX);
  return 'unrouted';
}

const networkOf = (cidr: string) => cidr.slice(0, cidr.lastIndexOf('/') || undefined);

export function groupHosts(
  hosts: NmapHost[],
  grouping?: HostGrouping,
): { cidr: string; hosts: NmapHost[] }[] {
  const buckets = new Map<string, NmapHost[]>();
  for (const host of hosts) {
    const cidr = subnetOf(host.ip, grouping);
    const bucket = buckets.get(cidr);
    if (bucket) bucket.push(host);
    else buckets.set(cidr, [host]);
  }
  return [...buckets.entries()]
    .map(([cidr, list]) => ({ cidr, hosts: [...list].sort((a, b) => compareIp(a.ip, b.ip)) }))
    .sort((a, b) => compareIp(networkOf(a.cidr), networkOf(b.cidr)) || a.cidr.length - b.cidr.length);
}

function layoutRoute(scan: NmapScan): { hops: PlacedHop[]; bottom: number } {
  const depthByIp = new Map<string, number>();
  for (const host of scan.hosts) {
    host.hops.forEach((ip, index) => {
      // nmap ends a trace at the target: that entry names the host, not a router.
      if (ip === host.ip) return;
      const depth = index + 1;
      // A router several traces pass through is drawn at the earliest column it
      // appears in, which is the column its own path reaches it from.
      const seen = depthByIp.get(ip);
      if (seen === undefined || depth < seen) depthByIp.set(ip, depth);
    });
  }

  const byDepth = new Map<number, string[]>();
  for (const [ip, depth] of depthByIp) {
    const column = byDepth.get(depth);
    if (column) column.push(ip);
    else byDepth.set(depth, [ip]);
  }

  const hops: PlacedHop[] = [];
  const names = new Map((scan.trace ?? []).filter((hop) => hop.host).map((hop) => [hop.ip, hop.host as string]));
  let bottom = 0;
  for (const depth of [...byDepth.keys()].sort((a, b) => a - b)) {
    const column = [...(byDepth.get(depth) ?? [])].sort(compareIp);
    column.forEach((ip, row) => {
      const y = row * (HOP_H + 12);
      hops.push({ ip, depth, x: ORIGIN_W + 140 + (depth - 1) * (HOP_W + 84), y, hostname: names.get(ip) });
      bottom = Math.max(bottom, y + HOP_H);
    });
  }
  return { hops, bottom };
}

export function layoutScan(scan: NmapScan, grouping?: HostGrouping): ScanLayout {
  const route = layoutRoute(scan);
  const top = Math.max(route.bottom, ORIGIN_H) + 96;

  const subnets: PlacedSubnet[] = [];
  let cursorX = 0;
  let cursorY = top;
  let rowHeight = 0;

  for (const group of groupHosts(scan.hosts, grouping)) {
    const count = group.hosts.length;
    const cols = Math.min(MAX_COLS, Math.max(1, Math.ceil(Math.sqrt(count))));
    const rows = Math.ceil(count / cols);
    const innerW = cols * HOST_W + (cols - 1) * H_GAP;
    const innerH = rows * HOST_H + (rows - 1) * V_GAP;
    const w = innerW + PAD * 2;
    const h = innerH + PAD * 2 + HEADER_H;

    if (cursorX > 0 && cursorX + w > MAX_ROW_W) {
      cursorX = 0;
      cursorY += rowHeight + SUBNET_GAP;
      rowHeight = 0;
    }

    const placed: PlacedHost[] = group.hosts.map((host, index) => ({
      host,
      x: PAD + (index % cols) * (HOST_W + H_GAP),
      y: PAD + HEADER_H + Math.floor(index / cols) * (HOST_H + V_GAP),
    }));

    subnets.push({ cidr: group.cidr, x: cursorX, y: cursorY, w, h, hosts: placed });
    cursorX += w + SUBNET_GAP;
    rowHeight = Math.max(rowHeight, h);
  }

  const width = Math.max(
    ORIGIN_W,
    ...subnets.map((s) => s.x + s.w),
    ...route.hops.map((h) => h.x + HOP_W),
  );
  const height = Math.max(ORIGIN_H, ...subnets.map((s) => s.y + s.h));

  return { origin: { x: 0, y: 0 }, subnets, hops: route.hops, width, height };
}
