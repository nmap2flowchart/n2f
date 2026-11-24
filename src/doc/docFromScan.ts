import type { NmapHost, NmapPort, NmapScan, VulnRef } from '../model/types';
import { openPorts } from '../model/types';
import { VULN_SEVERITY_ORDER } from '../model/vulns';
import { detectIcon } from '../icons/detect';
import { routedIcon } from '../model/device';
import { layoutScan, type HostGrouping } from '../graph/layout';
import { slotsInSection } from './measure';
import { suggestGrouping } from '../nmap/targets';
import {
  LAYER_COLORS,
  MAIN_LAYER,
  NOTES_LAYER,
  sectionNodeId,
  type DiagramDoc,
  type DiagramEdge,
  type DiagramNode,
  type Layer,
} from './types';

function baseLayers(): Layer[] {
  return [
    { id: MAIN_LAYER, name: 'Scanned network', parentId: null, visible: true, color: '#4b9fff' },
    { id: NOTES_LAYER, name: 'Notes & links', parentId: null, visible: true, color: '#facc15' },
  ];
}

const nodeId = (kind: string, value: string) => `${kind}:${value.replace(/[^0-9a-zA-Z./:]+/g, '_')}`;

/**
 * The command line the origin card shows. nmap records the path of its own binary –
 * `"C:\\Program Files (x86)\\Nmap\\nmap.exe" -sV -oX scan.xml 10.1.2.0/24` on Windows –
 * so the card, and the code written from it, would spend their width on the path and
 * cut off the flags that say what the scan actually did. `nmap` stands in for the
 * executable; everything after it is kept.
 */
function commandOf(args: string | undefined): string | undefined {
  const text = (args ?? '').replace(/\s+/g, ' ').trim();
  if (!text) return undefined;
  const executable = /^(?:"[^"]*\.exe"|[A-Za-z]:\\[^]*?\.exe|\S*?\.exe|\/\S*?\bnmap|"[^"]*")(?=\s|$)\s*/i.exec(text);
  const command = executable ? `nmap ${text.slice(executable[0].length)}` : text;
  return command.trim().slice(0, 120);
}

export function hostNodeId(host: NmapHost): string {
  return nodeId('host', host.ip);
}

function buildFromScan(scan: NmapScan, grouping?: HostGrouping): { nodes: DiagramNode[]; edges: DiagramEdge[] } {
  const layout = layoutScan(scan, grouping);
  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  const discoveryScan = scan.hosts.length > 0 && scan.hosts.every((host) => host.portsScanned === false);
  const hostIps = new Set(scan.hosts.map((host) => host.ip));
  // A trace hop that is also a scanned host is drawn as that host card, not twice.
  const routerDepth = new Map(layout.hops.map((hop) => [hop.ip, hop.depth]));

  nodes.push({
    id: 'origin',
    kind: 'origin',
    layerId: MAIN_LAYER,
    position: layout.origin,
    icon: 'cloud',
    label: 'Scan origin',
    address: commandOf(scan.args),
    subtitle: `${scan.hosts.length} hosts${discoveryScan ? ' · no port scan' : ''}${
      scan.scanner && scan.scanner.toLowerCase() !== 'nmap' ? ` · ${scan.scanner}` : ''
    }`,
  });

  for (const hop of layout.hops) {
    if (hostIps.has(hop.ip)) continue;
    nodes.push({
      id: nodeId('hop', hop.ip),
      kind: 'hop',
      layerId: MAIN_LAYER,
      position: { x: hop.x, y: hop.y },
      address: hop.ip,
      depth: hop.depth,
      subtitle: hop.hostname,
      icon: 'router',
    });
  }

  for (const subnet of layout.subnets) {
    const sectionId = sectionNodeId(subnet.cidr);
    nodes.push({
      id: sectionId,
      kind: 'section',
      layerId: MAIN_LAYER,
      position: { x: subnet.x, y: subnet.y },
      cidr: subnet.cidr,
      icon: 'server',
      size: { w: subnet.w, h: subnet.h },
    });

    for (const placed of subnet.hosts) {
      const depth = routerDepth.get(placed.host.ip);
      nodes.push({
        id: hostNodeId(placed.host),
        kind: 'host',
        layerId: MAIN_LAYER,
        parentId: sectionId,
        position: { x: placed.x, y: placed.y },
        host: placed.host,
        // The card is a router when other traces pass through it: the route lane
        // chains by depth, and a card in that chain wears a network icon.
        icon: depth ? routedIcon(placed.host) : detectIcon(placed.host),
        ...(depth ? { depth } : {}),
      });
    }
  }

  edges.push(...routeEdges(nodes));
  return { nodes, edges };
}

export function routeEdges(nodes: DiagramNode[]): DiagramEdge[] {
  const byLayer = new Map<string, DiagramNode[]>();
  for (const node of nodes) {
    const bucket = byLayer.get(node.layerId);
    if (bucket) bucket.push(node);
    else byLayer.set(node.layerId, [node]);
  }
  return [...byLayer.values()].flatMap((group) => routeEdgesInLayer(group));
}

/**
 * Route edges chain the routers each trace actually names: `origin → depth 1 → …
 * → card`, one line per consecutive pair on that host's own path.
 *
 * The previous version connected every router at one hop depth to every router at
 * the next, which turned two independent traces into a mesh – a router on one path
 * was drawn as reaching a router only the other path ever saw. A router can be a
 * hop card or a scanned host card: a switch or gateway the scan also probed lives
 * inside its subnet frame and is still on the path.
 */
function routeEdgesInLayer(nodes: DiagramNode[]): DiagramEdge[] {
  const origin = nodes.find((node) => node.kind === 'origin');
  const addressOf = (node: DiagramNode): string | undefined =>
    node.kind === 'hop' ? node.address : node.kind === 'host' ? node.host?.ip : undefined;

  const byAddress = new Map<string, DiagramNode>();
  for (const node of nodes) {
    const address = addressOf(node);
    if (!address) continue;
    const current = byAddress.get(address);
    // A host card carries more than a hop card for the same address.
    if (!current || (current.kind === 'hop' && node.kind === 'host')) byAddress.set(address, node);
  }

  const edges: DiagramEdge[] = [];
  const seen = new Set<string>();
  const link = (source: DiagramNode, target: DiagramNode) => {
    if (source.id === target.id) return;
    const pair = `${source.id}|${target.id}`;
    const reverse = `${target.id}|${source.id}`;
    if (seen.has(pair) || seen.has(reverse)) return;
    seen.add(pair);
    edges.push({ id: `route:${source.id}-${target.id}`, source: source.id, target: target.id, kind: 'route' });
  };

  for (const host of nodes.filter((node) => node.kind === 'host' && node.host)) {
    // nmap ends a trace at the target; that last entry names the card, not a router.
    const path = (host.host?.hops ?? []).filter((ip) => ip.length > 0 && ip !== host.host?.ip);
    if (path.length === 0) continue;
    let previous: DiagramNode | undefined = origin;
    for (const address of path) {
      const router = byAddress.get(address);
      if (!router) continue;
      if (router.id === host.id) break;
      if (previous) link(previous, router);
      previous = router;
    }
    if (previous) link(previous, host);
  }
  return edges;
}

/** The grouping a diagram should use for a scan, when the caller has no opinion. */
export function groupingFor(scan: NmapScan, doc?: DiagramDoc | null): HostGrouping | undefined {
  if (doc?.grouping) return doc.grouping;
  const ipv4 = suggestGrouping(scan.targets ?? []);
  return ipv4 === undefined ? undefined : { ipv4 };
}

export function createDocFromScan(scan: NmapScan, grouping?: HostGrouping): DiagramDoc {
  const resolved = grouping ?? groupingFor(scan);
  const { nodes, edges } = buildFromScan(scan, resolved);
  return {
    version: 2,
    fileName: scan.fileName,
    args: scan.args,
    ...(scan.targets ? { targets: scan.targets } : {}),
    ...(resolved ? { grouping: resolved } : {}),
    layers: baseLayers(),
    nodes,
    edges,
    focusedLayerId: null,
  };
}

let layerCounter = 0;

const nextLayerId = () => {
  layerCounter += 1;
  return `layer:scan-${Date.now().toString(36)}${layerCounter.toString(36)}`;
};

function rootBottom(nodes: DiagramNode[]): number {
  const bottomOf = (node: DiagramNode) =>
    node.position.y + (node.size?.h ?? (node.kind === 'section' ? 220 : 120));
  return Math.max(0, ...nodes.filter((node) => !node.parentId).map(bottomOf));
}

export function importScanAsLayer(
  doc: DiagramDoc,
  scan: NmapScan,
  grouping?: HostGrouping,
): { doc: DiagramDoc; layerId: string; added: number } {
  const fresh = buildFromScan(scan, grouping ?? groupingFor(scan, doc));
  const layerId = nextLayerId();
  const base = (scan.fileName.replace(/\.[^.]+$/, '') || 'scan').slice(0, 42);
  const usedNames = new Set(doc.layers.map((item) => item.name));
  let name = base;
  for (let n = 2; usedNames.has(name); n += 1) name = `${base} ${n}`;
  const layer: Layer = {
    id: layerId,
    name,
    parentId: null,
    visible: true,
    color: LAYER_COLORS[doc.layers.length % LAYER_COLORS.length],
  };

  const taken = new Set(doc.nodes.map((node) => node.id));
  const idMap = new Map<string, string>();
  let counter = 0;
  for (const node of fresh.nodes) {
    let id = node.id;
    while (taken.has(id)) {
      counter += 1;
      id = `${node.id}~${counter}`;
    }
    taken.add(id);
    idMap.set(node.id, id);
  }

  const offset = rootBottom(doc.nodes) + 140;
  const nodes: DiagramNode[] = fresh.nodes.map((node) => ({
    ...node,
    id: idMap.get(node.id) ?? node.id,
    layerId,
    position: node.parentId ? node.position : { x: node.position.x, y: node.position.y + offset },
    parentId: node.parentId ? (idMap.get(node.parentId) ?? node.parentId) : (node.parentId ?? null),
  }));

  return {
    doc: {
      ...doc,
      focusedLayerId: null,
      layers: [...doc.layers, layer],
      nodes: [...doc.nodes, ...nodes],
      edges: [...doc.edges, ...routeEdges(nodes)],
    },
    layerId,
    added: nodes.length,
  };
}

export function emptyDoc(): DiagramDoc {
  return {
    version: 2,
    fileName: 'untitled diagram',
    layers: baseLayers(),
    nodes: [],
    edges: [],
    focusedLayerId: null,
  };
}

const portKey = (port: NmapPort) => `${port.protocol}/${port.port}`;

/**
 * One port, as two scans describe it. The newer scan describes the service; the
 * older one contributes the history that lets the inspector say "open in the
 * January scan, closed in February" instead of quietly forgetting.
 */
function mergePortRecord(current: NmapPort | undefined, incoming: NmapPort, when: string | undefined): NmapPort {
  if (!current) {
    return {
      ...incoming,
      ...(when ? { firstSeen: incoming.firstSeen ?? when, lastSeen: incoming.lastSeen ?? when } : {}),
    };
  }
  return {
    ...incoming,
    firstSeen: current.firstSeen ?? incoming.firstSeen ?? when,
    lastSeen: incoming.lastSeen ?? when ?? current.lastSeen,
    previousState: current.state !== incoming.state ? current.state : current.previousState,
    scripts: incoming.scripts.length > 0 ? incoming.scripts : current.scripts,
    cpe: incoming.cpe ?? current.cpe,
  };
}

/**
 * Union of two port lists. A port the new scan does not mention is kept as it was:
 * a filtered port, a slower scan that missed the window, or a target list that
 * changed is not evidence that the service went away.
 */
function mergePorts(current: NmapPort[], incoming: NmapPort[], when: string | undefined): NmapPort[] {
  const before = new Map(current.map((port) => [portKey(port), port]));
  const merged = incoming.map((port) => mergePortRecord(before.get(portKey(port)), port, when));
  const seen = new Set(merged.map(portKey));
  for (const port of current) if (!seen.has(portKey(port))) merged.push(port);
  return merged.sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));
}

/**
 * Two imports can both describe one address: one probed it, another only traced
 * past it. The card keeps the richer record's content and takes what that record
 * lacks from the other – a scan without `--traceroute` must not erase the path a
 * scan with it found, and a port list must not lose the ports a slower scan saw.
 */
function mergeHostRecords(current: NmapHost | undefined, incoming: NmapHost): NmapHost {
  if (!current) return incoming;
  const value = (host: NmapHost) => openPorts(host).length * 10 + host.hostnames.length * 2 + host.ports.length;
  const [richer, other] = value(incoming) >= value(current) ? [incoming, current] : [current, incoming];
  const hostnames = [...new Set([...richer.hostnames, ...other.hostnames])];
  const when = incoming.seenAt ?? incoming.ports.find((port) => port.lastSeen)?.lastSeen;
  return {
    ...richer,
    hostnames: hostnames.length > 0 ? hostnames : richer.hostnames,
    hops: richer.hops.length > 0 ? richer.hops : other.hops,
    mac: richer.mac ?? other.mac,
    macs: richer.macs ?? other.macs,
    vendor: richer.vendor ?? other.vendor,
    os: richer.os.length > 0 ? richer.os : other.os,
    scripts: richer.scripts.length > 0 ? richer.scripts : other.scripts,
    addresses: [...new Set([...(richer.addresses ?? []), ...(other.addresses ?? [])])],
    ports: mergePorts(current.ports, incoming.ports, when),
    vulns: mergeVulns(current.vulns, incoming.vulns),
    seenAt: incoming.seenAt ?? current.seenAt,
    scanFile: incoming.scanFile ?? current.scanFile,
  };
}

/** Findings from either scan; the higher score wins for the same id. */
function mergeVulns(current: VulnRef[] | undefined, incoming: VulnRef[] | undefined): VulnRef[] | undefined {
  if (!current?.length) return incoming;
  if (!incoming?.length) return current;
  const found = new Map(current.map((vuln) => [vuln.id, vuln]));
  for (const vuln of incoming) {
    const existing = found.get(vuln.id);
    if (!existing || (vuln.cvss ?? 0) > (existing.cvss ?? 0)) found.set(vuln.id, vuln);
  }
  return [...found.values()].sort(
    (a, b) =>
      VULN_SEVERITY_ORDER.indexOf(a.severity) - VULN_SEVERITY_ORDER.indexOf(b.severity) ||
      (b.cvss ?? 0) - (a.cvss ?? 0) ||
      a.id.localeCompare(b.id),
  );
}

export function mergeScanIntoDoc(
  doc: DiagramDoc,
  scan: NmapScan,
  grouping?: HostGrouping,
): { doc: DiagramDoc; added: number; gone: number } {
  const fresh = buildFromScan(scan, grouping ?? groupingFor(scan, doc));
  const layerNodes = doc.nodes.filter((node) => node.layerId === MAIN_LAYER);
  const otherNodes = doc.nodes.filter((node) => node.layerId !== MAIN_LAYER);
  const existing = new Map<string, DiagramNode>();
  for (const node of layerNodes) {
    const key = identify(node);
    const current = existing.get(key);
    // A host card carries more than a hop card for the same address.
    if (current && (current.kind === 'host' || node.kind !== 'host')) continue;
    existing.set(key, node);
  }
  const existingById = new Map(layerNodes.map((node) => [node.id, node]));

  const bottomOf = (node: DiagramNode) =>
    node.position.y + (node.size?.h ?? (node.kind === 'section' ? 220 : 120));
  const existingBottom = Math.max(0, ...doc.nodes.filter((node) => !node.parentId).map(bottomOf));
  const offset = existingBottom + 140;

  const newSectionIds = new Set(
    fresh.nodes.filter((node) => node.kind === 'section' && !existingById.has(node.id)).map((node) => node.id),
  );
  /** Cards appended to a section that already exists, placed once the set is known. */
  const pendingIn = new Map<string, string[]>();

  const nodes: DiagramNode[] = [];
  let added = 0;

  for (const incoming of fresh.nodes) {
    const match = existing.get(identify(incoming));
    if (match) {
      // The richer card wins: probing a router that another scan only saw on the
      // path turns the hop card into a host card, not the other way round.
      const host = incoming.host ? mergeHostRecords(match.host, incoming.host) : match.host;
      // The icon may have been read from the record that just lost its evidence –
      // a Plex banner over the router firmware – so refresh an auto-detected one.
      const autoIcon = match.host ? match.icon === detectIcon(match.host) : true;
      nodes.push({
        ...match,
        kind: host ? 'host' : match.kind,
        host,
        ...(host && autoIcon ? { icon: detectIcon(host) } : {}),
        address: incoming.address ?? match.address,
        depth: incoming.depth ?? match.depth,
        subtitle: match.subtitle ?? incoming.subtitle,
        stale: false,
      });
      continue;
    }

    added += 1;
    if (incoming.kind === 'section') {
      nodes.push({ ...incoming, position: { x: incoming.position.x, y: incoming.position.y + offset } });
      continue;
    }
    if (incoming.parentId && newSectionIds.has(incoming.parentId)) {
      nodes.push(incoming);
      continue;
    }
    if (incoming.parentId) {
      const bucket = pendingIn.get(incoming.parentId);
      if (bucket) bucket.push(incoming.id);
      else pendingIn.set(incoming.parentId, [incoming.id]);
      nodes.push(incoming);
      continue;
    }
    nodes.push({ ...incoming, position: { x: incoming.position.x, y: incoming.position.y + offset } });
  }

  const seen = new Set(nodes.map(identify));
  let gone = 0;
  for (const node of layerNodes) {
    if (node.kind === 'note' || node.kind === 'origin' || seen.has(identify(node))) continue;
    nodes.push({ ...node, stale: true });
    if (node.kind === 'host') gone += 1;
  }
  nodes.push(...otherNodes);

  // Cards appended to an existing section are placed against everything that will
  // be in that section – the cards already there, the ones that just merged in,
  // and each other – so a merge fills gaps instead of stacking cards on top of
  // the first three columns.
  for (const [sectionId, pending] of pendingIn) {
    const byId = new Map(nodes.map((node) => [node.id, node]));
    const section = byId.get(sectionId);
    if (!section || section.kind !== 'section') continue;
    const pendingIds = new Set(pending);
    const siblings = nodes.filter((node) => node.parentId === sectionId && !pendingIds.has(node.id));
    const placed = slotsInSection(section, siblings, pending.length);
    pending.forEach((id, index) => {
      const target = byId.get(id);
      if (target) target.position = placed[index];
    });
  }

  const nodeIds = new Set(nodes.map((node) => node.id));
  const links = doc.edges.filter(
    (edge) => edge.kind === 'link' && nodeIds.has(edge.source) && nodeIds.has(edge.target),
  );
  // A route the user has styled, labelled or re-anchored is their drawing, not the
  // scan's: regenerating every route on a merge used to throw that away.
  const editedRoutes = doc.edges.filter(
    (edge) =>
      edge.kind === 'route' && isEditedRoute(edge) && nodeIds.has(edge.source) && nodeIds.has(edge.target),
  );
  const editedIds = new Set(editedRoutes.map((edge) => edge.id));
  const routes = routeEdges(nodes).filter(
    (edge) => !editedIds.has(edge.id) && nodeIds.has(edge.source) && nodeIds.has(edge.target),
  );

  return {
    doc: {
      ...doc,
      fileName: scan.fileName,
      args: scan.args ?? doc.args,
      targets: scan.targets ?? doc.targets,
      nodes,
      edges: [...routes, ...editedRoutes, ...links],
    },
    added,
    gone,
  };
}

/** A route edge whose drawing no longer follows the scan's defaults. */
export function isEditedRoute(edge: DiagramEdge): boolean {
  return (
    edge.label !== undefined ||
    edge.line !== undefined ||
    edge.path !== undefined ||
    edge.from !== undefined ||
    edge.to !== undefined ||
    edge.arrow !== undefined
  );
}

export function identify(node: DiagramNode): string {
  // A hop and a host with the same address are the same device: one scan can see
  // a router on the path while another probes it, and the card must not double.
  if (node.kind === 'host') return `device:${node.host?.ip || node.id}`;
  if (node.kind === 'hop') return `device:${node.address || node.id}`;
  if (node.kind === 'section') return `section:${node.cidr || node.id}`;
  if (node.kind === 'origin') return 'origin';
  return node.id;
}

export type ImportMode = 'merge' | 'replace' | 'layer';

export type ImportEffect = {
  nodes: number;
  matched: number;
  added: number;
  stale: number;
  /** Matched hosts whose ports or names this scan changes. */
  updated: number;
  /** Open ports the diagram has that this scan no longer reports. */
  closedPorts: number;
};

/**
 * Effect counts for all three import modes from a single layout pass: switching
 * mode in the preview dialog is instant, and a big scan is only laid out once.
 */
export function scanEffects(
  doc: DiagramDoc | null,
  scan: NmapScan,
  grouping?: HostGrouping,
): Record<ImportMode, ImportEffect> {
  const fresh = buildFromScan(scan, grouping ?? groupingFor(scan, doc)).nodes;
  const freshOnly: ImportEffect = {
    nodes: fresh.length,
    matched: 0,
    added: fresh.length,
    stale: 0,
    updated: 0,
    closedPorts: 0,
  };
  if (!doc) return { replace: freshOnly, layer: freshOnly, merge: freshOnly };

  const layerNodes = doc.nodes.filter((node) => node.layerId === MAIN_LAYER);
  const existing = new Map<string, DiagramNode>();
  for (const node of layerNodes) {
    const key = identify(node);
    const current = existing.get(key);
    // A host card carries more than a hop card for the same address.
    if (current && (current.kind === 'host' || node.kind !== 'host')) continue;
    existing.set(key, node);
  }
  const seen = new Set(fresh.map(identify));
  let matched = 0;
  let updated = 0;
  let closedPorts = 0;

  for (const node of fresh) {
    const current = existing.get(identify(node));
    if (!current) continue;
    matched += 1;
    const before = new Set((current.host ? openPorts(current.host) : []).map((port) => port.port));
    const after = new Set((node.host ? openPorts(node.host) : []).map((port) => port.port));
    const closed = [...before].filter((port) => !after.has(port)).length;
    closedPorts += closed;
    const gainedPorts = [...after].some((port) => !before.has(port));
    const newNames = (node.host?.hostnames ?? []).some((name) => !(current.host?.hostnames ?? []).includes(name));
    if (closed > 0 || gainedPorts || newNames) updated += 1;
  }

  const stale = layerNodes.filter(
    (node) => node.kind === 'host' && !seen.has(identify(node)),
  ).length;

  return {
    replace: freshOnly,
    layer: freshOnly,
    merge: { nodes: fresh.length, matched, added: fresh.length - matched, stale, updated, closedPorts },
  };
}

export function previewImport(
  doc: DiagramDoc | null,
  scan: NmapScan,
  mode: ImportMode,
): ImportEffect {
  return scanEffects(doc, scan)[mode];
}
