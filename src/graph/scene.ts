import {
  edgeLine,
  edgePath,
  flattenLayers,
  isLayerVisible,
  layerMap,
  type DiagramDoc,
  type DiagramEdge,
  type DiagramNode,
  type EdgeLine,
  type EdgePath,
} from '../doc/types';
import { absolutePosition, measureSection, nodeSize } from '../doc/measure';
import { nodeRisk, type NodeRisk, type RiskPolicy } from '../doc/risk';
import { classifyHost, type DeviceEvidence, type DeviceRole } from '../model/device';
import type { VulnRef } from '../model/types';

/**
 * The drawing decisions every renderer shares.
 *
 * The canvas and the exporters used to re-derive these one by one – which nodes
 * are visible, where a section's frame ends, how layers and `z` stack, what risk
 * a card carries – which is how a collapsed section ended up hiding its cards in
 * SVG but not in draw.io. `buildScene` answers all of it once; the React Flow
 * adapter and the SVG / draw.io / Mermaid writers only decide how to paint.
 */

export type SceneBox = { x: number; y: number; w: number; h: number };

export type SceneNode = {
  node: DiagramNode;
  /** Absolute canvas rectangle, the same numbers an exporter must draw. */
  box: SceneBox;
  /** Children that survive the current layers and collapsed sections. */
  children: DiagramNode[];
  /** Every child, drawn or not – the section header's "n nodes" count. */
  childCount: number;
  /** Painter's order: higher draws over lower. */
  z: number;
  /** Resolved risk for host cards, `null` for anything else. */
  risk: NodeRisk | null;
  /** What the box does, when the scan proves it. */
  role?: DeviceRole;
  roleEvidence?: DeviceEvidence;
  /** Findings the scan's scripts reported, worst first. */
  vulns: VulnRef[];
  /** The worst finding, for the card's badge and the picture's chip. */
  worstVuln: VulnRef | null;
};

export type SceneEdge = {
  edge: DiagramEdge;
  source: SceneNode;
  target: SceneNode;
  line: EdgeLine;
  path: EdgePath;
};

export type Scene = {
  /** Sections in document order: they belong under every card. */
  sections: SceneNode[];
  /** Cards in painter's order, so the last one drawn is the one on top. */
  cards: SceneNode[];
  edges: SceneEdge[];
  /** Ids of everything that is drawn; the key for edge filtering. */
  ids: Set<string>;
  node: (id: string) => SceneNode | undefined;
  /** Extent of the drawn content, before an export adds its own margin. */
  bounds: SceneBox;
};

/**
 * Layers stack in rows (later rows draw over earlier ones), sections sit in the
 * lower band of their layer and cards in the upper band, and `z` orders peers.
 * A frame inside a frame sits one step above the frame around it, or the outer
 * fill would paint over the inner one.
 * The canvas feeds these numbers to React Flow's `zIndex`; the exporters sort by
 * them, so a card moved to the front is in front in the picture too.
 */
export function sceneStack(doc: DiagramDoc): (node: DiagramNode) => number {
  const rank = new Map<string, number>();
  flattenLayers(doc.layers).forEach(({ layer }, index) => rank.set(layer.id, index));
  const layerCount = Math.max(1, doc.layers.length);
  const depths = sectionDepths(doc.nodes);

  return (node: DiagramNode) => {
    const base = (layerCount - (rank.get(node.layerId) ?? 0)) * 10_000;
    if (node.kind !== 'section') return base + 1000 + (node.z ?? 0);
    return base + Math.min(depths.get(node.id) ?? 0, SECTION_DEPTH_STEPS) * SECTION_DEPTH_STEP + (node.z ?? 0);
  };
}

/** Nested frames stay under the cards: 15 levels of 60 still leave the 1000 band. */
const SECTION_DEPTH_STEP = 60;
const SECTION_DEPTH_STEPS = 15;

/** How many sections enclose each frame; 0 for a top-level frame. One pass. */
function sectionDepths(nodes: DiagramNode[]): Map<string, number> {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const depths = new Map<string, number>();
  const resolve = (node: DiagramNode, guard = 0): number => {
    const known = depths.get(node.id);
    if (known !== undefined) return known;
    const parent = node.parentId ? byId.get(node.parentId) : undefined;
    const depth = parent?.kind === 'section' && guard < 32 ? resolve(parent, guard + 1) + 1 : 0;
    depths.set(node.id, depth);
    return depth;
  };
  for (const node of nodes) if (node.kind === 'section') resolve(node);
  return depths;
}

export function buildScene(doc: DiagramDoc, riskPolicy: RiskPolicy): Scene {
  const layers = layerMap(doc.layers);
  const drawable = (node: DiagramNode) => isLayerVisible(layers, node.layerId, doc.focusedLayerId);

  const childrenOf = new Map<string, DiagramNode[]>();
  for (const node of doc.nodes) {
    if (!node.parentId) continue;
    const bucket = childrenOf.get(node.parentId);
    if (bucket) bucket.push(node);
    else childrenOf.set(node.parentId, [node]);
  }

  const byId = new Map(doc.nodes.map((node) => [node.id, node]));
  const stackOf = sceneStack(doc);

  // A frame inside a collapsed or hidden frame is not on the canvas either – at any
  // depth, which is what used to make a collapsed section draw its nested frames.
  const drawn = new Map<string, boolean>();
  const visiting = new Set<string>();
  const isDrawn = (node: DiagramNode): boolean => {
    const known = drawn.get(node.id);
    if (known !== undefined) return known;
    let result = drawable(node);
    const parent = node.parentId ? byId.get(node.parentId) : undefined;
    if (result && parent?.kind === 'section' && !visiting.has(node.id)) {
      visiting.add(node.id);
      result = !parent.collapsed && isDrawn(parent);
      visiting.delete(node.id);
    }
    drawn.set(node.id, result);
    return result;
  };

  const ids = new Set<string>();
  for (const node of doc.nodes) {
    if (isDrawn(node)) ids.add(node.id);
  }

  // Measured from the frames and cards that are actually drawn, bottom-up, so a
  // frame fits what is inside it whether that is a card or a nested frame.
  const measured = new Map<string, { w: number; h: number }>();
  const sizeOf = (node: DiagramNode, guard = 0): { w: number; h: number } => {
    if (node.kind !== 'section') return nodeSize(node);
    const known = measured.get(node.id);
    if (known) return known;
    const children = (childrenOf.get(node.id) ?? []).filter((child) => ids.has(child.id));
    const size = measureSection(node, children, (child) =>
      guard < 8 ? sizeOf(child, guard + 1) : nodeSize(child),
    );
    measured.set(node.id, size);
    return size;
  };

  const entry = (node: DiagramNode): SceneNode => {
    const all = childrenOf.get(node.id) ?? [];
    const children = all.filter((child) => ids.has(child.id));
    const size = node.kind === 'section' ? sizeOf(node) : nodeSize(node);    const position = absolutePosition(node, byId);
    const profile = node.kind === 'host' ? classifyHost(node.host) : undefined;
    const vulns = node.host?.vulns ?? [];
    return {
      node,
      box: { x: position.x, y: position.y, w: size.w, h: size.h },
      children,
      childCount: all.length,
      z: stackOf(node),
      risk: node.kind === 'host' ? nodeRisk(node.host, riskPolicy) : null,
      role: profile?.role,
      roleEvidence: profile?.roleEvidence,
      vulns,
      worstVuln: vulns[0] ?? null,
    };
  };

  // Outer frames first, so an exporter that paints in document order never covers a
  // nested frame with the one around it.
  const sections = doc.nodes
    .filter((node) => node.kind === 'section' && ids.has(node.id))
    .map(entry)
    .sort((a, b) => a.z - b.z || b.box.w * b.box.h - a.box.w * a.box.h);
  const cards = doc.nodes
    .filter((node) => node.kind !== 'section' && ids.has(node.id))
    .map(entry)
    .sort((a, b) => a.z - b.z);

  const index = new Map<string, SceneNode>();
  for (const item of [...sections, ...cards]) index.set(item.node.id, item);

  const edges: SceneEdge[] = [];
  for (const edge of doc.edges) {
    const source = index.get(edge.source);
    const target = index.get(edge.target);
    if (!source || !target) continue;
    edges.push({ edge, source, target, line: edgeLine(edge), path: edgePath(edge) });
  }

  let maxX = 0;
  let maxY = 0;
  let minX = Number.POSITIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  for (const item of [...sections, ...cards]) {
    maxX = Math.max(maxX, item.box.x + item.box.w);
    maxY = Math.max(maxY, item.box.y + item.box.h);
    minX = Math.min(minX, item.box.x);
    minY = Math.min(minY, item.box.y);
  }
  const empty = index.size === 0;
  const bounds: SceneBox = {
    x: empty ? 0 : minX,
    y: empty ? 0 : minY,
    w: empty ? 0 : maxX - minX,
    h: empty ? 0 : maxY - minY,
  };

  return { sections, cards, edges, ids, node: (id) => index.get(id), bounds };
}
