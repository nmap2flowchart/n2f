import type { DiagramNode } from './types';
import { HOP_H, HOP_W, HOST_H, HOST_W, NOTE_H, NOTE_W, ORIGIN_H, ORIGIN_W } from '../graph/layout';

export const SECTION_PAD = 24;
export const SECTION_HEADER = 44;
export const SECTION_MIN_W = 300;
export const SECTION_MIN_H = 150;
export const COLLAPSED_H = 52;
/** A note thinner than this cannot show its own title. */
export const NOTE_MIN_W = 160;
export const NOTE_MIN_H = 100;

export type Size = { w: number; h: number };

export function nodeSize(node: DiagramNode): Size {
  switch (node.kind) {
    case 'section':
      return { w: node.size?.w ?? 360, h: node.size?.h ?? 240 };
    case 'note':
      return { w: node.size?.w ?? NOTE_W, h: node.size?.h ?? NOTE_H };
    case 'hop':
      return { w: HOP_W, h: HOP_H };
    case 'origin':
      return { w: ORIGIN_W, h: ORIGIN_H };
    default:
      return { w: HOST_W, h: HOST_H };
  }
}

/**
 * `sizeOf` answers "how big is this child". A section child has to be measured from
 * its own children first, which is what `nodeSizer` does – measuring a frame from
 * another frame's declared `size` would use a stale number once the inner frame
 * grows.
 */
export function sectionMinSize(
  children: DiagramNode[],
  sizeOf: (node: DiagramNode) => Size = nodeSize,
): Size {
  let right = SECTION_PAD;
  let bottom = SECTION_HEADER + 12;
  for (const child of children) {
    const size = sizeOf(child);
    right = Math.max(right, child.position.x + size.w + SECTION_PAD);
    bottom = Math.max(bottom, child.position.y + size.h + SECTION_PAD);
  }
  return {
    w: Math.max(right, SECTION_MIN_W),
    h: Math.max(bottom, SECTION_MIN_H),
  };
}

export function measureSection(
  section: DiagramNode,
  children: DiagramNode[],
  sizeOf: (node: DiagramNode) => Size = nodeSize,
): Size {
  if (section.collapsed) {
    return { w: Math.max(section.size?.w ?? 0, SECTION_MIN_W), h: COLLAPSED_H };
  }
  if (section.manualSize && section.size) {
    return { w: Math.max(section.size.w, 160), h: Math.max(section.size.h, 96) };
  }
  const min = sectionMinSize(children, sizeOf);
  return {
    w: Math.max(section.size?.w ?? 0, min.w),
    h: Math.max(section.size?.h ?? 0, min.h),
  };
}

/**
 * One resolver for every node in a document, so a frame inside a frame is measured
 * from finished children rather than from a declared size. Children are measured
 * before parents, and a repeated id or a parent cycle stops at the guard instead of
 * recursing.
 */
export function nodeSizer(nodes: DiagramNode[]): (node: DiagramNode) => Size {
  const childrenOf = new Map<string, DiagramNode[]>();
  for (const node of nodes) {
    if (!node.parentId) continue;
    const bucket = childrenOf.get(node.parentId);
    if (bucket) bucket.push(node);
    else childrenOf.set(node.parentId, [node]);
  }
  const memo = new Map<string, Size>();
  const resolve = (node: DiagramNode, depth = 0): Size => {
    const known = memo.get(node.id);
    if (known) return known;
    const size =
      node.kind === 'section' && depth < 8
        ? measureSection(node, childrenOf.get(node.id) ?? [], (child) => resolve(child, depth + 1))
        : nodeSize(node);
    memo.set(node.id, size);
    return size;
  };
  return (node) => resolve(node);
}

const SLOT_GAP = 14;
/** A section wider than this many card columns is not a layout anyone can read. */
const MAX_SLOT_COLUMNS = 512;

type SlotBox = { left: number; top: number; right: number; bottom: number };

const overlaps = (candidate: SlotBox, box: SlotBox): boolean =>
  !(
    candidate.right + SLOT_GAP <= box.left ||
    box.right + SLOT_GAP <= candidate.left ||
    candidate.bottom + SLOT_GAP <= box.top ||
    box.bottom + SLOT_GAP <= candidate.top
  );

/**
 * Finds free slots in a section.
 *
 * The candidates are the sibling positions, which in a laid-out section sit on a
 * card-pitch grid, so siblings are bucketed by that pitch and a candidate only
 * tests the handful of boxes its own footprint touches. The old search tested
 * every candidate against every sibling, which is what made a dense network map
 * slow to paste into or merge into.
 */
function createSlotFinder(section: DiagramNode, siblings: DiagramNode[], size: Size) {
  const startY = SECTION_HEADER + SECTION_PAD;
  const frame = measureSection(section, siblings);
  const rightEdge = frame.w - SECTION_PAD;

  const xs = [...new Set([SECTION_PAD, ...siblings.map((child) => child.position.x)])].sort((a, b) => a - b);
  const ys = [...new Set([startY, ...siblings.map((child) => child.position.y)])].sort((a, b) => a - b);
  while (xs[xs.length - 1] + size.w < rightEdge && xs.length < MAX_SLOT_COLUMNS) {
    xs.push(xs[xs.length - 1] + size.w + SLOT_GAP);
  }
  ys.push(ys[ys.length - 1] + size.h + SLOT_GAP);

  const pitchX = size.w + SLOT_GAP;
  const pitchY = size.h + SLOT_GAP;
  const buckets = new Map<string, SlotBox[]>();
  const all: SlotBox[] = [];
  const bucketsFor = (box: SlotBox) => {
    const keys: string[] = [];
    const firstCol = Math.floor(box.left / pitchX);
    const lastCol = Math.floor(box.right / pitchX);
    const firstRow = Math.floor(box.top / pitchY);
    const lastRow = Math.floor(box.bottom / pitchY);
    for (let col = firstCol; col <= lastCol; col += 1) {
      for (let row = firstRow; row <= lastRow; row += 1) keys.push(`${col}:${row}`);
    }
    return keys;
  };
  const index = (box: SlotBox) => {
    all.push(box);
    for (const key of bucketsFor(box)) {
      const bucket = buckets.get(key);
      if (bucket) bucket.push(box);
      else buckets.set(key, [box]);
    }
  };
  for (const child of siblings) {
    const childSize = nodeSize(child);
    index({
      left: child.position.x,
      top: child.position.y,
      right: child.position.x + childSize.w,
      bottom: child.position.y + childSize.h,
    });
  }

  const free = (candidate: SlotBox) =>
    bucketsFor(candidate).every((key) => (buckets.get(key) ?? []).every((box) => !overlaps(candidate, box)));

  return () => {
    for (const y of ys) {
      for (const x of xs) {
        if (x + size.w > rightEdge) break;
        const candidate: SlotBox = { left: x, top: y, right: x + size.w, bottom: y + size.h };
        if (!free(candidate)) continue;
        index(candidate);
        return { x, y };
      }
    }
    // The frame is full: land below everything that is already in it, which grows
    // the section rather than stacking a card on one that is there.
    let bottom = startY;
    for (const box of all) bottom = Math.max(bottom, box.bottom);
    const y = bottom + SLOT_GAP;
    index({ left: SECTION_PAD, top: y, right: SECTION_PAD + size.w, bottom: y + size.h });
    return { x: SECTION_PAD, y };
  };
}

export function slotInSection(
  section: DiagramNode,
  siblings: DiagramNode[],
  size: Size = { w: HOST_W, h: HOST_H },
): { x: number; y: number } {
  return createSlotFinder(section, siblings, size)();
}

/**
 * Place several cards in one pass – a merge or a multi-node paste – without any of
 * them landing on a sibling or on each other.
 */
export function slotsInSection(
  section: DiagramNode,
  siblings: DiagramNode[],
  count: number,
  size: Size = { w: HOST_W, h: HOST_H },
): { x: number; y: number }[] {
  const next = createSlotFinder(section, siblings, size);
  return Array.from({ length: Math.max(0, count) }, () => next());
}

export function absolutePosition(node: DiagramNode, byId: Map<string, DiagramNode>): { x: number; y: number } {
  let x = node.position.x;
  let y = node.position.y;
  let parent = node.parentId ? byId.get(node.parentId) : undefined;
  let guard = 0;
  while (parent && guard < 16) {
    x += parent.position.x;
    y += parent.position.y;
    parent = parent.parentId ? byId.get(parent.parentId) : undefined;
    guard += 1;
  }
  return { x, y };
}

export type SectionFrame = {
  id: string;
  node: DiagramNode;
  /** Absolute canvas rectangle, so a hit test never rescans the document. */
  x: number;
  y: number;
  w: number;
  h: number;
  area: number;
};

/**
 * Every section's absolute frame, measured in one pass.
 *
 * Dragging asks "which section is under this card" on every pointer move; building
 * this once per drag (or per drop) keeps the answer out of the O(sections × nodes)
 * shape it had when each section filtered the whole document for its children.
 */
export function sectionFrames(nodes: DiagramNode[]): SectionFrame[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const sizeOf = nodeSizer(nodes);

  const frames: SectionFrame[] = [];
  for (const node of nodes) {
    if (node.kind !== 'section') continue;
    const size = sizeOf(node);
    const origin = absolutePosition(node, byId);
    frames.push({
      id: node.id,
      node,
      x: origin.x,
      y: origin.y,
      w: size.w,
      h: size.h,
      area: size.w * size.h,
    });
  }
  return frames;
}

/** The smallest frame containing the point – the innermost section wins. */
export function sectionAtFrames(
  frames: SectionFrame[],
  point: { x: number; y: number },
  options: { skip?: string | ReadonlySet<string> } = {},
): string | null {
  const skip = typeof options.skip === 'string' ? new Set([options.skip]) : options.skip;
  let best: SectionFrame | null = null;
  for (const frame of frames) {
    if (skip?.has(frame.id)) continue;
    const inside =
      point.x >= frame.x && point.x <= frame.x + frame.w && point.y >= frame.y && point.y <= frame.y + frame.h;
    if (inside && (!best || frame.area < best.area)) best = frame;
  }
  return best?.id ?? null;
}

export function sectionAt(
  nodes: DiagramNode[],
  point: { x: number; y: number },
  options: { skip?: string | ReadonlySet<string> } = {},
): string | null {
  return sectionAtFrames(sectionFrames(nodes), point, options);
}
