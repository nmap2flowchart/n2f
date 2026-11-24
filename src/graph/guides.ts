import type { DiagramDoc, DiagramNode } from '../doc/types';
import { absolutePosition, nodeSize } from '../doc/measure';

export type Guide = {
  axis: 'x' | 'y';
  /** Flow coordinate of the line. */
  at: number;
  /** Where the line starts and ends, so it spans the cards it relates. */
  from: number;
  to: number;
};

type Hit = { at: number; diff: number };

const edges = (start: number, size: number) => [start, start + size / 2, start + size];

/** One line another card offers: its coordinate and the span it covers. */
type LineEntry = { at: number; from: number; to: number };

/**
 * The lines every other card offers, per axis, sorted once.
 *
 * Dragging asks this question on every pointer move, and the answer only changes
 * when a card moves – so the scan of the whole document happens once per drag
 * (see `createGuideIndex`) and each frame becomes a binary search.
 */
export type GuideIndex = { x: LineEntry[]; y: LineEntry[] };

const sorted = (entries: LineEntry[]): LineEntry[] => entries.sort((a, b) => a.at - b.at);

export function createGuideIndex(doc: DiagramDoc, nodeId: string): GuideIndex {
  const byId = new Map(doc.nodes.map((item) => [item.id, item]));
  const x: LineEntry[] = [];
  const y: LineEntry[] = [];
  for (const item of doc.nodes) {
    if (item.id === nodeId) continue;
    const at = absolutePosition(item, byId);
    const size = nodeSize(item);
    for (const line of edges(at.x, size.w)) x.push({ at: line, from: at.y, to: at.y + size.h });
    for (const line of edges(at.y, size.h)) y.push({ at: line, from: at.x, to: at.x + size.w });
  }
  return { x: sorted(x), y: sorted(y) };
}

/** First index whose coordinate is at or after `value`. */
function lowerBound(entries: LineEntry[], value: number): number {
  let low = 0;
  let high = entries.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (entries[middle].at < value) low = middle + 1;
    else high = middle;
  }
  return low;
}

function nearest(entries: LineEntry[], own: number, threshold: number): Hit | null {
  let best: Hit | null = null;
  const consider = (entry: LineEntry) => {
    const diff = Math.abs(own - entry.at);
    if (diff > threshold) return;
    if (!best || diff < best.diff) best = { at: entry.at, diff };
  };
  // Only the window inside the threshold is looked at, from the insertion point
  // outwards: a dense map has thousands of lines, six of which can matter.
  const start = lowerBound(entries, own - threshold);
  for (let index = start; index < entries.length && entries[index].at <= own + threshold; index += 1) {
    consider(entries[index]);
  }
  for (let index = start - 1; index >= 0 && entries[index].at >= own - threshold; index -= 1) {
    consider(entries[index]);
  }
  return best;
}

type Box = { x: number; y: number; w: number; h: number };

/**
 * The lines a dragged card shares with its neighbours, from a prepared index.
 * Only the closest match per axis is returned – two lines are a hint, ten of them
 * are noise. `self` is the dragged card's absolute box.
 */
export function guidesFromIndex(index: GuideIndex, self: Box, threshold = 5): Guide[] {
  const pick = (entries: LineEntry[], own: number[], axis: 'x' | 'y'): Guide | null => {
    let best: Hit | null = null;
    for (const line of own) {
      const hit = nearest(entries, line, threshold);
      if (hit && (!best || hit.diff < best.diff)) best = hit;
    }
    if (!best) return null;
    let from = axis === 'x' ? self.y : self.x;
    let to = axis === 'x' ? self.y + self.h : self.x + self.w;
    for (let i = lowerBound(entries, best.at - 0.5); i < entries.length && entries[i].at < best.at + 0.5; i += 1) {
      from = Math.min(from, entries[i].from);
      to = Math.max(to, entries[i].to);
    }
    return { axis, at: best.at, from, to };
  };

  const guides: Guide[] = [];
  const vertical = pick(index.x, edges(self.x, self.w), 'x');
  if (vertical) guides.push(vertical);
  const horizontal = pick(index.y, edges(self.y, self.h), 'y');
  if (horizontal) guides.push(horizontal);
  return guides;
}

/**
 * The lines a dragged card shares with its neighbours: left/centre/right and
 * top/middle/bottom.
 *
 * `position` is the card's position while dragging (relative to its section, as
 * React Flow reports it), `threshold` is in flow units. A drag should prepare the
 * index once (`createGuideIndex`) and ask `guidesFromIndex` per frame instead.
 */
export function alignmentGuides(
  doc: DiagramDoc,
  node: DiagramNode,
  position: { x: number; y: number },
  threshold = 5,
): Guide[] {
  const byId = new Map(doc.nodes.map((item) => [item.id, item]));
  const at = absolutePosition({ ...node, position }, byId);
  const size = nodeSize(node);
  return guidesFromIndex(createGuideIndex(doc, node.id), { x: at.x, y: at.y, w: size.w, h: size.h }, threshold);
}
