import {
  MarkerType,
  type Edge,
  type Node,
  type XYPosition,
} from '@xyflow/react';
import { type NmapHost, type VulnRef } from '../model/types';
import { type NodeRisk, type RiskPolicy } from '../doc/risk';
import type { DeviceEvidence, DeviceRole } from '../model/device';
import { matchesFilter, type CompiledFilter } from './filter';
import {
  edgeArrow,
  edgeLine,
  edgePath,
  edgeSides,
  type DiagramDoc,
  type DiagramEdge,
  type DiagramNode,
  type EdgeKind,
} from '../doc/types';
import { HOP_H, HOP_W, HOST_H, HOST_W, ORIGIN_H, ORIGIN_W } from './layout';
import { NOTE_MIN_H, NOTE_MIN_W, nodeSize, sectionMinSize } from '../doc/measure';
import { buildScene } from './scene';

export type AppNodeData = {
  node?: DiagramNode;
  host?: NmapHost;
  /** Resolved risk level for this host, from the active policy. */
  risk?: NodeRisk | null;
  /** What the box does, when the scan proves it. */
  role?: DeviceRole;
  roleEvidence?: DeviceEvidence;
  /** Findings the scan's scripts reported, worst first. */
  vulns?: VulnRef[];
  childCount?: number;
  dimmed?: boolean;
  editing?: boolean;
  dropTarget?: boolean;
  minW?: number;
  minH?: number;
  onToggle?: (id: string) => void;
  onTidy?: (id: string) => void;
  onResize?: (id: string, size: { w: number; h: number }) => void;
  onNoteFocus?: () => void;
  onNoteChange?: (id: string, notes: string) => void;
  onStopEdit?: () => void;
  onDelete?: (id: string) => void;
};

export type AppNode = Node<AppNodeData>;
export type AppEdge = Edge<{ kind: EdgeKind; label?: string }>;

export type BuildOptions = {
  selectedNodeIds: string[];
  selectedEdgeIds: string[];
  /** The compiled canvas filter; an invalid pattern is handled by the caller. */
  filter: CompiledFilter;
  onlyMatches?: boolean;
  riskPolicy: RiskPolicy;
  editingNoteId?: string | null;
  dropSectionId?: string | null;
  onToggle: (id: string) => void;
  /** A hand-dragged size for a frame or a note. */
  onResize?: (id: string, size: { w: number; h: number }) => void;
  onSectionTidy?: (id: string) => void;
  onNoteFocus?: () => void;
  onNoteChange?: (id: string, notes: string) => void;
  onStopEdit?: () => void;
  onDelete?: (id: string) => void;
};

const ROUTE_STYLE = { stroke: '#3f5d7a', strokeWidth: 1.5 };
const INTO_HOST_STYLE = { stroke: '#2b4459', strokeWidth: 1.1, opacity: 0.7 };
const LINK_STYLE = { stroke: 'var(--accent)', strokeWidth: 1.8 };

const DASH: Record<string, string | undefined> = {
  solid: undefined,
  dashed: '9 5',
  dotted: '1.6 4.6',
};

const RF_EDGE_TYPE = {
  curve: 'default',
  straight: 'straight',
  step: 'step',
  smoothstep: 'smoothstep',
} as const;

export function buildRfGraph(
  doc: DiagramDoc,
  {
    selectedNodeIds,
    selectedEdgeIds,
    filter,
    onlyMatches,
    riskPolicy,
    editingNoteId,
    dropSectionId,
    onToggle,
    onResize,
    onSectionTidy,
    onNoteFocus,
    onNoteChange,
    onStopEdit,
    onDelete,
  }: BuildOptions,
): { nodes: AppNode[]; edges: AppEdge[] } {
  const searching = filter.terms.length > 0;
  const selectedNodes = new Set(selectedNodeIds);
  const selectedEdges = new Set(selectedEdgeIds);

  // Visibility, geometry and stacking belong to the scene, so the canvas and the
  // exporters cannot drift apart about what is on the diagram.
  const scene = buildScene(doc, riskPolicy);

  const nodes: AppNode[] = [];
  const pushed = new Set<string>();
  // Measured boxes come from the scene, so a frame's minimum size is the size its
  // children were drawn at – nested frames included.
  const sizeOf = (node: DiagramNode) => {
    const item = scene.node(node.id);
    return item ? { w: item.box.w, h: item.box.h } : nodeSize(node);
  };
  // React Flow needs a parent before its children in the array, so frames are
  // ordered by how deeply they nest and cards follow them.
  const ordered = [...scene.sections.map((item) => item.node), ...scene.cards.map((item) => item.node)];

  for (const node of ordered) {
    const item = scene.node(node.id);
    if (!item) continue;
    const matches = !searching || matchesFilter(node, filter, riskPolicy);
    const dimmed = searching && !matches;
    if (onlyMatches && searching && !matches) continue;
    // A card whose frame was filtered out has nowhere to hang.
    if (node.parentId && !pushed.has(node.parentId)) continue;

    if (node.kind === 'section') {
      const min = sectionMinSize(item.children, sizeOf);
      nodes.push({
        id: node.id,
        type: 'section',
        position: node.position,
        parentId: node.parentId ?? undefined,
        selected: selectedNodes.has(node.id),
        style: { width: item.box.w, height: item.box.h },
        data: {
          node,
          childCount: item.childCount,
          dimmed,
          dropTarget: dropSectionId === node.id,
          minW: node.manualSize ? 160 : min.w,
          minH: node.manualSize ? 96 : min.h,
          onToggle,
          onTidy: onSectionTidy,
          onResize,
        },
        zIndex: item.z,
      });
      pushed.add(node.id);
      continue;
    }

    const position: XYPosition = node.position;
    const common = {
      id: node.id,
      position,
      parentId: node.parentId ?? undefined,
      selected: selectedNodes.has(node.id),
      data: {
        node,
        host: node.host,
        risk: item.risk,
        role: item.role,
        roleEvidence: item.roleEvidence,
        vulns: item.vulns,
        dimmed,
        editing: editingNoteId === node.id,
        onToggle,
        onNoteFocus,
        onNoteChange,
        onStopEdit,
        onDelete,
      },
    };

    if (node.kind === 'host') {
      nodes.push({
        ...common,
        type: 'host',
        style: { width: HOST_W, height: HOST_H },
        zIndex: item.z,
        hidden: false,
      });
    } else if (node.kind === 'note') {
      nodes.push({
        ...common,
        type: 'note',
        style: { width: item.box.w, height: item.box.h },
        data: {
          ...common.data,
          minW: NOTE_MIN_W,
          minH: NOTE_MIN_H,
          onResize,
        },
        zIndex: item.z,
      });
    } else if (node.kind === 'hop') {
      nodes.push({
        ...common,
        type: 'hop',
        style: { width: HOP_W, height: HOP_H },
        zIndex: item.z,
      });
    } else {
      nodes.push({
        ...common,
        type: 'origin',
        style: { width: ORIGIN_W, height: ORIGIN_H },
        zIndex: item.z,
      });
    }
    pushed.add(node.id);
  }

  const shown = new Set(nodes.map((node) => node.id));
  const edges: AppEdge[] = [];
  for (const { edge } of scene.edges) {
    if (!shown.has(edge.source) || !shown.has(edge.target)) continue;
    edges.push(toRfEdge(edge, selectedEdges.has(edge.id)));
  }

  return { nodes, edges };
}

export function toRfEdge(edge: DiagramEdge, selected: boolean): AppEdge {
  const line = edgeLine(edge);
  const dash = DASH[line];
  const round = line === 'dotted' ? { strokeLinecap: 'round' as const } : {};
  const type = RF_EDGE_TYPE[edgePath(edge)];
  const sides = edgeSides(edge);
  const arrow = edgeArrow(edge);

  if (edge.kind === 'route') {
    const intoHost = edge.target.startsWith('host:');
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      sourceHandle: sides.from,
      targetHandle: sides.to,
      type,
      selected,
      interactionWidth: 12,
      data: { kind: edge.kind, label: edge.label },
      style: { ...(intoHost ? INTO_HOST_STYLE : ROUTE_STYLE), ...round, strokeDasharray: dash },
      ...arrowMarkers(arrow, '#3f5d7a'),
      label: edge.label,
      labelStyle: LABEL_STYLE,
      labelBgStyle: LABEL_BG_STYLE,
    };
  }
  return {
    id: edge.id,
    source: edge.source,
    target: edge.target,
    sourceHandle: sides.from,
    targetHandle: sides.to,
    type,
    selected,
    interactionWidth: 26,
    data: { kind: edge.kind, label: edge.label },
    style: { ...LINK_STYLE, ...round, strokeDasharray: dash },
    ...arrowMarkers(arrow, 'var(--accent)'),
    label: edge.label,
    labelStyle: LABEL_STYLE,
    labelBgStyle: LABEL_BG_STYLE,
  };
}

/** Arrowheads on the ends the edge asks for; `none` keeps a plain line. */
function arrowMarkers(arrow: ReturnType<typeof edgeArrow>, color: string) {
  const marker = { type: MarkerType.ArrowClosed, color, width: 16, height: 16 };
  if (arrow === 'none') return {};
  if (arrow === 'source') return { markerStart: marker };
  if (arrow === 'both') return { markerStart: marker, markerEnd: marker };
  return { markerEnd: marker };
}

const LABEL_STYLE = { fill: '#cfdae6', fontSize: 10, fontFamily: 'ui-monospace, monospace' };
const LABEL_BG_STYLE = { fill: '#0d141c', fillOpacity: 0.9 };
