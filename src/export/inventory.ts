import type { DiagramDoc, DiagramNode } from '../doc/types';
import { nodeTitle } from '../doc/types';
import { RISK_SCOPE_LABEL, type RiskPolicy, type RiskScope } from '../doc/risk';
import { buildScene } from '../graph/scene';
import { DEVICE_ROLE_LABELS, classifyHost, HIGH_VALUE_ROLES } from '../model/device';
import { openPorts } from '../model/types';
import { csvCell } from './text';

/**
 * The diagram as an inventory: one row per host card, grouped by its section.
 *
 * The picture answers "what does this network look like"; a table is what people
 * put in a ticket, a change record or a handover. Both read the same scene, so the
 * scope (focused layer, hidden nodes) is the same one the canvas shows.
 */

export type InventoryMeta = {
  diagram: string;
  /** Human sentence describing what is in the table. */
  scopeLabel: string;
  policyScope: RiskScope;
  generated: string;
};

export type InventoryRow = {
  section: string;
  address: string;
  names: string;
  role: string;
  os: string;
  ports: string;
  risk: string;
  cves: string;
  layer: string;
};

function sectionTitle(doc: DiagramDoc, node: DiagramNode): string {
  if (!node.parentId) return '(free on canvas)';
  const parent = doc.nodes.find((item) => item.id === node.parentId);
  return parent ? nodeTitle(parent) : '(free on canvas)';
}

export function inventoryRows(doc: DiagramDoc, riskPolicy: RiskPolicy): InventoryRow[] {
  const scene = buildScene(doc, riskPolicy);
  const rows: InventoryRow[] = [];
  for (const item of scene.cards) {
    const node = item.node;
    if (node.kind !== 'host' || !node.host) continue;
    const host = node.host;
    const profile = classifyHost(host);
    const risk = item.risk;    rows.push({
      section: sectionTitle(doc, node),
      address: nodeTitle(node),
      names: host.hostnames.join(', ') || host.mac || '',
      role: profile.role ? DEVICE_ROLE_LABELS[profile.role] : '',
      os: host.os[0]?.name ?? '',
      ports: openPorts(host)
        .map((port) => `${port.port}/${port.service ?? port.protocol}`)
        .join(', '),
      risk: risk ? risk.label : '',
      cves: (host.vulns ?? []).map((vuln) => vuln.id).join(' '),
      layer: doc.layers.find((layer) => layer.id === node.layerId)?.name ?? '',
    });
  }
  return rows.sort(
    (a, b) => a.section.localeCompare(b.section) || a.address.localeCompare(b.address),
  );
}

/** Markdown has no cell escaping rule, so a pipe or a newline in a name would break the table. */
const cell = (value: string): string => value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim();

function header(doc: DiagramDoc, meta: InventoryMeta): string[] {
  return [
    `# ${cell(meta.diagram)} – host inventory`,
    '',
    `- Scope: ${cell(meta.scopeLabel)}`,
    `- Risk levels: ${RISK_SCOPE_LABEL[meta.policyScope]}`,
    ...(doc.args ? [`- Command: \`${doc.args.replace(/`/g, "'")}\``] : []),
    ...(doc.targets?.length ? [`- Targets: ${doc.targets.join(', ')}`] : []),
    ...(doc.grouping?.ipv4 ? [`- Sections: /${doc.grouping.ipv4} per frame`] : []),
    `- Generated: ${meta.generated}`,
    '',
  ];
}

export function toInventoryMarkdown(doc: DiagramDoc, riskPolicy: RiskPolicy, meta: InventoryMeta): string {
  const rows = inventoryRows(doc, riskPolicy);
  const lines = header(doc, meta);
  if (rows.length === 0) {
    lines.push('No host cards are in the exported scope.', '');
    return lines.join('\n');
  }

  const groups = new Map<string, InventoryRow[]>();
  for (const row of rows) {
    const bucket = groups.get(row.section);
    if (bucket) bucket.push(row);
    else groups.set(row.section, [row]);
  }

  for (const [section, entries] of groups) {
    lines.push(`## ${cell(section)}`, '');
    lines.push('| Address | Names | Role | OS | Open ports | Risk | Findings | Layer |');
    lines.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
    for (const row of entries) {
      lines.push(
        `| ${[row.address, row.names, row.role, row.os, row.ports, row.risk, row.cves, row.layer]
          .map(cell)
          .join(' | ')} |`,
      );
    }
    lines.push('');
  }

  const findings = rows.reduce((total, row) => total + (row.cves ? row.cves.split(' ').length : 0), 0);
  lines.push(
    `_${rows.length} host${rows.length === 1 ? '' : 's'}, ` +
      `${rows.reduce((total, row) => total + (row.ports ? row.ports.split(', ').length : 0), 0)} open ports, ` +
      `${findings} finding${findings === 1 ? '' : 's'}._`,
    '',
  );
  return lines.join('\n');
}

export function toInventoryCsv(doc: DiagramDoc, riskPolicy: RiskPolicy, meta: InventoryMeta): string {
  const rows = inventoryRows(doc, riskPolicy);
  const headerRow = ['section', 'address', 'names', 'role', 'os', 'open_ports', 'risk', 'cves', 'layer'];
  const lines = rows.map((row) =>
    [row.section, row.address, row.names, row.role, row.os, row.ports, row.risk, row.cves, row.layer]
      .map(csvCell)
      .join(','),
  );
  return [
    `# ${meta.diagram} · host inventory · ${meta.scopeLabel} · levels: ${RISK_SCOPE_LABEL[meta.policyScope]}`,
    headerRow.join(','),
    ...lines,
  ].join('\r\n');
}

/** Hosts whose role is worth a summary line, used by the dialog and tests. */
export function roleCounts(doc: DiagramDoc): { role: string; hosts: number }[] {
  const counts = new Map<string, number>();
  for (const node of doc.nodes) {
    if (!node.host) continue;
    const profile = classifyHost(node.host);
    if (!profile.role || !HIGH_VALUE_ROLES.has(profile.role)) continue;
    const label = DEVICE_ROLE_LABELS[profile.role];
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([role, hosts]) => ({ role, hosts }))
    .sort((a, b) => b.hosts - a.hosts || a.role.localeCompare(b.role));
}
