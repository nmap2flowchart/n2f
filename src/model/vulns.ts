import type { NmapHost, NmapScript } from './types';
import type { VulnRef, VulnSeverity } from './types';

export type { VulnRef, VulnSeverity } from './types';

/**
 * Vulnerabilities an nmap script run reported.
 *
 * Everything here comes from the scan itself – `vulners`, `smb-vuln-*`,
 * `http-vuln-*`, `rdp-vuln-*` – because the editor never talks to the network and
 * has no vulnerability database to look a version up in.
 */

export const VULN_SEVERITY_ORDER: VulnSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const VULN_SEVERITY_LABELS: Record<VulnSeverity, string> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
};

const SEVERITY_COLORS: Record<VulnSeverity, string> = {
  critical: '#e5484d',
  high: '#f08c2e',
  medium: '#e3c53d',
  low: '#3b82f6',
  info: '#94a3b8',
};

export const vulnColor = (severity: VulnSeverity): string => SEVERITY_COLORS[severity];

export function severityOfScore(cvss: number | undefined): VulnSeverity {
  if (cvss === undefined || !Number.isFinite(cvss)) return 'info';
  if (cvss >= 9) return 'critical';
  if (cvss >= 7) return 'high';
  if (cvss >= 4) return 'medium';
  if (cvss > 0) return 'low';
  return 'info';
}

const CVE = /CVE-\d{4}-\d{4,7}/gi;
/** `vulners` prints `CVE-2021-44228  9.8  https://vulners.com/cve/…`. */
const VULNERS_ROW = /(CVE-\d{4}-\d{4,7})\s+(\d{1,2}(?:\.\d)?)/gi;

function scriptList(host: NmapHost): NmapScript[] {
  return [...host.scripts, ...host.ports.flatMap((port) => port.scripts)].filter((script) => script.output.length > 0);
}

/** A script that says `State: VULNERABLE` is reporting a finding, not a version. */
function isVulnerable(script: NmapScript): boolean {
  return /state:\s*vulnerable/i.test(script.output);
}

function scoreNear(output: string, id: string): number | undefined {
  const index = output.toUpperCase().indexOf(id.toUpperCase());
  if (index < 0) return undefined;
  const window = output.slice(Math.max(0, index - 40), index + id.length + 60);
  const match = /(\b\d{1,2}(?:\.\d)?\b)/.exec(window.replace(/CVE-\d{4}-\d{4,7}/i, ''));
  const value = match ? Number(match[1]) : Number.NaN;
  return Number.isFinite(value) && value >= 0 && value <= 10 ? value : undefined;
}

/**
 * Every finding the scan carries, deduped by id with the highest score kept, worst
 * first. A card with forty CVEs reports the first few and a count.
 */
export function vulnsOf(host: NmapHost | undefined): VulnRef[] {
  if (!host) return [];
  const found = new Map<string, VulnRef>();

  const add = (entry: VulnRef) => {
    const current = found.get(entry.id);
    if (!current) {
      found.set(entry.id, entry);
      return;
    }
    const better = (entry.cvss ?? 0) > (current.cvss ?? 0);
    found.set(entry.id, {
      ...current,
      ...(better && entry.cvss !== undefined ? { cvss: entry.cvss, severity: entry.severity } : {}),
      title: current.title ?? entry.title,
    });
  };

  for (const script of scriptList(host)) {
    const reported = script.id.startsWith('vuln') || script.id.includes('vuln') || isVulnerable(script);
    if (!reported) continue;

    const rows = [...script.output.matchAll(VULNERS_ROW)];
    if (rows.length > 0) {
      for (const row of rows) {
        const cvss = Number(row[2]);
        add({
          id: row[1].toUpperCase(),
          cvss: Number.isFinite(cvss) ? cvss : undefined,
          severity: severityOfScore(cvss),
          script: script.id,
        });
      }
      continue;
    }

    const ids = [...new Set((script.output.match(CVE) ?? []).map((id) => id.toUpperCase()))];
    if (ids.length > 0) {
      // A script that says "VULNERABLE" without a score is still a finding.
      const fallback: VulnSeverity = isVulnerable(script) ? 'high' : 'info';
      for (const id of ids) {
        const cvss = scoreNear(script.output, id);
        add({ id, cvss, severity: cvss === undefined ? fallback : severityOfScore(cvss), script: script.id });
      }
      continue;
    }

    if (isVulnerable(script)) {
      const title = /^\s*\|?\s*([A-Za-z][^\n:]{6,80}):/m.exec(script.output)?.[1]?.trim();
      add({ id: script.id, severity: 'high', script: script.id, ...(title ? { title } : {}) });
    }
  }

  return [...found.values()].sort(
    (a, b) =>
      VULN_SEVERITY_ORDER.indexOf(a.severity) - VULN_SEVERITY_ORDER.indexOf(b.severity) ||
      (b.cvss ?? 0) - (a.cvss ?? 0) ||
      a.id.localeCompare(b.id),
  );
}

/** The worst finding a card carries, for its badge. */
export function worstVuln(vulns: VulnRef[]): VulnRef | null {
  return vulns[0] ?? null;
}
