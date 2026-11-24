import type { DiagramDoc } from '../doc/types';
import type { NmapScan } from '../model/types';
import {
  createDocFromScan,
  importScanAsLayer,
  mergeScanIntoDoc,
  scanEffects,
  type ImportEffect,
  type ImportMode,
} from '../doc/docFromScan';
import type { HostGrouping } from '../graph/layout';
import { parseNmapXml } from './parseNmapXml';
import { parseGrepable, parseNormal, type TextScan } from './parseNmapText';
import { detectScanFormat, type ScanFormat } from './scanFormat';
import { targetsDiffer } from './targets';

/**
 * The whole nmap import – parse, lay out, merge – with no DOM and no React, so it
 * can run in a worker (see import.worker.ts) or inline where a worker is not
 * available. Everything the caller needs to update the app comes back in one
 * structured-cloneable object.
 */

export type ImportRequest = {
  text: string;
  fileName: string;
  mode: ImportMode;
  /** The document the import lands in; `null` starts a new one. */
  doc: DiagramDoc | null;
  /** Section grouping chosen in the preview; absent keeps the diagram's own. */
  grouping?: HostGrouping;
};

export type ImportSuccess = {
  ok: true;
  fileName: string;
  mode: ImportMode;
  /** Parsed scan, kept for the preview dialog's statistics. */
  scan: NmapScan;
  /** Effect counts for every mode, so switching modes needs no second pass. */
  effects: Record<ImportMode, ImportEffect>;
  /** The document this import produces. */
  doc: DiagramDoc;
  added: number;
  gone: number;
  layerId: string | null;
  /** Things the merge would do that the preview should say out loud. */
  warnings: string[];
  /** Which nmap output shape was read, for the preview's metadata line. */
  format: ScanFormat;
};

export type ImportFailure = { ok: false; error: string };

export type ImportResponse = ImportSuccess | ImportFailure;

/**
 * nmap is happy to write a file that found nothing – a router that drops the
 * probes, a typo in the range, the wrong interface. Say what nmap itself said
 * instead of drawing an empty diagram over the one that is open.
 */
function emptyScanError(fileName: string, scan: NmapScan): string {
  const args = scan.args ?? '';
  const hint = /(^|\s)-sn(\s|$)/.test(args)
    ? 'A ping sweep only lists hosts that answer – try sudo for ARP discovery on the local subnet, or scan again with -Pn.'
    : 'Nothing answered. Check the target range, and add -Pn when the hosts block ping.';
  const summary = scan.summary ? ` Nmap reported: ${scan.summary}.` : '';
  return `${fileName} is a valid scan, but it found 0 hosts up, so there is nothing to draw.${summary} ${hint}`;
}

/**
 * What the merge preview should say before the user commits: a scan pointed at a
 * different range, and ports the diagram still shows that this scan no longer
 * found (they are kept, with their last-seen time, rather than deleted).
 */
function importWarnings(doc: DiagramDoc | null, scan: NmapScan, effects: Record<ImportMode, ImportEffect>): string[] {
  if (!doc) return [];
  const warnings: string[] = [];
  if (targetsDiffer(doc.targets, scan.targets)) {
    warnings.push(
      `This scan targets ${scan.targets?.join(', ')} – the open diagram came from ${doc.targets?.join(', ')}. Cards are matched by address.`,
    );
  }
  const closed = effects.merge.closedPorts;
  if (closed > 0) {
    warnings.push(
      `${closed} open port${closed === 1 ? '' : 's'} in this diagram ${closed === 1 ? 'is' : 'are'} not reported by this scan; ${closed === 1 ? 'it stays' : 'they stay'} on the card with the time it was last seen.`,
    );
  }
  return warnings;
}

export function runImport({ text, fileName, mode, doc, grouping }: ImportRequest): ImportResponse {
  const format = detectScanFormat(text);
  let scan: NmapScan;
  let readWarnings: string[] = [];  try {
    if (format === 'xml') {
      scan = { ...parseNmapXml(text, fileName), format: 'xml' };
    } else if (format === 'grepable' || format === 'normal') {
      const read: TextScan = format === 'grepable' ? parseGrepable(text, fileName) : parseNormal(text, fileName);
      scan = { ...read.scan, format };
      readWarnings = read.warnings;
    } else if (format === 'unknown' && /^\s*</.test(text)) {
      // Something XML-shaped but not nmap: let the XML reader say exactly what is
      // wrong with it ("No <nmaprun> root element…") instead of a generic refusal.
      scan = { ...parseNmapXml(text, fileName), format: 'xml' };
    } else {
      return {
        ok: false,
        error:
          'That file is not an nmap scan this reader knows. Use -oX (XML), -oG (grepable) or -oN (normal) output, or a masscan XML file.',
      };
    }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'That file could not be read.' };
  }

  // A reader that had to repair or skip something says so on the scan; the preview
  // shows it before the user commits to a diagram built from a damaged file.
  readWarnings = [...readWarnings, ...(scan.warnings ?? [])];

  if (scan.hosts.length === 0) return { ok: false, error: emptyScanError(fileName, scan) };

  try {
    const effects = scanEffects(doc, scan, grouping);
    const warnings = [...readWarnings, ...importWarnings(doc, scan, effects)];

    if (!doc) {
      const next = createDocFromScan(scan, grouping);
      return { ok: true, fileName, mode: 'replace', scan, effects, doc: next, added: next.nodes.length, gone: 0, layerId: null, warnings, format };
    }

    if (mode === 'layer') {
      const { doc: next, layerId, added } = importScanAsLayer(doc, scan, grouping);
      return { ok: true, fileName, mode, scan, effects, doc: next, added, gone: 0, layerId, warnings, format };
    }

    if (mode === 'replace') {
      const next = createDocFromScan(scan, grouping);
      return { ok: true, fileName, mode, scan, effects, doc: next, added: next.nodes.length, gone: 0, layerId: null, warnings, format };
    }

    const { doc: next, added, gone } = mergeScanIntoDoc(doc, scan, grouping);
    return { ok: true, fileName, mode, scan, effects, doc: next, added, gone, layerId: null, warnings, format };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'The scan could not be laid out.' };
  }
}
