import type { ImportEffect, ImportMode } from '../doc/docFromScan';
import type { ImportPreview } from '../hooks/useImportFlow';
import { openPorts, discoveryOnly, type NmapScan } from '../model/types';
import { groupHosts, type HostGrouping } from '../graph/layout';

export const IMPORT_MODE_HINTS: Record<ImportMode, { label: string; hint: string }> = {
  merge: { label: 'Merge', hint: 'Refresh matching hosts, add new ones, keep the rest' },
  replace: { label: 'Replace', hint: 'Start over from this scan' },
  layer: { label: 'New layer', hint: 'Add this scan beside the current diagram' },
};

/** The prefixes the grouping control offers, plus the scan's own suggestion. */
const GROUPING_OPTIONS = [16, 20, 22, 24, 25, 26, 28];

const FORMAT_LABELS: Record<string, string> = {
  xml: 'nmap XML (-oX)',
  grepable: 'nmap grepable (-oG)',
  normal: 'nmap normal (-oN)',
};

function subnetCount(scan: NmapScan, grouping?: HostGrouping) {
  return groupHosts(scan.hosts.filter((host) => !host.ip.includes(':')), grouping).length;
}

/**
 * The review step of an import: what the file holds, how it should land, and
 * the scan metadata worth checking before committing. Shared by the standalone
 * preview (after a drag and drop) and by the guided import dialog.
 */
export function ImportPreviewBody({
  preview,
  effect,
  hasDiagram,
  onChooseMode,
  onChooseGrouping,
  onConfirm,
  onCancel,
  cancelLabel = 'Cancel',
}: {
  preview: ImportPreview;
  effect: ImportEffect | null;
  hasDiagram: boolean;
  onChooseMode: (mode: ImportMode) => void;
  onChooseGrouping?: (grouping: HostGrouping | undefined) => void;
  onConfirm: () => void;
  onCancel: () => void;
  cancelLabel?: string;
}) {
  const scan = preview.scan;
  const grouping = preview.grouping?.ipv4;
  const confirmLabel = !hasDiagram
    ? 'Import scan'
    : preview.mode === 'replace'
      ? 'Replace diagram'
      : preview.mode === 'layer'
        ? 'Add as layer'
        : 'Merge scan';

  return (
    <>
      <div className="import-preview__grid">
        <div>
          <strong>{scan.hosts.length}</strong>
          <span>hosts</span>
        </div>
        <div>
          <strong>{subnetCount(scan, preview.grouping)}</strong>
          <span>subnets</span>
        </div>
        <div>
          <strong>{scan.hosts.reduce((count, host) => count + openPorts(host).length, 0)}</strong>
          <span>open ports</span>
        </div>
        <div>
          <strong>{scan.trace?.length ?? scan.hosts.reduce((count, host) => count + host.hops.length, 0)}</strong>
          <span>trace hops</span>
        </div>
      </div>

      {hasDiagram ? (
        <div className="import-preview__modes" role="radiogroup" aria-label="Import mode">
          {(Object.keys(IMPORT_MODE_HINTS) as ImportMode[]).map((mode) => (
            <button
              key={mode}
              type="button"
              role="radio"
              aria-checked={preview.mode === mode}
              className={`import-mode${preview.mode === mode ? ' is-on' : ''}`}
              onClick={() => onChooseMode(mode)}
            >
              <strong>{IMPORT_MODE_HINTS[mode].label}</strong>
              <span>{IMPORT_MODE_HINTS[mode].hint}</span>
            </button>
          ))}
        </div>
      ) : (
        // Nothing to merge into or sit beside: there is one sensible outcome.
        <p className="import-preview__new">This scan becomes a new diagram.</p>
      )}

      {effect && (
        <p className={`import-preview__effect${preview.mode === 'replace' && hasDiagram ? ' is-warning' : ''}`}>
          {!hasDiagram
            ? `${effect.nodes} nodes · read in this browser, nothing uploaded`
            : preview.mode === 'merge'
              ? `${effect.added} new node${effect.added === 1 ? '' : 's'} · ${effect.matched} refreshed${
                  effect.updated > 0 ? ` (${effect.updated} changed)` : ''
                }${effect.stale > 0 ? ` · ${effect.stale} kept as stale` : ''}${
                  effect.closedPorts > 0 ? ` · ${effect.closedPorts} port no longer open` : ''
                }`
              : preview.mode === 'layer'
                ? `${effect.nodes} nodes on a new layer · the current diagram is untouched`
                : 'Replaces the open diagram – undo restores it'}
        </p>
      )}

      {preview.warnings.length > 0 && (
        <ul className="import-preview__warnings">
          {preview.warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      )}

      {onChooseGrouping && (
        <label className="import-preview__grouping">
          <span>Group hosts by</span>
          <select
            value={grouping === undefined ? 'auto' : String(grouping)}
            onChange={(event) => {
              const value = event.target.value;
              onChooseGrouping(value === 'auto' ? undefined : { ipv4: Number(value) });
            }}
          >
            <option value="auto">
              Auto{preview.grouping?.ipv4 ? ` (/${preview.grouping.ipv4})` : ' (/24)'}
            </option>
            {GROUPING_OPTIONS.map((prefix) => (
              <option key={prefix} value={prefix}>
                /{prefix}
              </option>
            ))}
          </select>
        </label>
      )}

      <dl className="import-preview__metadata">
        <div>
          <dt>Format</dt>
          <dd>
            {FORMAT_LABELS[preview.format] ?? preview.format}
            {scan.recovered ? <span className="import-preview__recovered"> · partially recovered</span> : null}
          </dd>
        </div>
        <div>
          <dt>Command</dt>
          <dd>{scan.args || 'Not reported'}</dd>
        </div>
        <div>
          <dt>Nmap version</dt>
          <dd>{scan.version || 'Not reported'}</dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd>{scan.startedAt || 'Not reported'}</dd>
        </div>
        <div>
          <dt>Elapsed</dt>
          <dd>{scan.elapsedSeconds != null ? `${scan.elapsedSeconds}s` : 'Not reported'}</dd>
        </div>
        <div>
          <dt>Discovery only</dt>
          <dd>{scan.hosts.filter((host) => discoveryOnly(host)).length} hosts without a port scan</dd>
        </div>
      </dl>

      <div className="dialog__actions">
        <button type="button" className="btn" onClick={onCancel}>
          {cancelLabel}
        </button>
        <button type="button" className="btn btn--accent" onClick={onConfirm}>
          {confirmLabel}
        </button>
      </div>
    </>
  );
}
