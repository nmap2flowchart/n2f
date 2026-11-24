/**
 * What a scan was pointed at.
 *
 * nmap records the command line it ran (`<nmaprun args>`), and `-oX` also writes a
 * `<target specification>` element for a target it skipped. Both are read here so
 * the importer can tell whether a scan covers the range the diagram already holds,
 * and how wide a section frame should be.
 */

/** Flags that take the next token as their value, so it is not a target. */
const VALUE_FLAGS = new Set([
  '-oA',
  '-oG',
  '-oN',
  '-oX',
  '-oS',
  '-iL',
  '-iR',
  '-p',
  '-e',
  '-S',
  '-g',
  '-b',
  '-D',
  '--script',
  '--script-args',
  '--script-args-file',
  '--exclude',
  '--excludefile',
  '--top-ports',
  '--data-dir',
  '--data-length',
  '--source-port',
  '--max-retries',
  '--host-timeout',
  '--scan-delay',
  '--max-scan-delay',
  '--min-rate',
  '--max-rate',
  '--min-parallelism',
  '--max-parallelism',
  '--defeat-rst-ratelimit',
  // masscan's command line, which lands in the same `<nmaprun args>` attribute.
  '--output-format',
  '--output-file',
  '-oB',
  '-oJ',
  '-oL',
  '-oM',
  '-oH',
  '--rate',
  '--readscan',
  '--adapter',
  '--adapter-ip',
  '--adapter-port',
  '--adapter-mac',
  '--router-mac',
  '--source-ip',
  '--source-port',
  '--interface',
  '--wait',
  '--randomize-hosts',
  '--retries',
  '--ttl',
  '--excludefile',
  '-c',
  '--conf',
  '--ports',
]);

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV4_CIDR = /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/;
const IPV4_RANGE = /^\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;
const IPV6_CIDR = /^[0-9a-fA-F:]+\/\d{1,3}$/;
const HOSTNAME = /^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,}\.?$/;

/** Split a command line into words, keeping quoted arguments together. */
function words(args: string): string[] {
  const out: string[] = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(args)) !== null) out.push(match[1] ?? match[2] ?? match[3] ?? '');
  return out;
}

function looksLikeTarget(token: string): boolean {
  if (!token || token.startsWith('-')) return false;
  if (IPV4.test(token) || IPV4_CIDR.test(token) || IPV4_RANGE.test(token)) return true;
  if (token.includes(':') && (IPV6.test(token) || IPV6_CIDR.test(token))) return true;
  // A comma-separated last octet: 10.0.0.1,2,3
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?:,\d{1,3})+$/.test(token)) return true;
  return HOSTNAME.test(token);
}

/**
 * The targets named on nmap's command line, in order. Flags and their values are
 * skipped, so `-oX scan.xml` does not make `scan.xml` look like a host name.
 */
export function parseTargets(args: string | undefined): string[] {
  const text = (args ?? '').replace(/\s+/g, ' ').trim();
  if (!text) return [];
  const tokens = words(text);
  // Drop the program itself: `nmap`, `/usr/bin/nmap`, `C:\…\nmap.exe`, `masscan`.
  if (tokens.length > 0 && /(?:^|[\\/])(?:nmap|masscan)(?:\.exe)?$/i.test(tokens[0])) tokens.shift();

  const targets: string[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.startsWith('-')) {
      if (VALUE_FLAGS.has(token)) index += 1;
      continue;
    }
    if (looksLikeTarget(token)) targets.push(token);
  }
  return targets;
}

/** Sort a target list into a stable, comparable shape. */
export function normalizeTargets(targets: string[]): string[] {
  return [...new Set(targets.map((target) => target.trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

/**
 * The prefix a scan's own range suggests for its section frames.
 *
 * `undefined` means "the usual /24": a host list with no target information, or a
 * target too wide to draw (a /8 scan is not one frame). Mixed ranges take the
 * narrowest prefix, so a /16 scanned next to a /24 is drawn as /24 frames.
 */
export function suggestGrouping(targets: string[]): number | undefined {
  const prefixes = targets
    .filter((target) => IPV4_CIDR.test(target))
    .map((target) => Number(target.slice(target.lastIndexOf('/') + 1)))
    .filter((prefix) => Number.isInteger(prefix) && prefix >= 16 && prefix <= 28);
  if (prefixes.length === 0) return undefined;
  return Math.max(...prefixes);
}

/** True when two target lists name different ranges – the merge preview warns then. */
export function targetsDiffer(left: string[] | undefined, right: string[] | undefined): boolean {
  if (!left || !right || left.length === 0 || right.length === 0) return false;
  const a = normalizeTargets(left);
  const b = normalizeTargets(right);
  return a.length !== b.length || a.some((target, index) => target !== b[index]);
}
