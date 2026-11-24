import type { DiagramNode } from '../doc/types';
import { hostMatchesRiskFilter, type RiskPolicy } from '../doc/risk';
import type { NmapHost } from '../model/types';

/**
 * The canvas filter: a small query language with an optional regular-expression
 * mode.
 *
 * Terms are ANDed. `prefix:value` narrows the field a term looks at – `ip:`,
 * `host:`, `subnet:`, `port:`, `service:` and `risk:` – and anything else is free
 * text searched across the card. With `regex` on, each **value** is a
 * case-insensitive regular expression; the prefixes keep their meaning, and `risk:`
 * stays a lookup (`any`, `high`, a level name) because it reads the risk policy
 * rather than text.
 *
 * Compilation happens once per query, and a bad pattern is reported instead of
 * thrown: the caller keeps its last good filter, so a half-typed expression never
 * blanks the canvas.
 */

export type FilterPrefix = '' | 'ip' | 'host' | 'subnet' | 'port' | 'service' | 'risk';

export type FilterTerm = {
  prefix: FilterPrefix;
  /** The part after `prefix:` – the regex or the literal text. */
  value: string;
  /** What the user typed, for error messages. */
  text: string;
  /** Compiled once; `null` for literal terms and for `risk:`. */
  pattern: RegExp | null;
};

export type CompiledFilter = {
  /** The query this was built from, trimmed and capped. */
  raw: string;
  regex: boolean;
  terms: FilterTerm[];
};

export type FilterCompile =
  | { ok: true; filter: CompiledFilter }
  | { ok: false; error: { term: string; message: string } };

export const EMPTY_FILTER: CompiledFilter = { raw: '', regex: false, terms: [] };

/** A filter this long is a mistake or a stress test, not a search. */
const MAX_QUERY = 200;
/** Terms beyond this are dropped rather than made to slow every card down. */
const MAX_TERMS = 12;

const PREFIXES = new Set<string>(['ip', 'host', 'subnet', 'port', 'service', 'risk']);

function splitTerm(text: string): { prefix: FilterPrefix; value: string } {
  const colon = text.indexOf(':');
  if (colon > 0) {
    const prefix = text.slice(0, colon).toLowerCase();
    if (PREFIXES.has(prefix)) return { prefix: prefix as FilterPrefix, value: text.slice(colon + 1) };
  }
  return { prefix: '', value: text };
}

export function compileFilter(raw: string, options: { regex?: boolean } = {}): FilterCompile {
  const regex = options.regex === true;
  const trimmed = (raw ?? '').trim().slice(0, MAX_QUERY);
  if (!trimmed) return { ok: true, filter: { raw: '', regex, terms: [] } };

  const terms: FilterTerm[] = [];
  for (const text of trimmed.split(/\s+/).filter(Boolean).slice(0, MAX_TERMS)) {
    const { prefix, value } = splitTerm(text);
    if (prefix === 'risk') {
      terms.push({ prefix, value, text, pattern: null });
      continue;
    }
    // `ip:` with nothing after it is not "every host": it is the text the user
    // typed, searched like any other free text.
    if (!value) {
      terms.push({ prefix: '', value: text, text, pattern: null });
      continue;
    }
    if (!regex) {
      terms.push({ prefix, value, text, pattern: null });
      continue;
    }
    try {
      // No `g`/`y`: `test()` must not carry state between cards.
      terms.push({ prefix, value, text, pattern: new RegExp(value, 'i') });
    } catch (error) {
      return {
        ok: false,
        error: { term: text, message: error instanceof Error ? error.message : 'invalid pattern' },
      };
    }
  }
  return { ok: true, filter: { raw: trimmed, regex, terms } };
}

export const isFilterEmpty = (filter: CompiledFilter): boolean => filter.terms.length === 0;

const nodeValues = (node: DiagramNode): string[] =>
  [node.label, node.subtitle, node.cidr, node.address, node.notes, node.host?.ip].filter(
    (value): value is string => typeof value === 'string' && value.length > 0,
  );

const hostValues = (host: NmapHost): string[] => [
  host.ip,
  host.ipv6 ?? '',
  host.mac ?? '',
  host.vendor ?? '',
  ...host.hostnames,
  ...host.os.map((match) => match.name),
  ...host.ports.map((port) => `${port.port} ${port.service ?? ''} ${port.product ?? ''}`),
];

export function matchesFilter(node: DiagramNode, filter: CompiledFilter, riskPolicy: RiskPolicy): boolean {
  if (filter.terms.length === 0) return true;

  /** Regex terms read the original text; literal terms compare lowercased. */
  const hit = (term: FilterTerm, text: string): boolean => {
    if (term.pattern) return term.pattern.test(text);
    if (!term.value) return true;
    return text.toLowerCase().includes(term.value.toLowerCase());
  };
  /** Each field is tested on its own, so `^…$` means one address, not a joined blob. */
  const hitAny = (term: FilterTerm, values: string[]): boolean => values.some((value) => hit(term, value));

  const host = node.host;
  const ports = host?.ports ?? [];

  return filter.terms.every((term) => {
    if (term.prefix === 'risk') {
      // A bare `risk:` means "any flagged host", and the lookup ignores the
      // regex toggle: it reads the policy, not the text on the card.
      return hostMatchesRiskFilter(host, riskPolicy, term.value || 'any');
    }
    if (term.prefix === 'ip' || term.prefix === 'host') {
      return hitAny(term, [host?.ip ?? '', host?.ipv6 ?? '', ...(host?.hostnames ?? [])]);
    }
    if (term.prefix === 'subnet') return hit(term, node.cidr ?? '');
    if (term.prefix === 'port') return hitAny(term, ports.map((port) => String(port.port)));
    if (term.prefix === 'service') {
      return hitAny(
        term,
        ports.flatMap((port) => [
          port.service ?? '',
          port.product ?? '',
          `${port.service ?? ''} ${port.product ?? ''}`.trim(),
        ]),
      );
    }
    if (hitAny(term, nodeValues(node))) return true;
    return host ? hitAny(term, hostValues(host)) : false;
  });
}
