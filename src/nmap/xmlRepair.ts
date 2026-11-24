import { XMLValidator } from 'fast-xml-parser';

/**
 * Repairs for nmap XML that is *almost* XML: a truncated download, a scan cut off
 * by Ctrl-C, a banner with a bare `&`. The file is put through a ladder of cheap
 * text fixes, and the reader only falls back to reading it host by host when
 * nothing usable comes out. Half a diagram the user can check beats a refusal.
 *
 * Nothing here evaluates or expands anything: the DOCTYPE (and with it any entity
 * declaration) is gone before this runs, and every step is plain text surgery.
 */

export type XmlRepair = {
  /** The best candidate to parse: cleaned, and repaired when a step validated. */
  text: string;
  /** Repairs that were applied to produce `text`, in order. */
  repairs: string[];
  /** The validator's complaint about the file as it arrived. */
  problem?: string;
  /** Whether `text` validates. False means the ladder ran out of ideas. */
  clean: boolean;
};

const CONTROL_CHARACTERS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g;
const STRAY_AMPERSAND = /&(?!(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][\w.:-]*);)/g;

function validate(text: string): string | null {
  if (text.trim().length === 0) return 'the file is empty';
  const result = XMLValidator.validate(text);
  if (result === true) return null;
  const { err } = result;
  const where = err.line ? ` (line ${err.line}, column ${err.col})` : '';
  return `${err.msg}${where}`;
}

/** Drops bytes that are not legal XML at all – usually from a binary-truncated file. */
function stripControlCharacters(text: string): string {
  return text.replace(CONTROL_CHARACTERS, '');
}

/** `&` in a banner that nmap did not escape, which otherwise stops the parse dead. */
function escapeStrayAmpersands(text: string): string {
  return text.replace(STRAY_AMPERSAND, '&amp;');
}

type Tag = { closing: boolean; name: string; at: number; end: number; selfClosing: boolean };

/**
 * One left-to-right pass over the markup, skipping comments, CDATA and processing
 * instructions, so text inside a script's output never counts as a tag. Stops at an
 * unfinished tag (the file ends inside one) and reports where it starts.
 */
function readTags(text: string, visit: (tag: Tag) => void): { unfinished: number | null } {
  let index = 0;
  while (index < text.length) {
    const start = text.indexOf('<', index);
    if (start === -1) break;

    if (text.startsWith('<!--', start)) {
      const end = text.indexOf('-->', start + 4);
      if (end === -1) return { unfinished: start };
      index = end + 3;
      continue;
    }
    if (text.startsWith('<![CDATA[', start)) {
      const end = text.indexOf(']]>', start + 9);
      if (end === -1) return { unfinished: start };
      index = end + 3;
      continue;
    }
    if (text.startsWith('<?', start)) {
      const end = text.indexOf('?>', start + 2);
      if (end === -1) return { unfinished: start };
      index = end + 2;
      continue;
    }
    if (text.startsWith('<!', start)) {
      const end = text.indexOf('>', start + 2);
      if (end === -1) return { unfinished: start };
      index = end + 1;
      continue;
    }

    const end = text.indexOf('>', start + 1);
    if (end === -1) return { unfinished: start };

    const body = text.slice(start + 1, end).trim();
    index = end + 1;
    if (body.length === 0) continue;

    if (body.startsWith('/')) {
      visit({ closing: true, name: body.slice(1).trim(), at: start, end: end + 1, selfClosing: false });
      continue;
    }
    const selfClosing = body.endsWith('/');
    const name = /^[^\s/>]+/.exec(body)?.[0];
    if (name) visit({ closing: false, name, at: start, end: end + 1, selfClosing });
  }

  return { unfinished: null };
}

/**
 * Closes what was left open, at the point the file gave up: a mismatched `</host>`
 * gets its missing `</ports>` inserted in front of it, and a file that simply stops
 * gets its remaining closers appended. This is the repair that saves a scan killed
 * by Ctrl-C, which is complete apart from its last few lines.
 */
function closeOpenTags(text: string): string {
  const open: string[] = [];
  const insertions: { at: number; text: string }[] = [];

  const { unfinished } = readTags(text, (tag) => {
    if (tag.selfClosing) return;
    if (!tag.closing) {
      open.push(tag.name);
      return;
    }
    const position = open.lastIndexOf(tag.name);
    if (position === -1) return; // a stray closer; a later step drops it
    const missing = open
      .slice(position + 1)
      .reverse()
      .map((name) => `</${name}>`)
      .join('');
    if (missing) insertions.push({ at: tag.at, text: missing });
    open.length = position;
  });

  if (unfinished !== null || (open.length === 0 && insertions.length === 0)) return text;

  let result = text.trimEnd();
  for (const insertion of [...insertions].reverse()) {
    result = result.slice(0, insertion.at) + insertion.text + result.slice(insertion.at);
  }
  return result + [...open].reverse().map((name) => `</${name}>`).join('');
}

/** Cuts a tag the file ends in the middle of, attributes and all. */
function dropUnfinishedTag(text: string): string {
  const { unfinished } = readTags(text, () => {});
  return unfinished === null ? text : text.slice(0, unfinished);
}

/** Cuts back to the last element that was never closed, keeping everything before it. */
function dropUnclosedTail(text: string): string {
  const open: { name: string; at: number }[] = [];
  readTags(text, (tag) => {
    if (tag.selfClosing) return;
    if (!tag.closing) {
      open.push({ name: tag.name, at: tag.at });
      return;
    }
    const position = open.map((entry) => entry.name).lastIndexOf(tag.name);
    if (position !== -1) open.length = position;
  });
  const last = open[open.length - 1];
  return last ? text.slice(0, last.at) : text;
}

/** A `</foo>` with no `<foo>` is the other half of a truncated file. */
function dropStrayClosingTags(text: string): string {
  const open: string[] = [];
  const stray: { at: number; end: number }[] = [];
  readTags(text, (tag) => {
    if (tag.selfClosing) return;
    if (!tag.closing) {
      open.push(tag.name);
      return;
    }
    const position = open.lastIndexOf(tag.name);
    if (position === -1) stray.push({ at: tag.at, end: tag.end });
    else open.length = position;
  });
  if (stray.length === 0) return text;

  let result = text;
  for (const entry of [...stray].reverse()) result = result.slice(0, entry.at) + result.slice(entry.end);
  return result;
}

/**
 * The ladder: one step at a time, keeping every earlier step, stopping as soon as the
 * result validates. A file that already validates is returned untouched.
 */
export function repairXml(text: string): XmlRepair {
  const cleaned = stripControlCharacters(text);
  const repairs: string[] = cleaned === text ? [] : ['control characters removed'];

  const problem = validate(cleaned);
  if (!problem) return { text: cleaned, repairs, clean: true };

  const steps: { label: string; apply: (value: string) => string }[] = [
    { label: 'unescaped & escaped', apply: escapeStrayAmpersands },
    { label: 'unclosed tags closed', apply: closeOpenTags },
    { label: 'unfinished tag dropped', apply: dropUnfinishedTag },
    { label: 'unclosed tags closed after the cut', apply: closeOpenTags },
    { label: 'stray closing tags dropped', apply: dropStrayClosingTags },
    { label: 'unclosed element and its tail dropped', apply: dropUnclosedTail },
    { label: 'unclosed tags closed after the drop', apply: closeOpenTags },
  ];

  let current = cleaned;
  for (const step of steps) {
    const next = step.apply(current);
    if (next === current) continue;
    current = next;
    repairs.push(step.label);
    if (!validate(current)) return { text: current, repairs, problem, clean: true };
  }

  return { text: cleaned, repairs: [], problem, clean: false };
}

export type HostSalvage = {
  /** Each `<host …>…</host>` block, ready to be parsed on its own. */
  blocks: string[];
  /** Hosts that were started but never closed – a truncated tail, usually. */
  dropped: number;
  /** The `<nmaprun …>` tag's attributes, recovered with a regex. */
  header: Record<string, string>;
};

const SALVAGE_LIMIT = 20_000;

function headerAttributes(text: string): Record<string, string> {
  const start = text.search(/<nmaprun\b/);
  if (start === -1) return {};
  const end = text.indexOf('>', start);
  if (end === -1) return {};
  const attributes: Record<string, string> = {};
  const pattern = /([\w:-]+)\s*=\s*"([^"]*)"/g;
  const tag = text.slice(start, end);
  for (let match = pattern.exec(tag); match; match = pattern.exec(tag)) {
    attributes[match[1]] = match[2]
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&');
  }
  return attributes;
}

/**
 * The last resort: find `<host>` blocks in the raw text and let each one be parsed
 * alone. Nmap never nests hosts, so a depth counter is enough – and the blocks nmap
 * wrote before it died are usually complete, which is exactly the part worth keeping.
 */
export function salvageHostBlocks(text: string): HostSalvage {
  const blocks: string[] = [];
  let dropped = 0;
  let index = 0;

  while (blocks.length < SALVAGE_LIMIT) {
    const start = text.indexOf('<host', index);
    if (start === -1) break;
    const nextCharacter = text[start + 5];
    if (nextCharacter !== undefined && !/[\s/>]/.test(nextCharacter)) {
      // <hostnames>, <hostscript>, <hosthint>: not a host.
      index = start + 5;
      continue;
    }

    let depth = 0;
    let cursor = start;
    let end = -1;
    while (cursor < text.length) {
      const opening = text.indexOf('<host', cursor);
      const closing = text.indexOf('</host', cursor);
      if (closing === -1) break;
      if (opening !== -1 && opening < closing && /[\s/>]/.test(text[opening + 5] ?? ' ')) {
        const tagEnd = text.indexOf('>', opening);
        if (tagEnd === -1) break;
        if (text.slice(opening, tagEnd).trimEnd().endsWith('/')) {
          cursor = tagEnd + 1;
          continue;
        }
        depth += 1;
        cursor = tagEnd + 1;
        continue;
      }
      const tagEnd = text.indexOf('>', closing);
      if (tagEnd === -1) break;
      depth -= 1;
      cursor = tagEnd + 1;
      if (depth === 0) {
        end = cursor;
        break;
      }
    }

    if (end === -1) {
      dropped += 1;
      break;
    }
    blocks.push(text.slice(start, end));
    index = end;
  }

  return { blocks, dropped, header: headerAttributes(text) };
}
