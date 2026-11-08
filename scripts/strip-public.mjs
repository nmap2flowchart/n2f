#!/usr/bin/env node
/**
 * Trims the bundle that GitHub Pages serves: the public artifact should carry the
 * app, not the notes we wrote for each other.
 *
 *   npm run build              runs this right after `vite build`
 *   node scripts/strip-public.mjs            strip dist/ in place
 *   node scripts/strip-public.mjs --check    exit 1 when anything would change
 *
 * It removes HTML comments (conditional comments are kept, they are instructions to
 * a browser), comments in the emitted CSS, and the `@__PURE__` annotations the
 * bundler leaves behind in worker chunks. It also refuses to publish a source map.
 *
 * JavaScript is only touched through exact, unambiguous tokens. A regular
 * expression that removed every `/*` sequence would corrupt the SQL-injection
 * heuristics in the app – one of their descriptions is literally "SQL block
 * comment open: /* ... *\/" inside a string – so no such pass is attempted.
 *
 * The comments in `src/` and `index.html` stay: they are the documentation for
 * whoever edits the app. Only `dist/` is published.
 */
import { existsSync } from 'node:fs';
import { readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST = path.join(ROOT, 'dist');
const checkOnly = process.argv.slice(2).includes('--check');

/** Comments the bundler emits as annotations; never part of a string literal. */
const JS_ANNOTATIONS = [
  /\/\*\s*[@#]\s*__PURE__\s*\*\/[ \t]*/g,
  /\/\*\s*[@#]\s*__NO_SIDE_EFFECTS__\s*\*\/[ \t]*/g,
];

async function walk(dir, prefix = '') {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...(await walk(path.join(dir, entry.name), rel)));
    else if (entry.isFile()) files.push(rel);
  }
  return files.sort();
}

function stripHtml(source) {
  let removed = 0;
  const text = source.replace(/<!--([\s\S]*?)-->/g, (match, body) => {
    // `<!--[if IE]>` and friends are read by the browser, not by us.
    if (/^\s*\[if|\[endif\]\s*$|<!\s*\[endif/i.test(body)) return match;
    removed += 1;
    return '';
  });
  // Closing the gap a removed comment leaves behind, so the markup stays readable.
  return { text: text.replace(/\n[ \t]*\n(?:[ \t]*\n)+/g, '\n\n'), removed };
}

/** Quote-aware: a `/*` inside a string or url() is content, not a comment. */
function stripCss(source) {
  let out = '';
  let removed = 0;
  let quote = null;
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    if (quote) {
      out += ch;
      if (ch === '\\') {
        out += source[i + 1] ?? '';
        i += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      out += ch;
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      const end = source.indexOf('*/', i + 2);
      i = end === -1 ? source.length : end + 1;
      removed += 1;
      continue;
    }
    out += ch;
  }
  return { text: out, removed };
}

function stripJs(source) {
  let removed = 0;
  let text = source.replace(/^\/\*![\s\S]*?\*\/\s*/, (banner) => {
    removed += 1;
    return '';
  });
  for (const annotation of JS_ANNOTATIONS) {
    text = text.replace(annotation, () => {
      removed += 1;
      return '';
    });
  }
  const maps = text.match(/^\/\/[#@] sourceMappingURL=.*$/gm);
  if (maps) {
    removed += maps.length;
    text = text.replace(/^\/\/[#@] sourceMappingURL=.*$\n?/gm, '');
  }
  return { text, removed };
}

const STRIP = {
  '.html': stripHtml,
  '.css': stripCss,
  '.js': stripJs,
};

async function main() {
  if (!existsSync(DIST)) {
    throw new Error('No dist/ to trim – run `vite build` first.');
  }

  const files = await walk(DIST);
  const maps = files.filter((rel) => rel.endsWith('.map'));
  if (maps.length > 0) {
    throw new Error(
      `dist/ contains source maps (${maps.join(', ')}). ` +
        'Set build.sourcemap to false – the public artifact must not ship sources.',
    );
  }

  const changed = [];
  let removed = 0;

  for (const rel of files) {
    const strip = STRIP[path.extname(rel)];
    if (!strip) continue;
    const disk = path.join(DIST, rel);
    const before = await readFile(disk, 'utf8');
    const result = strip(before);
    if (result.removed === 0) continue;
    removed += result.removed;
    if (result.text !== before) changed.push({ rel, disk, text: result.text });
  }

  if (checkOnly) {
    if (changed.length === 0) {
      console.log('dist/ carries no comments');
      return 0;
    }
    console.error(`${changed.length} published file(s) still carry comments:`);
    for (const file of changed) console.error(`  ~ ${file.rel}`);
    return 1;
  }

  for (const file of changed) await writeFile(file.disk, file.text);

  let bytes = 0;
  for (const rel of files) bytes += (await stat(path.join(DIST, rel))).size;
  const size = bytes > 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.round(bytes / 1024)} kB`;
  console.log(
    changed.length === 0
      ? `dist/ was already clean – ${files.length} files, ${size}`
      : `trimmed ${removed} comment(s) from ${changed.length} file(s) – ${files.length} files, ${size}`,
  );
  return 0;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  },
);
