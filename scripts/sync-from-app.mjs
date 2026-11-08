#!/usr/bin/env node
/**
 * Copies the frontend of the NMAP2Flowchart app (../App by default) into this
 * repository and applies the static-edition overlays from ./overlay.
 *
 *   npm run sync             rewrite src/ and the shared public assets
 *   npm run sync:check       exit 1 when the copy would change anything
 *   npm run sync -- --app <dir>   read the sources from somewhere else
 *
 * `src/` is generated: edit the app in ../App (or ./overlay), then re-run this.
 * `public/` files listed in PUBLIC_OWNED are this repository's own and are never
 * overwritten.
 */
import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const argv = process.argv.slice(2);
const checkOnly = argv.includes('--check');
const appFlag = argv.indexOf('--app');
const APP_DIR = path.resolve(
  appFlag === -1 ? (process.env.N2F_APP_DIR ?? path.join(ROOT, '..', 'App')) : argv[appFlag + 1],
);

/** public/ files this repository writes itself; upstream copies are ignored. */
const PUBLIC_OWNED = new Set(['site.webmanifest']);

/** Text edits applied after the copy. Each pattern must match exactly once. */
const PATCHES = [
  {
    file: 'src/App.tsx',
    reason: 'the brand line is the document h1',
    from: '<strong>NMAP2Flowchart</strong>',
    to: '<h1 className="brand__title">NMAP2Flowchart</h1>',
  },
  {
    file: 'src/App.tsx',
    reason: 'the empty state is a section under that h1, not a second one',
    from:
      "<h1>{shared.enabled ? 'This shared diagram is empty' : 'Turn an nmap scan into a network map'}</h1>",
    to:
      "<h2 className=\"empty-state__title\">{shared.enabled ? 'This shared diagram is empty' : 'Turn an nmap scan into a network map'}</h2>",
  },
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

async function collect(dir, filter) {
  const out = new Map();
  for (const rel of await walk(dir)) {
    if (filter && !filter(rel)) continue;
    out.set(rel, await readFile(path.join(dir, rel)));
  }
  return out;
}

function patch(source, patch) {
  const hits = source.split(patch.from).length - 1;
  if (hits !== 1) {
    throw new Error(
      `${patch.file} should contain "${patch.from}" exactly once, found ${hits}. ` +
        `Upstream changed its markup – update PATCHES in scripts/sync-from-app.mjs.`,
    );
  }
  return source.replace(patch.from, patch.to);
}

async function main() {
  const appSrc = path.join(APP_DIR, 'src');
  const appPublic = path.join(APP_DIR, 'public');
  if (!existsSync(appSrc)) {
    throw new Error(
      `No ${path.relative(ROOT, appSrc)} to sync from. ` +
        `Check out the app next to this repository, or pass --app <dir>.`,
    );
  }

  /** repo-relative path -> Buffer/string that the repository should contain */
  const target = new Map();

  for (const [rel, content] of await collect(appSrc)) target.set(`src/${rel}`, content);
  if (existsSync(appPublic)) {
    for (const [rel, content] of await collect(appPublic, (rel) => !PUBLIC_OWNED.has(rel))) {
      target.set(`public/${rel}`, content);
    }
  }
  for (const [rel, content] of await collect(path.join(ROOT, 'overlay', 'src'))) {
    target.set(`src/${rel}`, content);
  }

  for (const patchSpec of PATCHES) {
    const content = target.get(patchSpec.file);
    if (!content) throw new Error(`${patchSpec.file} is missing from the copy.`);
    target.set(patchSpec.file, patch(content.toString('utf8'), patchSpec));
  }

  const license = path.join(APP_DIR, '..', 'LICENSE');
  if (existsSync(license)) target.set('LICENSE', await readFile(license));

  const missing = [];
  const changed = [];
  for (const [rel, content] of target) {
    const disk = path.join(ROOT, rel);
    const current = existsSync(disk) ? await readFile(disk) : null;
    if (!current) missing.push(rel);
    else if (Buffer.compare(Buffer.from(content), current) !== 0) changed.push(rel);
  }

  const stale = [];
  const localSrc = path.join(ROOT, 'src');
  if (existsSync(localSrc)) {
    for (const rel of await walk(localSrc)) {
      if (!target.has(`src/${rel}`)) stale.push(`src/${rel}`);
    }
  }

  const drift = [...missing.map((rel) => `+ ${rel}`), ...changed.map((rel) => `~ ${rel}`), ...stale.map((rel) => `- ${rel}`)];

  if (checkOnly) {
    if (drift.length === 0) {
      console.log(`src/ and public/ match ${path.relative(ROOT, APP_DIR) || '.'}`);
      return 0;
    }
    console.error(`${drift.length} file(s) differ from ${path.relative(ROOT, APP_DIR)}:`);
    for (const line of drift) console.error(`  ${line}`);
    return 1;
  }

  for (const rel of stale) await rm(path.join(ROOT, rel), { force: true });
  for (const [rel, content] of target) {
    const disk = path.join(ROOT, rel);
    if (!existsSync(path.dirname(disk))) await mkdir(path.dirname(disk), { recursive: true });
    await writeFile(disk, content);
  }

  const written = missing.length + changed.length;
  console.log(
    written === 0 && stale.length === 0
      ? `src/ and public/ already match ${path.relative(ROOT, APP_DIR) || '.'}`
      : `synced ${written} file(s) from ${path.relative(ROOT, APP_DIR) || '.'}` +
          (stale.length ? `, removed ${stale.length} stale` : ''),
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
