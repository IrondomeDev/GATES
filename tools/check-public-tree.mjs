import assert from 'node:assert/strict';
import { lstat, readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

const result = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { encoding: 'utf8' });
if (result.error) throw result.error;
assert.equal(result.status, 0, 'run this check from a Git checkout');
const manifest = JSON.parse(await readFile('docs/public/gates/manifest.json', 'utf8'));
const allowedDocs = new Set(['docs/public/README.md', 'docs/public/gates/manifest.json', ...manifest.pages.map(page => page.path)]);
const allowedExamples = new Set(manifest.examples);
const rootFiles = new Set(['.gitignore', 'LICENSE', 'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'package.json', 'package-lock.json', 'tsconfig.json', 'tsconfig.build.json']);
const allowedTools = new Set(['build-package.mjs', 'package-smoke.mjs', 'test-qualified.mjs', 'check-public-docs.mjs', 'export-public-docs.mjs', 'check-public-tree.mjs', 'live-screening.mjs', 'qualify-online.mjs']);
const allowedAssets = new Set(['assets/brand/gates-dark.svg']);
const invalid = [];
let checked = 0;
for (const file of new Set(result.stdout.split('\0').filter(Boolean))) {
  let entry;
  try { entry = await lstat(file); }
  catch (error) { if (error.code === 'ENOENT') continue; throw error; }
  if (file === 'node_modules' && entry.isSymbolicLink()) continue;
  const allowed = rootFiles.has(file) || allowedAssets.has(file) || allowedDocs.has(file) || allowedExamples.has(file) ||
    /^(src|test)\/[^\0]+\.ts$/.test(file) || /^migrations\/\d{3}_[a-z_]+\.sql$/.test(file) ||
    (file.startsWith('tools/') && allowedTools.has(file.slice('tools/'.length))) || /^\.github\/workflows\/[a-z0-9_-]+\.ya?ml$/.test(file);
  if (!allowed || !entry.isFile()) invalid.push(file);
  checked++;
}
assert.deepEqual(invalid, [], `unexpected public repository paths: ${invalid.join(', ')}`);
console.log(`Public tree: ${checked} files match the source, test, migration, documentation and build allowlist.`);
