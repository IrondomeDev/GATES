import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { createEmailPolicy, prepareEmail } from '@irondome-dev/gate';

const root = process.cwd();
const manifest = JSON.parse(await readFile('docs/public/gates/manifest.json', 'utf8'));
const allowed = new Set([...manifest.pages.map(page => page.path), ...manifest.examples]);
assert.equal(allowed.size, manifest.pages.length + manifest.examples.length, 'duplicate manifest path');
assert.equal(new Set(manifest.pages.map(page => page.route)).size, manifest.pages.length, 'duplicate route');
for (const relative of allowed) {
  assert(!path.isAbsolute(relative) && !relative.split('/').includes('..'), `unsafe manifest path: ${relative}`);
  assert((await stat(relative)).isFile(), `missing file: ${relative}`);
  if (!relative.endsWith('.md')) continue;
  const source = await readFile(relative, 'utf8');
  assert(!source.includes('\u2014'), `em dash: ${relative}`);
  const fences = [...source.matchAll(/^```([^\n]*)$/gm)];
  assert.equal(fences.length % 2, 0, `unbalanced code fence: ${relative}`);
  fences.forEach((match, index) => {
    if (index % 2 === 0) assert(match[1].trim(), `untagged code block: ${relative}`);
    else assert.equal(match[1].trim(), '', `invalid closing fence: ${relative}`);
  });
  for (const match of source.matchAll(/\[[^\]]*\]\(([^\s)]+)\)/g)) {
    const link = match[1];
    if (/^(https?:|mailto:)/.test(link)) continue;
    const [target, anchor] = link.split('#');
    const resolved = target ? path.resolve(path.dirname(relative), target) : path.resolve(relative);
    assert(resolved.startsWith(`${root}${path.sep}`), `escaping link: ${relative}: ${link}`);
    const normalized = path.relative(root, resolved).split(path.sep).join('/');
    assert(allowed.has(normalized), `non-public link: ${relative}: ${link}`);
    assert((await stat(resolved)).isFile(), `broken link: ${relative}: ${link}`);
    if (anchor && normalized.endsWith('.md')) {
      const targetText = await readFile(resolved, 'utf8');
      const headings = [...targetText.matchAll(/^#{1,6} (.+)$/gm)].map(x => x[1].toLowerCase().replace(/[`*]/g, '').replace(/[^\p{L}\p{N}_\- ]/gu, '').replace(/ /g, '-'));
      assert(headings.includes(anchor), `missing anchor: ${relative}: ${link}`);
    }
  }
}
assert.equal(prepareEmail('alex+trial@gmail.com').canonical, 'alex@gmail.com');
const prepared = createEmailPolicy({ 'company.example': { lowercase: true, stripPlusTag: true } }).prepareEmail('Alex+trial@company.example');
assert.equal(prepared.canonical, 'alex@company.example');
assert.equal(prepared.deliveryEmail, 'Alex+trial@company.example');
console.log(`Public docs: ${manifest.pages.length} pages, ${manifest.examples.length} example files; links, fences and local policy assertions passed.`);
