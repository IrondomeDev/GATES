import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

// stage reviewed sources; this does not publish a website
const root = process.cwd();
const output = process.argv[2];
assert(output, 'usage: node tools/export-public-docs.mjs <empty-output-directory>');
const destination = path.resolve(output);
assert(destination !== root, 'output must not be the repository root');
await mkdir(destination, { recursive: false });
const manifest = JSON.parse(await readFile('docs/public/gates/manifest.json', 'utf8'));
const routes = new Map(manifest.pages.map(page => [page.path, page.route]));
for (const example of manifest.examples) routes.set(example, `/docs/gates/examples/${path.basename(example)}`);
assert.equal(routes.size, manifest.pages.length + manifest.examples.length, 'duplicate source');
assert.equal(new Set(routes.values()).size, routes.size, 'duplicate destination');
const staged = [];
for (const [source, route] of routes) {
  assert(!path.isAbsolute(source) && !source.split('/').includes('..'), 'unsafe source path');
  assert(route.startsWith('/docs/gates') && !route.split('/').includes('..'), 'unsafe route');
  let content = await readFile(source, 'utf8');
  if (source.endsWith('.md')) {
    content = content.replace(/(\[[^\]]*\]\()([^\s)]+)(\))/g, (full, before, target, after) => {
      if (/^(https?:|mailto:)/.test(target) || target.startsWith('#')) return full;
      const [relative, anchor] = target.split('#');
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(source), relative));
      const mapped = routes.get(resolved);
      assert(mapped, `unlisted link in ${source}: ${target}`);
      return `${before}${mapped}${anchor ? `#${anchor}` : ''}${after}`;
    });
  }
  const relativeOutput = manifest.pages.some(page => page.path === source)
    ? `pages${route}.md`
    : `assets${route}`;
  const outputPath = path.join(destination, relativeOutput);
  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, content);
  staged.push({ source, route, file: relativeOutput });
}
await writeFile(path.join(destination, 'routes.json'), `${JSON.stringify({ publicationStatus: 'draft', files: staged }, null, 2)}\n`);
console.log(`Staged ${manifest.pages.length} pages and ${manifest.examples.length} example assets. No website was published.`);
