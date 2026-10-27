import { constants } from 'node:fs';
import { access, readdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

// Integration prerequisites must be explicit; the ordinary test command allows skips.
const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
const gotrueBinary = process.env.GATE_TEST_GOTRUE_BIN;
if (!databaseUrl || !gotrueBinary) {
  throw new Error('Qualification requires GATE_TEST_POSTGRES_URL and GATE_TEST_GOTRUE_BIN. See CONTRIBUTING.md.');
}
let localDatabase = false;
try {
  const url = new URL(databaseUrl);
  localDatabase = ['postgres:', 'postgresql:'].includes(url.protocol) &&
    ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) && url.search === '';
} catch { /* Never include the supplied database URL in an error. */ }
if (!localDatabase) throw new Error('Qualification requires an explicit disposable loopback PostgreSQL database.');
try {
  await access(gotrueBinary, constants.X_OK);
} catch {
  throw new Error('GATE_TEST_GOTRUE_BIN must point to an executable official GoTrue binary.');
}

async function run(args, capture = false) {
  const child = spawn(process.execPath, args, { stdio: ['inherit', capture ? 'pipe' : 'inherit', 'inherit'] });
  let tail = '';
  if (capture) {
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      process.stdout.write(chunk);
      tail = (tail + chunk).slice(-8192);
    });
  }
  await new Promise((resolveExit, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (code === 0) resolveExit();
      else reject(new Error(`Qualification subprocess failed (${signal ?? code}).`));
    });
  });
  return tail;
}

await run(['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json']);
const tests = (await readdir('.build/test')).filter(name => name.endsWith('.test.js')).sort();
if (tests.length === 0) throw new Error('Qualification found no test files.');
const output = await run(['--test', '--test-reporter=tap', ...tests.map(name => resolve('.build/test', name))], true);
const count = name => Number(new RegExp(`^# ${name} (\\d+)\\r?$`, 'm').exec(output)?.[1] ?? NaN);
if (!(count('tests') > 0) || count('fail') !== 0 || count('skipped') !== 0 ||
    count('cancelled') !== 0 || count('todo') !== 0 || count('pass') !== count('tests')) {
  throw new Error('Qualification requires every test to pass with zero skips, cancellations or TODOs.');
}
process.stdout.write(`Local qualification passed: ${count('pass')} tests, zero skips. Hosted provider deployment and package checks are separate.\n`);
