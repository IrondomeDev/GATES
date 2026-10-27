import { readFile, stat } from 'node:fs/promises';
import { dryRunBackfill, type BackfillRow } from './backfill.js';

try {
  const path = process.argv[2];
  if (!path || process.argv.length !== 3) throw new Error();
  if ((await stat(path)).size > 16 * 1024 * 1024) throw new Error();
  const rows: unknown = JSON.parse(await readFile(path, 'utf8'));
  if (!Array.isArray(rows) || rows.length > 100_000) throw new Error();
  const report = dryRunBackfill(rows as BackfillRow[]);
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exitCode = report.ready ? 0 : 2;
} catch {
  process.stderr.write('Backfill input invalid. Usage: npm run backfill:dry-run -- <local-json-array> (max 16 MiB / 100,000 rows).\n');
  process.exitCode = 1;
}
