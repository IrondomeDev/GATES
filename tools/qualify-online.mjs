import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { Pool } from 'pg';
import { createOnlinePostgresGate } from '../dist/storage/postgres/online.js';
import { createEmailPolicy, DEFAULT_EMAIL_POLICY } from '../dist/core/policy.js';

const rawUrl = process.env.GATE_TEST_POSTGRES_URL;
if (!rawUrl) throw new Error('Explicit disposable loopback PostgreSQL URL required');
const url = new URL(rawUrl);
assert.ok(['postgres:', 'postgresql:'].includes(url.protocol) && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname));
const rows = Number(process.env.GATE_ONLINE_ROWS ?? 100001);
assert.ok(Number.isSafeInteger(rows) && rows >= 1);
const schema = `gate_online_load_${randomBytes(6).toString('hex')}`;
const admin = new Pool({ connectionString: rawUrl, max: 2, connectionTimeoutMillis: 2000 });
const pool = new Pool({ connectionString: rawUrl, options: `-c search_path=${schema}`, max: 16,
  connectionTimeoutMillis: 5000, statement_timeout: 30000, query_timeout: 35000 });
const report = { date: new Date().toISOString(), rows, syntheticOnly: true,
  scope: 'Real PostgreSQL, synthetic verified source fixture, deterministic screening. No hosted providers or IronDome calls.',
  node: process.version, operations: {}, errors: {}, phases: {}, cleanup: false, passed: false };
report.sourceSha256 = createHash('sha256').update(await readFile(new URL('../dist/storage/postgres/online.js', import.meta.url))).digest('hex');
if (globalThis.gc) globalThis.gc();
let created = false, stop = false, workers = [], sampledPeakHeap = process.memoryUsage().heapUsed;
const baseHeap = sampledPeakHeap;
const sampler = setInterval(() => { sampledPeakHeap = Math.max(sampledPeakHeap, process.memoryUsage().heapUsed); }, 100);
const allow = { async screen() { return { allowed: true, reason: 'not_listed' }; } };
const tenantId = 'large-tenant';
function subject(index) { return `fixture-${String(index).padStart(12, '0')}`; }
function email(index) { return `First.Last${index}+tag@company.test`; }
async function observe(name, work) {
  const start = performance.now();
  try { return await work(); }
  catch (error) {
    const code = typeof error?.code === 'string' && /^[a-z_]+$/.test(error.code) ? error.code : 'unexpected';
    report.errors[code] = (report.errors[code] ?? 0) + 1; throw error;
  } finally {
    const metric = report.operations[name] ??= { count: 0, totalMs: 0, maxMs: 0 };
    const elapsed = performance.now() - start;
    metric.count++; metric.totalMs += elapsed; metric.maxMs = Math.max(metric.maxMs, elapsed);
  }
}
function actor(name, work) {
  return (async () => {
    let index = 0;
    while (!stop) {
      try { await observe(name, () => work(index++)); }
      catch { stop = true; return; }
    }
  })();
}
try {
  await admin.query(`CREATE SCHEMA "${schema}"`); created = true;
  for (const migration of ['001_identity.sql', '002_lifecycle.sql', '005_tenant_policy.sql', '006_online_policy.sql']) {
    await pool.query(await readFile(`migrations/${migration}`, 'utf8'));
  }
  const environment = await pool.query("SELECT version(),current_setting('fsync') AS fsync,current_setting('synchronous_commit') AS synchronous_commit");
  report.database = environment.rows[0];
  const cutovers = [];
  const instrumented = { query: (sql, values) => pool.query(sql, values), async connect() {
    const client = await pool.connect(); let heldAt, activation = false, updated = 0;
    return { async query(sql, values) {
      const result = await client.query(sql, values);
      if ((sql.includes('pg_try_advisory_xact_lock') && result.rows[0]?.acquired === true) || sql.includes('SELECT pg_catalog.pg_advisory_xact_lock(')) heldAt = performance.now();
      if (/UPDATE .*online_tenant SET active_epoch=pending_epoch/.test(sql)) { activation = true; updated = result.rowCount ?? 0; }
      if (sql === 'COMMIT' && activation) cutovers.push({ lockedTransactionMs: performance.now() - heldAt, tenantRowsUpdated: updated });
      return result;
    }, release(error) { client.release(error); } };
  } };
  const gate = createOnlinePostgresGate(instrumented, { schema, screening: allow, statementTimeoutMs: 30000 });
  // Adopt an empty tenant first; load test then exercises the native online path.
  const adoption = await gate.migration.begin({ tenantId, targetPolicy: DEFAULT_EMAIL_POLICY });
  await gate.migration.backfill({ tenantId, epoch: adoption.pendingEpoch });
  const initial = await gate.migration.activate({ tenantId, epoch: adoption.pendingEpoch });
  const seedStart = performance.now();
  await pool.query(`INSERT INTO irondome_gate_online_owner (tenant_id,user_id,delivery_email)
    SELECT $1,'fixture-' || pg_catalog.lpad(i::pg_catalog.text,12,'0'),'First.Last' || i || '+tag@company.test'
    FROM pg_catalog.generate_series(0,$2::pg_catalog.int4 - 1) AS i`, [tenantId, rows]);
  await pool.query(`INSERT INTO irondome_gate_online_key (tenant_id,epoch,canonical_email,user_id)
    SELECT tenant_id,$2::pg_catalog.uuid,delivery_email,user_id FROM irondome_gate_online_owner WHERE tenant_id=$1`, [tenantId, initial.activeEpoch]);
  await pool.query('ANALYZE irondome_gate_online_owner');
  await pool.query('ANALYZE irondome_gate_online_key');
  report.phases.seedMs = performance.now() - seedStart;
  const target = createEmailPolicy({ 'company.test': { lowercase: true, stripPlusTag: true, stripDots: true } });
  const begun = await gate.migration.begin({ tenantId, targetPolicy: target });
  await gate.claimVerified({ tenantId: 'other-tenant', userId: 'initial', email: 'Other@company.test' });
  workers = [
    actor('targetReads', index => gate.assertActive({ tenantId, userId: subject(index % rows), email: email(index % rows) })),
    actor('targetClaims', index => gate.claimVerified({ tenantId, userId: `live-${index}`, email: `Live.Writer${index}+tag@company.test` })),
    actor('otherTenantClaims', index => gate.claimVerified({ tenantId: 'other-tenant', userId: `other-${index}`, email: `Other.Writer${index}@company.test` })),
    actor('targetChangeAndRevoke', async index => {
      const userId = `temporary-${index}`;
      await gate.claimVerified({ tenantId, userId, email: `Temporary.${index}@company.test` });
      const state = await gate.getOwnership({ tenantId, userId }); assert.equal(state.status, 'active');
      await gate.changeVerifiedEmail({ tenantId, userId, email: `Changed.${index}@company.test`, expectedRevision: state.revision });
      await gate.revokeUser({ tenantId, userId });
      assert.equal((await gate.getOwnership({ tenantId, userId })).status, 'revoked');
    }),
  ];
  const start = performance.now();
  let state = begun, batches = 0;
  while (state.phase === 'building' && !stop) {
    state = await gate.migration.backfill({ tenantId, epoch: begun.pendingEpoch, batchSize: 1000 }); batches++;
  }
  assert.equal(stop, false, 'A live operation failed during backfill');
  assert.equal(state.phase, 'ready');
  report.phases.backfillMs = performance.now() - start; report.phases.batches = batches;
  const flip = performance.now();
  const activated = await gate.migration.activate({ tenantId, epoch: begun.pendingEpoch });
  report.phases.activateMs = performance.now() - flip;
  assert.equal(activated.activePolicyVersion, target.version);
  for (let index = 0; index < 20; index++) await gate.assertActive({ tenantId, userId: subject(index % rows), email: email(index % rows) });
  stop = true; await Promise.all(workers);
  assert.deepEqual(report.errors, {});
  assert.ok(report.operations.targetReads.count > 0 && report.operations.targetClaims.count > 0 && report.operations.otherTenantClaims.count > 0);
  const coverage = await pool.query(`SELECT
    (SELECT pg_catalog.count(*)::pg_catalog.text FROM irondome_gate_online_owner WHERE tenant_id=$1) AS owners,
    (SELECT pg_catalog.count(*)::pg_catalog.text FROM irondome_gate_online_key WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid) AS active_keys,
    (SELECT pg_catalog.count(*)::pg_catalog.text FROM irondome_gate_online_gap WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid) AS gaps`,
    [tenantId, activated.activeEpoch]);
  report.coverage = coverage.rows[0];
  assert.equal(report.coverage.owners, report.coverage.active_keys); assert.equal(report.coverage.gaps, '0');
  report.cutovers = cutovers;
  assert.ok(cutovers.every(value => value.tenantRowsUpdated === 1));
  assert.equal((await gate.migration.status({ tenantId: 'other-tenant' })).activePolicyVersion, DEFAULT_EMAIL_POLICY.version);
  report.passed = true;
} catch (error) {
  report.failure = typeof error?.code === 'string' ? error.code : 'qualification_failed';
  process.exitCode = 1;
} finally {
  stop = true; await Promise.allSettled(workers); clearInterval(sampler);
  report.sampledPeakHeapGrowthBytes = sampledPeakHeap - baseHeap;
  report.memoryScope = 'Sampled process-wide heap growth, includes concurrent actors and driver allocations; not retained migration memory or RSS.';
  if (globalThis.gc) {
    globalThis.gc();
    report.postGcHeapGrowthBytes = process.memoryUsage().heapUsed - baseHeap;
  }
  await pool.end();
  if (created) {
    await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
    report.cleanup = (await admin.query('SELECT 1 FROM pg_namespace WHERE nspname=$1', [schema])).rows.length === 0;
  }
  await admin.end();
  report.passed &&= report.cleanup;
  for (const metric of Object.values(report.operations)) {
    metric.meanMs = Number((metric.totalMs / metric.count).toFixed(3));
    metric.maxMs = Number(metric.maxMs.toFixed(3)); delete metric.totalMs;
  }
  if (process.env.GATE_ONLINE_REPORT) await writeFile(process.env.GATE_ONLINE_REPORT, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
}
