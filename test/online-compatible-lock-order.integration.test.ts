import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { createPostgresIdentityRegistry, type PgPool } from '../src/storage/postgres/identity.js';
import { createOnlinePostgresStore } from '../src/storage/postgres/online-store.js';

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
const wait = (ms: number) => new Promise<void>(resolveWait => setTimeout(resolveWait, ms));

test('real PostgreSQL: compatible fixed registry takes tenant lock before user lock during queued cutover', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL is unset; no real PostgreSQL verification performed',
  timeout: 30_000,
}, async (t) => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only an explicitly supplied local disposable PostgreSQL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol), 'Expected PostgreSQL URL');
  const driverName = 'pg';
  const driver = await import(driverName) as { Pool: new (options: Record<string, unknown>) => PgPool & { end(): Promise<void> } };
  const schema = `gate_lock_order_${process.pid}_${Date.now()}`;
  const poolOptions = { connectionString: databaseUrl, connectionTimeoutMillis: 2_000,
    statement_timeout: 5_000, query_timeout: 6_000, lock_timeout: 2_000, max: 8 };
  const admin = new driver.Pool(poolOptions);
  let pool: (PgPool & { end(): Promise<void> }) | undefined;
  let created = false;
  t.after(async () => {
    await pool?.end();
    try { if (created) await admin.query(`DROP SCHEMA ${schema} CASCADE`); }
    finally { await admin.end(); }
  });
  await admin.query(`CREATE SCHEMA ${schema}`);
  created = true;
  pool = new driver.Pool({ ...poolOptions, options: `-c search_path=${schema}` });
  for (const migration of ['001_identity.sql', '002_lifecycle.sql', '005_tenant_policy.sql', '006_online_policy.sql']) {
    await pool.query(await readFile(resolve('migrations', migration), 'utf8'));
  }

  const tenantId = 'tenant-lock-order';
  const userId = 'same-user';
  await pool.query(`INSERT INTO "${schema}".irondome_gate_online_policy(policy_version,rules) VALUES ('lock-order-policy','{}'::pg_catalog.jsonb)`);
  await pool.query(`INSERT INTO "${schema}".irondome_gate_online_tenant(tenant_id,active_epoch,active_version,legacy_mode)
    VALUES ($1,'00000000-0000-4000-8000-000000000001'::pg_catalog.uuid,'lock-order-policy',true)`, [tenantId]);
  const registry = createPostgresIdentityRegistry(pool, { schema });
  const store = createOnlinePostgresStore(pool, { schema, lockTimeoutMs: 1000, exclusiveWaitMs: 2000 });
  const blocker = await pool.connect();
  let blockerOpen = false;
  const userLock = JSON.stringify(['irondome-gate', tenantId, userId]);
  const claim = { tenantId, userId, canonical: 'same-user@lock.test', policyVersion: 'lock-order-policy' };
  let claimPromise: Promise<'claimed' | 'already-owned' | 'conflict' | 'revoked' | 'policy-mismatch'> | undefined;
  let cutoverPromise: Promise<void> | undefined;
  try {
    await blocker.query('BEGIN'); blockerOpen = true;
    await blocker.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1::pg_catalog.text,0))', [userLock]);

    // This compatible fixed registry must obtain tenant-shared first, then
    // wait on the deliberately-held user lock. A queued exclusive cutover can
    // then wait for that short shared transaction without a lock-order cycle.
    claimPromise = registry.claim(claim);
    await wait(60);
    cutoverPromise = store.cutoverTenant(tenantId, async client => {
      await client.query(`UPDATE "${schema}".irondome_gate_online_tenant SET protocol_enforced=true WHERE tenant_id=$1`, [tenantId]);
    });
    await wait(60);
    await blocker.query('COMMIT'); blockerOpen = false;
    assert.equal(await claimPromise, 'claimed');
    await cutoverPromise;
  } finally {
    if (blockerOpen) { try { await blocker.query('ROLLBACK'); } catch { /* cleanup continues */ } }
    blocker.release();
  }

  assert.equal(await registry.owns(claim), true);
  const state = await pool.query(`SELECT protocol_enforced FROM "${schema}".irondome_gate_online_tenant WHERE tenant_id=$1`, [tenantId]);
  assert.equal(state.rows[0]?.protocol_enforced, true);
});
