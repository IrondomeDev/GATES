import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { createOnlinePostgresGate } from '../src/storage/postgres/online.js';
import { createPostgresIdentityRegistry, type PgPool } from '../src/storage/postgres/identity.js';
import { DEFAULT_EMAIL_POLICY } from '../src/core/policy.js';

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;

test('real PostgreSQL: old registry reads are fenced after online activation and revocation', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL is unset; no real PostgreSQL verification performed',
  timeout: 30_000,
}, async (t) => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only an explicitly supplied local disposable PostgreSQL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol), 'Expected PostgreSQL URL');
  const driverName = 'pg';
  const driver = await import(driverName) as { Pool: new (options: Record<string, unknown>) => PgPool & { end(): Promise<void> } };
  const schema = `gate_online_fence_${process.pid}_${Date.now()}`;
  const poolOptions = { connectionString: databaseUrl, connectionTimeoutMillis: 2_000, statement_timeout: 5_000,
    query_timeout: 6_000, lock_timeout: 3_000, max: 8 };
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
  for (const migration of ['001_identity.sql', '002_lifecycle.sql', '005_tenant_policy.sql']) {
    await pool.query(await readFile(resolve('migrations', migration), 'utf8'));
  }

  const oldRegistry = createPostgresIdentityRegistry(pool, { schema });
  const legacyBase = { tenantId: 'tenant-fence', userId: 'legacy-user', canonical: 'legacy@example.com',
    policyVersion: DEFAULT_EMAIL_POLICY.version };
  const pre006 = { ...legacyBase, tenantId: 'pre-006-tenant', userId: 'pre-006-user', canonical: 'compatible@example.com' };

  // An old schema without 006 continues to work; the cached optional probe sees
  // that the online table is absent and uses the original ownership queries.
  assert.equal(await oldRegistry.claim(pre006), 'claimed');
  assert.equal(await oldRegistry.owns(pre006), true);
  assert.deepEqual(await oldRegistry.getOwnership(pre006), { status: 'active', canonical: pre006.canonical,
    policyVersion: DEFAULT_EMAIL_POLICY.version, revision: '1' });
  await oldRegistry.revokeUser(pre006);

  await pool.query(await readFile(resolve('migrations/006_online_policy.sql'), 'utf8'));
  const legacyRegistry = createPostgresIdentityRegistry(pool, { schema });
  assert.equal(await legacyRegistry.claim(legacyBase), 'claimed');
  assert.equal(await legacyRegistry.owns(legacyBase), true);

  const online = createOnlinePostgresGate(pool, {
    schema,
    screening: { async screen() { return { allowed: true, reason: 'test' }; } },
  });
  const targetPolicy = await online.getEmailPolicy(legacyBase.tenantId);
  const begun = await online.migration.begin({ tenantId: legacyBase.tenantId, targetPolicy });
  assert.ok(begun.pendingEpoch);
  await online.migration.backfill({ tenantId: legacyBase.tenantId, epoch: begun.pendingEpoch!,
    resolveLegacyEmail: async row => ({ userId: row.userId, email: legacyBase.canonical, emailVerified: true }) });
  const active = await online.migration.activate({ tenantId: legacyBase.tenantId, epoch: begun.pendingEpoch! });
  assert.equal(active.legacyAdoption, false);

  // The legacy row deliberately remains in place after activation. The older
  // fixed-policy registry must not treat it as active under the online policy.
  assert.equal((await pool.query('SELECT 1 FROM "' + schema + '".irondome_gate_identity WHERE tenant_id=$1 AND user_id=$2',
    [legacyBase.tenantId, legacyBase.userId])).rows.length, 1);
  assert.equal(await legacyRegistry.owns(legacyBase), false);
  assert.deepEqual(await legacyRegistry.getOwnership(legacyBase), { status: 'unclaimed' });

  await online.revokeUser({ tenantId: legacyBase.tenantId, userId: legacyBase.userId });
  assert.equal(await legacyRegistry.owns(legacyBase), false);
  assert.deepEqual(await legacyRegistry.getOwnership(legacyBase), { status: 'revoked' });
});
