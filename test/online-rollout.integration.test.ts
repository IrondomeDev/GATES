import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { createGate } from '../src/core/engine.js';
import { createOnlinePostgresGate } from '../src/storage/postgres/online.js';
import { createPostgresIdentityRegistry, type PgPool } from '../src/storage/postgres/identity.js';
import { createEmailPolicy, DEFAULT_EMAIL_POLICY } from '../src/core/policy.js';

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
const wait = (ms: number) => new Promise<void>(resolveWait => setTimeout(resolveWait, ms));

test('real PostgreSQL: online bridge rolls out while verified claims continue through epoch activation', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL is unset; no real PostgreSQL verification performed',
  timeout: 90_000,
}, async (t) => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only an explicitly supplied local disposable PostgreSQL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol), 'Expected PostgreSQL URL');
  const driverName = 'pg';
  const driver = await import(driverName) as { Pool: new (options: Record<string, unknown>) => PgPool & { end(): Promise<void> } };
  const schema = `gate_online_rollout_${process.pid}_${Date.now()}`;
  const baseOptions = { connectionString: databaseUrl, connectionTimeoutMillis: 2_000, statement_timeout: 5_000,
    query_timeout: 7_000, lock_timeout: 2_000, max: 20 };
  const admin = new driver.Pool(baseOptions);
  let pool: (PgPool & { end(): Promise<void> }) | undefined;
  let created = false;
  t.after(async () => {
    await pool?.end();
    try { if (created) await admin.query(`DROP SCHEMA ${schema} CASCADE`); }
    finally { await admin.end(); }
  });
  await admin.query(`CREATE SCHEMA ${schema}`);
  created = true;
  pool = new driver.Pool({ ...baseOptions, options: `-c search_path=${schema}` });
  for (const migration of ['001_identity.sql', '002_lifecycle.sql', '005_tenant_policy.sql']) {
    await pool.query(await readFile(resolve('migrations', migration), 'utf8'));
  }

  const screening = { async screen() { return { allowed: true, reason: 'integration fixture' }; } };
  const oldRegistry = createPostgresIdentityRegistry(pool, { schema });
  const oldGate = createGate({ registry: oldRegistry, screening });
  const tenantId = 'tenant-rollout';
  const oldUsers = Array.from({ length: 32 }, (_, index) => ({ userId: `legacy-user-${String(index).padStart(3, '0')}`,
    email: `legacy${index}+source@company.test` }));
  const newUsers = Array.from({ length: 16 }, (_, index) => ({ userId: `online-user-${String(index).padStart(3, '0')}`,
    email: `online${index}+source@company.test` }));
  const providerSources = new Map<string, string>();
  for (const user of oldUsers) {
    providerSources.set(user.userId, user.email);
    await oldGate.claimVerified({ tenantId, userId: user.userId, email: user.email });
  }
  await oldGate.assertActive({ tenantId, userId: oldUsers[0]!.userId, email: oldUsers[0]!.email });

  const totals = { old: 0, online: 0 };
  const stageCounts = new Map<string, { old: number; online: number }>();
  const errors: string[] = [];
  let stage = 'pre-006';
  let stopOld = false;
  let stopOnline = false;
  function count(actor: 'old' | 'online') {
    totals[actor]++;
    const current = stageCounts.get(stage) ?? { old: 0, online: 0 };
    current[actor]++;
    stageCounts.set(stage, current);
  }
  async function actorLoop(actor: 'old' | 'online', gate: Pick<typeof oldGate, 'claimVerified' | 'assertActive'>,
    users: typeof oldUsers, shouldStop: () => boolean) {
    let cursor = 0;
    while (!shouldStop()) {
      const user = users[cursor++ % users.length]!;
      try {
        await gate.claimVerified({ tenantId, userId: user.userId, email: user.email });
        count(actor);
        await gate.assertActive({ tenantId, userId: user.userId, email: user.email });
      } catch (error) {
        errors.push(`${actor}:${stage}:${error instanceof Error ? error.name : 'error'}`);
        return;
      }
      await wait(2);
    }
  }
  const oldActors = [actorLoop('old', oldGate, oldUsers, () => stopOld), actorLoop('old', oldGate, oldUsers, () => stopOld)];
  async function waitUntil(predicate: () => boolean, label: string) {
    const deadline = Date.now() + 5_000;
    while (!predicate() && Date.now() < deadline) await wait(10);
    assert.ok(predicate(), `timed out waiting for ${label}`);
  }
  await waitUntil(() => totals.old >= 8, 'old traffic before 006');

  // Trigger installation briefly requests SHARE ROW EXCLUSIVE locks. Keep the
  // migration transaction bounded, rolling back and retrying only lock
  // contention; old verified traffic continues between attempts.
  const migrationSql = await readFile(resolve('migrations/006_online_policy.sql'), 'utf8');
  let installed = false;
  let lockRetries = 0;
  stage = 'install-006';
  for (let attempt = 0; attempt < 40 && !installed; attempt++) {
    const client = await pool.connect();
    let open = false;
    let discard: Error | undefined;
    try {
      await client.query('BEGIN'); open = true;
      await client.query("SET LOCAL lock_timeout = '50ms'");
      await client.query("SET LOCAL statement_timeout = '5s'");
      await client.query(migrationSql);
      await client.query('COMMIT'); open = false;
      installed = true;
    } catch (error) {
      if (open) { try { await client.query('ROLLBACK'); } catch (rollbackError) { discard = rollbackError instanceof Error ? rollbackError : new Error('rollback failed'); } }
      const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
      if (code !== '55P03') throw error;
      lockRetries++;
    } finally { client.release(discard); }
    if (!installed) await wait(15);
  }
  assert.equal(installed, true, '006 migration should install within the bounded retry window');
  assert.ok(totals.old > 8, 'old actor traffic must continue during DDL retries/install');
  assert.equal(errors.length, 0);

  const online = createOnlinePostgresGate(pool, { schema, screening });
  stage = 'bridge-bootstrap';
  for (const user of newUsers) providerSources.set(user.userId, user.email);
  const onlineActors = [actorLoop('online', online, newUsers, () => stopOnline), actorLoop('online', online, newUsers, () => stopOnline)];
  await waitUntil(() => totals.online >= 8 && totals.old > 8, 'old and online bridge traffic');
  assert.equal((await online.getOwnership({ tenantId, userId: newUsers[0]!.userId })).status, 'active');

  // Every server capable of legacy reads/writes is retired before the durable
  // protocol fence is enabled. New-compatible request traffic remains online.
  stage = 'retire-old';
  const oldBeforeRetire = totals.old;
  const onlineBeforeRetire = totals.online;
  await waitUntil(() => totals.old > oldBeforeRetire && totals.online > onlineBeforeRetire, 'both actors during retirement');
  stopOld = true;
  await Promise.all(oldActors);
  assert.equal(errors.length, 0);

  const targetPolicy = createEmailPolicy({ 'company.test': { lowercase: true, stripPlusTag: true } });
  stage = 'begin';
  const beforeBegin = totals.online;
  const begun = await online.migration.begin({ tenantId, targetPolicy });
  assert.ok(begun.pendingEpoch);
  await waitUntil(() => totals.online > beforeBegin, 'online traffic after begin');

  stage = 'backfill';
  const beforeBackfill = totals.online;
  const migrated = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 100,
    resolveLegacyEmail: async row => {
      const email = providerSources.get(row.userId);
      return email ? { userId: row.userId, email, emailVerified: true } : null;
    } });
  assert.equal(migrated.scanComplete, true);
  assert.equal(migrated.gaps, '0');
  await waitUntil(() => totals.online > beforeBackfill, 'online traffic during backfill');

  stage = 'activate';
  const beforeActivate = totals.online;
  const activated = await online.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
  assert.equal(activated.activePolicyVersion, targetPolicy.version);
  await waitUntil(() => totals.online > beforeActivate, 'online traffic after activation');

  stage = 'verify';
  stopOnline = true;
  await Promise.all(onlineActors);
  assert.deepEqual(errors, []);
  assert.ok(totals.old > 0 && totals.online > 0);
  assert.ok((stageCounts.get('pre-006')?.old ?? 0) > 0);
  assert.ok((stageCounts.get('install-006')?.old ?? 0) > 0);
  assert.ok((stageCounts.get('bridge-bootstrap')?.old ?? 0) > 0);
  assert.ok((stageCounts.get('bridge-bootstrap')?.online ?? 0) > 0);
  for (const phase of ['begin', 'backfill', 'activate']) assert.ok((stageCounts.get(phase)?.online ?? 0) > 0, `${phase} must overlap requests`);

  const expected = new Map([...oldUsers, ...newUsers].map(user => [user.userId, targetPolicy.prepareEmail(user.email).canonical]));
  const keyResult = await pool.query(`SELECT o.user_id,k.canonical_email FROM "${schema}".irondome_gate_online_tenant t
    JOIN "${schema}".irondome_gate_online_owner o ON o.tenant_id=t.tenant_id
    JOIN "${schema}".irondome_gate_online_key k ON k.tenant_id=o.tenant_id AND k.user_id=o.user_id AND k.epoch=t.active_epoch
    WHERE t.tenant_id=$1`, [tenantId]);
  assert.equal(keyResult.rows.length, expected.size, 'all old and online owners must have exactly one active key');
  for (const row of keyResult.rows) assert.equal(row.canonical_email, expected.get(String(row.user_id)));
  assert.equal(keyResult.rows.find(row => row.user_id === oldUsers[0]!.userId)?.canonical_email, 'legacy0@company.test',
    'target-only plus-tag canonicalization must be active');
  assert.equal(providerSources.size, oldUsers.length + newUsers.length);
  assert.ok(lockRetries < 40);
});
