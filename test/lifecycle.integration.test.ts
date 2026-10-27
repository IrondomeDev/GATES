import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createPostgresIdentityRegistry, type PgPool } from '../src/storage/postgres/identity.js';
import { createLifecycleGate } from '../src/core/lifecycle.js';
import { applyBackfill } from '../src/migration/backfill.js';

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
test('real PostgreSQL: lifecycle migration, CAS, revocation fences, schema isolation and recovery', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL unset; lifecycle durability not verified', timeout: 30_000,
}, async t => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname));
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  const driverName = 'pg';
  const { Pool } = await import(driverName) as { Pool: new (options: Record<string, unknown>) => PgPool & { end(): Promise<void> } };
  const schema = `gate_lifecycle_${process.pid}_${Date.now()}`;
  const shadowSchema = `${schema}_shadow`;
  const config = { connectionString: databaseUrl, max: 16, connectionTimeoutMillis: 2000, statement_timeout: 4000, query_timeout: 5000, lock_timeout: 2000 };
  const admin = new Pool(config);
  const pool = new Pool({ ...config, options: `-c search_path=${schema}` });
  let created = false;
  t.after(async () => {
    await pool.end();
    try { if (created) { await admin.query(`DROP SCHEMA IF EXISTS ${shadowSchema} CASCADE`); await admin.query(`DROP SCHEMA ${schema} CASCADE`); } }
    finally { await admin.end(); }
  });
  await admin.query(`CREATE SCHEMA ${schema}`);
  created = true;
  await pool.query(await readFile('migrations/001_identity.sql', 'utf8'));
  await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('t','legacy','legacy@example.com','v1')");
  await pool.query(await readFile('migrations/002_lifecycle.sql', 'utf8'));
  await pool.query(await readFile('migrations/005_tenant_policy.sql', 'utf8'));
  const registry = createPostgresIdentityRegistry(pool, { schema });
  const base = { tenantId: 't', userId: 'u', canonical: 'old@example.com', policyVersion: 'v1' };
  const state = (userId: string) => registry.getOwnership({ tenantId: 't', userId });

  await t.test('upgrade retains existing owners with decimal revision 1', async () => {
    assert.deepEqual(await state('legacy'), { status: 'active', canonical: 'legacy@example.com', policyVersion: 'v1', revision: '1' });
    assert.deepEqual(await state('missing'), { status: 'unclaimed' });
  });
  await t.test('swap collision rolls back; successful swap and retry increment only once', async () => {
    await registry.claim(base);
    await registry.claim({ ...base, userId: 'occupied', canonical: 'occupied@example.com' });
    assert.equal(await registry.replaceVerified({ ...base, canonical: 'occupied@example.com', expectedRevision: '1' }), 'conflict');
    assert.equal(await registry.owns(base), true);
    assert.equal((await state('u') as { revision: string }).revision, '1');
    const change = { ...base, canonical: 'new@example.com', policyVersion: 'v1', expectedRevision: '1' };
    assert.equal(await registry.replaceVerified(change), 'replaced');
    assert.equal(await registry.owns(base), false);
    assert.equal(await registry.owns(change), true);
    assert.equal(await registry.replaceVerified(change), 'already-replaced');
    assert.equal(await registry.replaceVerified({ ...change, policyVersion: 'v3' }), 'stale');
    assert.deepEqual(await state('u'), { status: 'active', canonical: change.canonical, policyVersion: 'v1', revision: '2' });
  });
  await t.test('32 competing revisions select one winner; canonical ABA and stale retries are fenced', async () => {
    const input = { ...base, userId: 'cas', canonical: 'cas-original@example.com' };
    await registry.claim(input);
    const targets = Array.from({ length: 32 }, (_, index) => ({ ...input, canonical: `cas-${index}@example.com`, expectedRevision: '1' }));
    const outcomes = await Promise.all(targets.map(target => registry.replaceVerified(target)));
    assert.equal(outcomes.filter(x => x === 'replaced').length, 1);
    assert.equal(outcomes.filter(x => x === 'stale').length, 31);
    const winner = targets[outcomes.indexOf('replaced')]!;
    assert.equal(await registry.replaceVerified(winner), 'already-replaced');
    assert.equal(await registry.replaceVerified({ ...input, expectedRevision: '2' }), 'replaced');
    assert.equal(await registry.replaceVerified({ ...winner, canonical: 'stale@example.com' }), 'stale');
    assert.equal(await registry.replaceVerified(winner), 'stale');
    assert.equal(await registry.owns(input), true);
    // A same-canonical verified change still advances the revision to fence older work.
    assert.equal(await registry.replaceVerified({ ...input, expectedRevision: '3' }), 'replaced');
    assert.equal((await state('cas') as { revision: string }).revision, '4');
  });
  await t.test('different users racing a destination preserve every losing old identity', async () => {
    const inputs = Array.from({ length: 16 }, (_, index) => ({ ...base, userId: `dest-${index}`, canonical: `dest-old-${index}@example.com` }));
    await Promise.all(inputs.map(input => registry.claim(input)));
    const changes = inputs.map(input => ({ ...input, canonical: 'destination@example.com', expectedRevision: '1' }));
    const outcomes = await Promise.all(changes.map(input => registry.replaceVerified(input)));
    assert.equal(outcomes.filter(x => x === 'replaced').length, 1);
    assert.equal(outcomes.filter(x => x === 'conflict').length, 15);
    for (let i = 0; i < inputs.length; i++) assert.equal(await registry.owns(inputs[i]!), outcomes[i] === 'conflict');
  });
  await t.test('terminal revoke erases address, blocks stale proofs, permits a different user/tenant', async () => {
    const input = { ...base, userId: 'deleted', canonical: 'deleted@example.com' };
    await registry.claim(input);
    assert.equal(await registry.revokeUser(input), 'revoked');
    assert.equal(await registry.revokeUser(input), 'already-revoked');
    await registry.releaseUser(input);
    assert.deepEqual(await state(input.userId), { status: 'revoked' });
    assert.equal(await registry.owns(input), false);
    assert.equal(await registry.claim(input), 'revoked');
    assert.equal(await registry.claim({ ...input, canonical: 'another@example.com' }), 'revoked');
    assert.equal(await registry.replaceVerified({ ...input, expectedRevision: '1' }), 'revoked');
    assert.equal(await registry.claim({ ...input, userId: 'new-person' }), 'claimed');
    assert.equal(await registry.claim({ ...input, tenantId: 'another-tenant' }), 'claimed');
    const tombstone = await pool.query(`SELECT * FROM ${schema}.irondome_gate_revoked WHERE tenant_id=$1 AND user_id=$2`, [input.tenantId, input.userId]);
    assert.deepEqual(Object.keys(tombstone.rows[0]!).sort(), ['revoked_at', 'tenant_id', 'user_id']);
    assert.equal(await registry.revokeUser({ ...base, userId: 'never-claimed' }), 'revoked');
    assert.equal(await registry.claim({ ...base, userId: 'never-claimed' }), 'revoked');
  });
  await t.test('deletion racing claims and swaps ends revoked for every ordering', async () => {
    for (let round = 0; round < 8; round++) {
      const input = { ...base, userId: `delete-race-${round}`, canonical: `delete-race-${round}@example.com` };
      await registry.claim(input);
      await Promise.all([
        ...Array.from({ length: 8 }, () => registry.claim(input)),
        registry.replaceVerified({ ...input, canonical: `changed-race-${round}@example.com`, expectedRevision: '1' }),
        registry.revokeUser(input),
        registry.revokeUser(input),
      ]);
      assert.deepEqual(await state(input.userId), { status: 'revoked' });
      assert.equal(await registry.owns(input), false);
      assert.equal(await registry.claim(input), 'revoked');
    }
  });
  function intercepted(after: (sql: string, client: { query: PgPool['query'] }) => Promise<void>): PgPool {
    return { query: (sql, values) => pool.query(sql, values), async connect() {
      const client = await pool.connect();
      return { async query(sql, values) { const result = await client.query(sql, values); await after(sql, client); return result; }, release: error => client.release(error) };
    } };
  }
  await t.test('SQL error after swap rolls back identity and revision', async () => {
    const input = { ...base, userId: 'rollback', canonical: 'rollback-old@example.com' };
    await registry.claim(input);
    const failing = createPostgresIdentityRegistry(intercepted(async (sql, client) => { if (sql.startsWith('UPDATE ')) await client.query('SELECT 1 / 0'); }), { schema });
    await assert.rejects(failing.replaceVerified({ ...input, canonical: 'rollback-new@example.com', expectedRevision: '1' }));
    assert.equal(await registry.owns(input), true);
    assert.equal((await state(input.userId) as { revision: string }).revision, '1');
  });
  await t.test('lost COMMIT acknowledgements reconcile swaps and revocations idempotently', async () => {
    const input = { ...base, userId: 'lost-ack', canonical: 'ack-old@example.com' };
    await registry.claim(input);
    const lost = new Error('injected acknowledgment loss');
    const failing = createPostgresIdentityRegistry(intercepted(async sql => { if (sql === 'COMMIT') throw lost; }), { schema });
    const change = { ...input, canonical: 'ack-new@example.com', expectedRevision: '1' };
    await assert.rejects(failing.replaceVerified(change), error => error === lost);
    assert.equal(await registry.replaceVerified(change), 'already-replaced');
    await assert.rejects(failing.revokeUser(input), error => error === lost);
    assert.equal(await registry.revokeUser(input), 'already-revoked');
    assert.equal(await registry.claim(input), 'revoked');
  });
  await t.test('explicit schema ignores a shadow registry on the pooled search path', async () => {
    await admin.query(`CREATE SCHEMA ${shadowSchema}`);
    const hostile = new Pool({ ...config, options: `-c search_path=${shadowSchema},${schema}` });
    try {
      await hostile.query(await readFile('migrations/001_identity.sql', 'utf8'));
      await hostile.query(await readFile('migrations/002_lifecycle.sql', 'utf8'));
      await hostile.query(await readFile('migrations/005_tenant_policy.sql', 'utf8'));
      await hostile.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('t','impostor','shadow@example.com','v1')");
      const trusted = createPostgresIdentityRegistry(hostile, { schema });
      const input = { ...base, userId: 'impostor', canonical: 'shadow@example.com' };
      assert.equal(await trusted.owns(input), false);
      assert.equal(await trusted.claim(input), 'claimed');
      assert.equal(await registry.owns(input), true);
      await trusted.revokeUser(input);
      assert.equal(await trusted.owns(input), false);
      assert.equal((await hostile.query('SELECT count(*)::int AS n FROM irondome_gate_identity')).rows[0]?.n, 1);
    } finally { await hostile.end(); }
  });
  await t.test('real core screens new delivery, denies old access, and respects cancellation at committed write', async () => {
    const deliveries: string[] = [];
    const gate = createLifecycleGate({ registry, screening: { async screen(email) { deliveries.push(email); return { allowed: true, reason: 'not_listed' }; } } });
    const user = { tenantId: 'flow-tenant', userId: 'flow', email: 'Original+tag@Example.com' };
    await gate.claimVerified(user);
    const next = { ...user, email: 'Next+Tag@Example.com', expectedRevision: '1' };
    await gate.changeVerifiedEmail(next);
    await assert.rejects(gate.assertActive(user), { code: 'ownership_required' });
    await gate.assertActive(next);
    assert.deepEqual(deliveries, [user.email, next.email]);
    const blocked = createLifecycleGate({ registry, screening: { async screen() { return { allowed: false, reason: 'blocked_domain' }; } } });
    await assert.rejects(blocked.changeVerifiedEmail({ ...next, email: 'blocked@example.com', expectedRevision: '2' }), { code: 'screening_blocked' });
    await gate.assertActive(next);
    const controller = new AbortController();
    const cancelRegistry = { ...registry, async replaceVerified(input: Parameters<typeof registry.replaceVerified>[0]) { const result = await registry.replaceVerified(input); controller.abort(); return result; } };
    const cancelled = createLifecycleGate({ registry: cancelRegistry, screening: { async screen() { return { allowed: true, reason: 'not_listed' }; } } });
    const final = { ...next, email: 'final@example.com', expectedRevision: '2' };
    await assert.rejects(cancelled.changeVerifiedEmail({ ...final, signal: controller.signal }), { code: 'cancelled' });
    await gate.changeVerifiedEmail(final);
    assert.equal((await gate.getOwnership(user) as { revision: string }).revision, '3');
    await gate.revokeUser(user);
    await assert.rejects(gate.claimVerified(final), { code: 'identity_revoked' });
  });
  await t.test('supervised backfill applies and reruns real screened PostgreSQL owners', async () => {
    const gate = createLifecycleGate({ registry, screening: { async screen() { return { allowed: true, reason: 'not_listed' }; } } });
    const rows = Array.from({ length: 40 }, (_, i) => ({ tenantId: 'backfill', userId: `u${i}`, email: `backfill${i}@example.com`, emailVerified: true }));
    const first = await applyBackfill(gate, rows, { concurrency: 8, revalidate: async () => true });
    assert.equal(first.complete, true);
    assert.equal(first.completedRowIndexes.length, 40);
    const again = await applyBackfill(gate, rows, { concurrency: 8, revalidate: async () => true });
    assert.equal(again.complete, true);
    assert.equal((await pool.query(`SELECT count(*)::int AS n FROM ${schema}.irondome_gate_identity WHERE tenant_id='backfill'`)).rows[0]?.n, 40);
  });
});
