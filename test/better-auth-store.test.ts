import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createPostgresBetterAuthChangeStore, type BetterAuthChange } from '../src/storage/postgres/better-auth.js';
import type { PgPool } from '../src/storage/postgres/identity.js';

test('Better Auth store rejects invalid schema/fingerprints/expiry before SQL', async () => {
  let queries = 0;
  const pool: PgPool = { async connect() { throw new Error('unused'); }, async query() { queries++; throw new Error('unexpected SQL'); } };
  assert.throws(() => createPostgresBetterAuthChangeStore(pool, { schema: 'x.y' }), /Invalid change store schema/);
  const store = createPostgresBetterAuthChangeStore(pool);
  const base: BetterAuthChange = { tenantId: 't', userId: 'u', tokenHash: 'a'.repeat(64), purpose: 'change-email',
    previousDeliveryEmail: 'Before+tag@example.test', nextDeliveryEmail: 'After+tag@example.test', expectedRevision: '1', expiresAt: new Date(Date.now()+60_000) };
  for (const input of [{ ...base, tokenHash: 'raw-token-secret' }, { ...base, expectedRevision: '01' },
    { ...base, expiresAt: new Date(0) }, { ...base, previousDeliveryEmail: 'invalid' }]) await assert.rejects(store.save(input));
  await assert.rejects(store.find({ tenantId: 't', tokenHash: 'raw-token-secret' }));
  assert.equal(queries, 0);
});
const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
test('real PostgreSQL Better Auth proof store: exact binding, isolation, expiry and cleanup', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL unset; proof store durability not verified', timeout: 15_000,
}, async t => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost','127.0.0.1','[::1]'].includes(url.hostname) && ['postgres:','postgresql:'].includes(url.protocol) && !url.search);
  const pgModule = 'pg';
  const { Pool } = await import(pgModule) as { Pool: new (options: Record<string, unknown>) => PgPool & { end(): Promise<void> } };
  const schema = `gate_proof_store_${process.pid}_${Date.now()}`;
  const settings = { connectionString: databaseUrl, max: 4, connectionTimeoutMillis: 2000, statement_timeout: 3000, query_timeout: 4000 };
  const admin = new Pool(settings);
  const pool = new Pool({ ...settings, options: `-c search_path=${schema}` });
  let created = false;
  t.after(async () => { await pool.end(); try { if(created) await admin.query(`DROP SCHEMA ${schema} CASCADE`); } finally { await admin.end(); } });
  await admin.query(`CREATE SCHEMA ${schema}`); created = true;
  await pool.query(await readFile('migrations/003_better_auth.sql','utf8'));
  const store = createPostgresBetterAuthChangeStore(pool,{schema});
  const tokenHash = createHash('sha256').update('synthetic-provider-proof').digest('hex');
  const base: BetterAuthChange = { tenantId:'t', userId:'auth0|stable', tokenHash, purpose:'change-email',
    previousDeliveryEmail:'Case+Before@Example.test', nextDeliveryEmail:'Case+After@Example.test', expectedRevision:'9007199254740993', expiresAt:new Date(Date.now()+60_000) };
  const save = store.save(base);
  base.expiresAt.setTime(0); // The async write must have captured Date state.
  await save;
  const found = await store.find({tenantId:'t',tokenHash});
  assert.ok(found);
  assert.equal(found.expectedRevision,'9007199254740993');
  assert.equal(found.nextDeliveryEmail,'Case+After@Example.test');
  assert.equal(found.purpose,'change-email');
  assert.equal(await store.find({tenantId:'other',tokenHash}),null);
  await assert.rejects(store.save({...base, expiresAt:new Date(Date.now()+60_000)}));
  await store.save({...base, tenantId:'other', expiresAt:new Date(Date.now()+60_000)});
  await store.deleteUser({tenantId:'t',userId:base.userId});
  assert.equal(await store.find({tenantId:'t',tokenHash}),null);
  assert.ok(await store.find({tenantId:'other',tokenHash}));
  await pool.query('UPDATE irondome_gate_better_auth_change SET expires_at=CURRENT_TIMESTAMP - interval \'1 second\'');
  assert.equal(await store.find({tenantId:'other',tokenHash}),null);
  await store.deleteExpired();
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM irondome_gate_better_auth_change')).rows[0]?.n,0);
});
