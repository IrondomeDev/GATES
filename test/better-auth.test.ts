import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { betterAuth } from 'better-auth';
import { memoryAdapter, type MemoryDB } from 'better-auth/adapters/memory';
import { createBetterAuthGate, type BetterAuthGateEngine } from '../src/connectors/better-auth/index.js';
import { createGate } from '../src/core/engine.js';
import type { IdentityRegistry } from '../src/core/registry.js';

function fixture(overrides: Partial<BetterAuthGateEngine> = {}) {
  const db: MemoryDB = { user: [], account: [], session: [], verification: [] };
  const owners = new Map<string, string>();
  const screened: string[] = [];
  const deliveries: { email: string; token: string; url: string }[] = [];
  let denyScreen = false;
  let denyStorage = false;
  let loseNextClaimAcknowledgment = false;
  const registry: IdentityRegistry = {
    async releaseUser(input) { for (const [key, value] of owners) if (key.startsWith(`${input.tenantId}\0`) && value === input.userId) owners.delete(key); },
    async claim(input) {
      if (denyStorage) throw new Error('synthetic DB outage');
      const key = `${input.tenantId}\0${input.canonical}`;
      const prior = owners.get(key);
      if (prior && prior !== input.userId) return 'conflict';
      owners.set(key, input.userId);
      if (loseNextClaimAcknowledgment) { loseNextClaimAcknowledgment = false; throw new Error("synthetic commit acknowledgement loss"); }
      return prior ? 'already-owned' : 'claimed';
    },
    async owns(input) {
      if (denyStorage) throw new Error('synthetic DB outage');
      return owners.get(`${input.tenantId}\0${input.canonical}`) === input.userId;
    },
  };
  const core = createGate({ registry, screening: { async screen(email) {
    screened.push(email);
    return { allowed: !denyScreen, reason: denyScreen ? 'synthetic-block' : 'synthetic-allow' };
  } } });
  const gate = createBetterAuthGate({
    tenantId: 'test-tenant', engine: { ...core, ...overrides },
    async sendVerificationEmail({ user, token, url }) { deliveries.push({ email: user.email, token, url }); },
  });
  const auth = betterAuth({
    baseURL: 'https://auth.example.test', secret: 'only-for-local-tests-not-a-production-secret-123456',
    database: memoryAdapter(db), ...gate.authOptions,
  });
  const bound = gate.bind(auth);
  return { db, owners, screened, deliveries, auth, gate, bound,
    blockScreen: () => { denyScreen = true; },
    failStorage: () => { denyStorage = true; },
    restoreStorage: () => { denyStorage = false; },
    loseClaimAcknowledgment: () => { loseNextClaimAcknowledgment = true; },
  };
}

test('Better Auth plugin metadata matches the package release', () => {
  const { version } = JSON.parse(readFileSync('package.json', 'utf8'));
  const plugin = fixture().gate.authOptions.plugins[0];
  assert.equal(plugin.id, 'irondome-gate');
  assert.equal(plugin.version, version);
});

async function signUp(f: ReturnType<typeof fixture>, email: string) {
  return f.auth.api.signUpEmail({ body: { email, password: 'local-test-password-123', name: 'Synthetic fixture' } });
}
async function verify(f: ReturnType<typeof fixture>, index = 0) {
  const delivery = f.deliveries[index];
  assert.ok(delivery, 'a verification email was captured');
  return f.auth.api.verifyEmail({ query: { token: delivery.token } });
}

// These tests run actual Better Auth 1.7.7 routes/hooks with its in-memory adapter.
// The registry below is a deterministic test double, NOT a PostgreSQL simulation.
test('real Better Auth: preserves delivery spelling, no pending ownership, claim before login', async () => {
  const f = fixture();
  const result = await signUp(f, 'First.Last+trial@Gmail.com');
  assert.equal(result.token, null);
  assert.equal(f.owners.size, 0);
  assert.equal(f.db.user?.[0]?.emailVerified, false);
  assert.equal(f.db.user?.[0]?.gateDeliveryEmail, 'First.Last+trial@Gmail.com');
  assert.equal('gateDeliveryEmail' in result.user, false, 'private delivery field is not returned');
  assert.deepEqual(f.screened, ['First.Last+trial@Gmail.com'], 'one IronDome call per delivery');
  assert.equal(f.deliveries[0]?.email, 'First.Last+trial@Gmail.com');
  await assert.rejects(f.auth.api.signInEmail({ body: { email: 'first.last+trial@gmail.com', password: 'local-test-password-123' } }));
  assert.equal(f.db.session?.length, 0);
  await verify(f);
  assert.equal(f.owners.size, 1);
  assert.equal(f.db.user?.[0]?.emailVerified, true);
  const session = await f.auth.api.signInEmail({ body: { email: 'first.last+trial@gmail.com', password: 'local-test-password-123' } });
  assert.ok(session.token);
  const headers = new Headers({ cookie: `better-auth.session_token=${session.token}` });
  // Bare token is intentionally not a signed cookie; the real API refuses it.
  assert.equal(await f.bound.getActiveSession(headers), null);
});

test('real Better Auth: competing canonical aliases cannot both activate or obtain sessions', async () => {
  const f = fixture();
  await signUp(f, 'same.user+one@gmail.com');
  await signUp(f, 's.a.m.e.u.s.e.r+two@googlemail.com');
  assert.equal(f.owners.size, 0);
  const results = await Promise.allSettled([verify(f, 0), verify(f, 1)]);
  assert.equal(results.filter(x => x.status === 'fulfilled').length, 1);
  assert.equal(results.filter(x => x.status === 'rejected').length, 1);
  assert.equal(f.db.user?.filter(user => user.emailVerified).length, 1);
  assert.equal(f.owners.size, 1);
  const blocked = f.db.user?.find(user => !user.emailVerified);
  assert.ok(blocked);
  await assert.rejects(f.auth.api.signInEmail({ body: { email: blocked.email, password: 'local-test-password-123' } }));
  assert.equal(f.db.session?.length, 0);
});

test('real Better Auth: blocked screening sends no verification email and never activates', async () => {
  const f = fixture(); f.blockScreen();
  const result = await signUp(f, 'blocked@example.com');
  // BA catches mail callback failures. Generic success is not active admission.
  assert.equal(result.token, null);
  assert.equal(f.deliveries.length, 0);
  assert.equal(f.owners.size, 0);
  assert.equal(f.db.user?.[0]?.emailVerified, false);
  await assert.rejects(f.auth.api.signInEmail({ body: { email: 'blocked@example.com', password: 'local-test-password-123' } }));
  assert.equal(f.db.session?.length, 0);
});

test('real Better Auth: claim storage outage fails closed before verified write; token remains retryable', async () => {
  const f = fixture();
  await signUp(f, 'outage@example.com'); f.failStorage();
  await assert.rejects(verify(f), { statusCode: 503 });
  assert.equal(f.db.user?.[0]?.emailVerified, false);
  assert.equal(f.db.session?.length, 0);
  assert.equal(f.owners.size, 0);
  f.restoreStorage();
  await verify(f);
  assert.equal(f.db.user?.[0]?.emailVerified, true);
  assert.equal(f.owners.size, 1);
});

test('real Better Auth: injected private delivery field cannot overwrite submitted address', async () => {
  const f = fixture();
  try {
    await f.auth.api.signUpEmail({ body: {
      email: 'actual@example.com', password: 'local-test-password-123', name: 'Synthetic fixture',
      gateDeliveryEmail: 'victim@gmail.com',
    } as never });
  } catch { /* Rejecting a private field is also safe. */ }
  assert.ok(!f.db.user?.length || f.db.user[0]?.gateDeliveryEmail === 'actual@example.com');
  assert.equal(f.deliveries.some(item => item.email === 'victim@gmail.com'), false);
});

test('real Better Auth: verified user with no claim cannot create a session', async () => {
  const f = fixture();
  await signUp(f, 'legacy@example.com');
  f.db.user![0]!.emailVerified = true; // synthetic legacy row; bypasses ordinary hooks on purpose
  await assert.rejects(f.auth.api.signInEmail({ body: { email: 'legacy@example.com', password: 'local-test-password-123' } }), { statusCode: 403 });
  assert.equal(f.db.session?.length, 0);
});

test('real Better Auth: email change and private-field overwrite are blocked, old claim remains', async () => {
  const f = fixture();
  await signUp(f, 'immutable@example.com'); await verify(f);
  const context = await f.auth.$context;
  const id = f.db.user![0]!.id as string;
  await assert.rejects(context.internalAdapter.updateUser(id, { email: 'other@example.com' }));
  await assert.rejects(context.internalAdapter.updateUser(id, { gateDeliveryEmail: 'other@example.com' }));
  assert.equal(f.db.user![0]!.email, 'immutable@example.com');
  assert.equal(f.owners.size, 1);
});

test('bound getActiveSession requires fresh verified state and ownership for existing signed session', async () => {
  const f = fixture();
  await signUp(f, 'active@example.com'); await verify(f);
  const response = await f.bound.handler(new Request('https://auth.example.test/api/auth/sign-in/email', {
    method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://auth.example.test' },
    body: JSON.stringify({ email: 'active@example.com', password: 'local-test-password-123' }),
  }));
  assert.equal(response.status, 200);
  const cookie = response.headers.getSetCookie().map(value => value.split(';', 1)[0]).join('; ');
  assert.ok(cookie);
  const headers = new Headers({ cookie });
  assert.ok(await f.bound.getActiveSession(headers));
  f.owners.clear();
  await assert.rejects(f.bound.getActiveSession(headers), { statusCode: 403 });
});

test('factory refuses silently overwritten safeguards and unsupported social/plugin configurations', () => {
  const f = fixture();
  assert.throws(() => f.gate.bind({ ...f.auth, options: { ...f.auth.options, plugins: [{ id: 'unsupported' }] } }));
  assert.throws(() => f.gate.bind({ ...f.auth, options: { ...f.auth.options, socialProviders: { github: { clientId: 'x', clientSecret: 'x' } } } }));
  assert.throws(() => f.gate.bind({ ...f.auth, options: { ...f.auth.options, emailAndPassword: { enabled: true, requireEmailVerification: false } } }));
});


test('real Better Auth: lost claim acknowledgement retries without duplicate ownership or premature access', async () => {
  const f = fixture();
  await signUp(f, 'retry@example.com'); f.loseClaimAcknowledgment();
  await assert.rejects(verify(f), { statusCode: 503 });
  assert.equal(f.owners.size, 1, 'claim commit happened before synthetic acknowledgement loss');
  assert.equal(f.db.user?.[0]?.emailVerified, false);
  assert.equal(f.db.session?.length, 0);
  await verify(f);
  assert.equal(f.owners.size, 1);
  assert.equal(f.db.user?.[0]?.emailVerified, true);
  await verify(f); // Native already-verified replay does not create a second identity.
  assert.equal(f.owners.size, 1);
});

test('real Better Auth: case-sensitive custom delivery remains exact throughout proof and registry lookup', async () => {
  const f = fixture();
  await signUp(f, 'Case.Sensitive+tag@Example.com');
  assert.equal(f.deliveries[0]?.email, 'Case.Sensitive+tag@Example.com');
  assert.equal(f.db.user?.[0]?.email, 'case.sensitive+tag@example.com', 'BA login namespace is case-folded');
  await verify(f);
  assert.equal(f.owners.has('test-tenant\0Case.Sensitive+tag@example.com'), true);
  assert.equal(f.owners.has('test-tenant\0case.sensitive+tag@example.com'), false);
  const signed = await f.auth.api.signInEmail({ body: { email: 'case.sensitive+tag@example.com', password: 'local-test-password-123' } });
  assert.ok(signed.token);
});

const postgresUrl = process.env.GATE_TEST_POSTGRES_URL;
test('real Better Auth + real PostgreSQL: alias race, verified/session enforcement, live revocation', {
  skip: postgresUrl ? false : 'GATE_TEST_POSTGRES_URL unset; full PostgreSQL auth integration not run',
  timeout: 30_000,
}, async (t) => {
  const url = new URL(postgresUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only explicit local disposable PostgreSQL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  const driverName = 'pg';
  const { Pool } = await import(driverName) as {
    Pool: new (options: Record<string, unknown>) => import('../src/storage/postgres/identity.js').PgPool & { end(): Promise<void> };
  };
  const { getMigrations } = await import('better-auth/db/migration');
  const { readFile } = await import('node:fs/promises');
  const { resolve } = await import('node:path');
  const { createPostgresIdentityRegistry } = await import('../src/storage/postgres/identity.js');
  const schema = `gate_ba_test_${process.pid}_${Date.now()}`;
  const opts = { connectionString: postgresUrl, max: 12, connectionTimeoutMillis: 2_000, statement_timeout: 5_000, query_timeout: 6_000, lock_timeout: 3_000 };
  const admin = new Pool(opts);
  let pool: InstanceType<typeof Pool> | undefined;
  let created = false;
  t.after(async () => {
    await pool?.end();
    try { if (created) await admin.query(`DROP SCHEMA ${schema} CASCADE`); }
    finally { await admin.end(); }
  });
  await admin.query(`CREATE SCHEMA ${schema}`); created = true;
  pool = new Pool({ ...opts, options: `-c search_path=${schema}` });
  await pool.query(await readFile(resolve('migrations/001_identity.sql'), 'utf8'));
  await pool.query(await readFile(resolve('migrations/002_lifecycle.sql'), 'utf8'));
  await pool.query(await readFile(resolve('migrations/005_tenant_policy.sql'), 'utf8'));
  const registry = createPostgresIdentityRegistry(pool, { schema });
  const deliveries: { email: string; token: string }[] = [];
  const core = createGate({ registry, screening: { async screen() { return { allowed: true, reason: 'synthetic-test' }; } } });
  const integration = createBetterAuthGate({ tenantId: 'postgres-test', engine: core,
    async sendVerificationEmail({ user, token }) { deliveries.push({ email: user.email, token }); },
  });
  const options = {
    baseURL: 'https://auth.example.test', secret: 'postgres-local-test-only-secret-not-for-production-1234',
    database: pool as unknown as NonNullable<import('better-auth').BetterAuthOptions['database']>,
    ...integration.authOptions,
  };
  const migration = await getMigrations(options);
  assert.equal(migration.unsafeChanges.length, 0);
  await migration.runMigrations();
  const auth = betterAuth(options);
  const bound = integration.bind(auth);
  const signup = (email: string) => auth.api.signUpEmail({ body: { email, password: 'local-pg-test-password-123', name: 'Synthetic local PG test' } });
  await signup('Pg.Owner+one@gmail.com');
  await signup('p.g.o.w.n.e.r+two@googlemail.com');
  assert.equal(deliveries[0]?.email, 'Pg.Owner+one@gmail.com');
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM irondome_gate_identity')).rows[0]?.n, 0);
  const results = await Promise.allSettled(deliveries.map(item => auth.api.verifyEmail({ query: { token: item.token } })));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.filter(result => result.status === 'rejected').length, 1);
  const rows = await pool.query('SELECT id, email, "emailVerified", "gateDeliveryEmail" FROM "user" ORDER BY email');
  assert.equal(rows.rows.filter(user => user.emailVerified === true).length, 1);
  const winner = rows.rows.find(user => user.emailVerified === true)!;
  const loser = rows.rows.find(user => user.emailVerified === false)!;
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM irondome_gate_identity')).rows[0]?.n, 1);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM "session"')).rows[0]?.n, 0);
  await assert.rejects(auth.api.signInEmail({ body: { email: loser.email as string, password: 'local-pg-test-password-123' } }));
  const response = await bound.handler(new Request('https://auth.example.test/api/auth/sign-in/email', {
    method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://auth.example.test' },
    body: JSON.stringify({ email: winner.email, password: 'local-pg-test-password-123' }),
  }));
  assert.equal(response.status, 200);
  const cookie = response.headers.getSetCookie().map(value => value.split(';', 1)[0]).join('; ');
  assert.ok(cookie);
  const headers = new Headers({ cookie });
  assert.ok(await bound.getActiveSession(headers));
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM "session"')).rows[0]?.n, 1);
  // Fault injection: force the legacy/loser row verified outside the adapter. Even
  // then the claim gate—not emailVerified alone—must prevent a new session.
  await pool.query('UPDATE "user" SET "emailVerified" = true WHERE id = $1', [loser.id]);
  await assert.rejects(auth.api.signInEmail({ body: { email: loser.email as string, password: 'local-pg-test-password-123' } }), { statusCode: 403 });
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM "session"')).rows[0]?.n, 1);
  // Fault injection, not an endorsed deletion workflow: lose registry ownership
  // while keeping the issued session; live access must immediately fail closed.
  await pool.query('DELETE FROM irondome_gate_identity WHERE tenant_id = $1 AND user_id = $2', ['postgres-test', winner.id]);
  await assert.rejects(bound.getActiveSession(headers), { statusCode: 403 });
});
