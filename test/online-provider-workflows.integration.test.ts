import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import test from 'node:test';
import { betterAuth } from 'better-auth';
import { toNodeHandler } from 'better-auth/node';
import { memoryAdapter, type MemoryDB } from 'better-auth/adapters/memory';
import { createOnlinePostgresGate } from '../src/storage/postgres/online.js';
import { createPostgresBetterAuthChangeStore } from '../src/storage/postgres/better-auth.js';
import { createBetterAuthGate } from '../src/connectors/better-auth/index.js';
import { createEmailPolicy } from '../src/core/policy.js';
import type { PgPool } from '../src/storage/postgres/identity.js';

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
type PoolLike = PgPool & { end(): Promise<void> };

test('real Better Auth verification issued before online policy cutover completes afterward', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL unset; online provider workflow not verified against PostgreSQL',
  timeout: 60_000,
}, async t => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only explicitly supplied loopback PostgreSQL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  const pgModule = 'pg';
  const { Pool } = await import(pgModule) as { Pool: new (options: Record<string, unknown>) => PoolLike };
  const schema = `gate_online_ba_${process.pid}_${Date.now()}`;
  const config = { connectionString: databaseUrl, max: 12, connectionTimeoutMillis: 2_000,
    statement_timeout: 5_000, query_timeout: 6_000, lock_timeout: 3_000 };
  const admin = new Pool(config);
  let pool: PoolLike | undefined;
  let created = false;
  let server: Server | undefined;
  t.after(async () => {
    try {
      await new Promise<void>(resolve => server?.close(() => resolve()) ?? resolve());
      await pool?.end();
      if (created) await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
    } finally { await admin.end(); }
  });

  await admin.query(`CREATE SCHEMA "${schema}"`);
  created = true;
  pool = new Pool({ ...config, options: `-c search_path=${schema}` });
  for (const migration of ['001_identity.sql', '002_lifecycle.sql', '003_better_auth.sql', '005_tenant_policy.sql', '006_online_policy.sql']) {
    await pool.query(await readFile(`migrations/${migration}`, 'utf8'));
  }

  const tenantId = 'online-better-auth-proof';
  const gate = createOnlinePostgresGate(pool, { schema, screening: { async screen() { return { allowed: true, reason: 'not_listed' }; } } });
  const changeStore = createPostgresBetterAuthChangeStore(pool, { schema });
  const deliveries: Array<{ email: string; url: string; token: string }> = [];
  const integration = createBetterAuthGate({ tenantId, engine: gate, changes: changeStore,
    async sendVerificationEmail({ user, url, token }) { deliveries.push({ email: user.email, url, token }); } });

  let nodeHandler: ReturnType<typeof toNodeHandler> | undefined;
  server = createServer((request, response) => {
    if (!nodeHandler) { response.writeHead(503); response.end(); return; }
    void nodeHandler(request, response).catch(() => {
      if (!response.headersSent) { response.writeHead(500); response.end(); }
      else response.destroy();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server!.once('error', reject);
    server!.listen(0, '127.0.0.1', () => { server!.off('error', reject); resolve(); });
  });
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;

  const memory: MemoryDB = { user: [], account: [], session: [], verification: [] };
  const authOptions = {
    baseURL: `${origin}/api/auth`,
    secret: 'local-online-cutover-test-secret-not-for-production-0123456789',
    database: memoryAdapter(memory),
    ...integration.authOptions,
  };
  const auth = betterAuth(authOptions);
  const bound = integration.bind(auth);
  nodeHandler = toNodeHandler(bound.handler);

  class CookieJar {
    private readonly values = new Map<string, string>();
    update(response: Response): void {
      for (const item of response.headers.getSetCookie()) {
        const pair = item.split(';', 1)[0]!;
        const split = pair.indexOf('=');
        if (split <= 0) continue;
        const name = pair.slice(0, split), value = pair.slice(split + 1);
        if (!value || /max-age=0/i.test(item)) this.values.delete(name);
        else this.values.set(name, value);
      }
    }
    header(): string { return [...this.values].map(([name, value]) => `${name}=${value}`).join('; '); }
  }
  async function call(path: string, method = 'GET', body?: unknown, jar?: CookieJar): Promise<{ response: Response; data: any }> {
    const headers = new Headers({ origin, accept: 'application/json' });
    if (body !== undefined) headers.set('content-type', 'application/json');
    if (jar?.header()) headers.set('cookie', jar.header());
    const response = await fetch(`${origin}/api/auth${path}`, { method, headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}), redirect: 'manual' });
    jar?.update(response);
    let data: any = null;
    try { data = await response.clone().json(); } catch { /* Native proof completion redirects. */ }
    return { response, data };
  }
  async function verify(index: number, jar?: CookieJar): Promise<Response> {
    const message = deliveries[index];
    assert.ok(message);
    const url = new URL(message.url);
    return (await call(`/verify-email?${url.searchParams.toString()}`, 'GET', undefined, jar)).response;
  }
  async function dbUser(email: string): Promise<Record<string, unknown> | undefined> {
    return memory.user?.find(user => user.email === email.toLowerCase()) as Record<string, unknown> | undefined;
  }

  await t.test('captured native email-change proof remains valid across a key-only policy flip', async () => {
    const oldDelivery = 'User+Initial@company.test';
    const signup = await call('/sign-up/email', 'POST', { email: oldDelivery, password: 'local-cutover-password-123', name: 'Cutover Owner' });
    assert.equal(signup.response.status, 200, JSON.stringify(signup.data));
    assert.equal(deliveries[0]?.email, oldDelivery);
    assert.equal((await verify(0)).status, 302);
    const record = await dbUser(oldDelivery);
    assert.ok(record);
    const userId = String(record.id);

    const session = new CookieJar();
    const login = await call('/sign-in/email', 'POST', { email: oldDelivery, password: 'local-cutover-password-123' }, session);
    assert.equal(login.response.status, 200, JSON.stringify(login.data));
    assert.ok(session.header());
    const activeBefore = await gate.getOwnership({ tenantId, userId });
    assert.equal(activeBefore.status, 'active');
    if (activeBefore.status !== 'active') return;

    const nextDelivery = 'Next+Verified@company.test';
    const change = await call('/change-email', 'POST', { newEmail: nextDelivery }, session);
    assert.equal(change.response.status, 200, JSON.stringify(change.data));
    assert.equal(deliveries[1]?.email, nextDelivery);
    const intent = await pool!.query(`SELECT expected_revision::pg_catalog.text AS expected_revision, previous_delivery_email,
      next_delivery_email FROM "${schema}".irondome_gate_better_auth_change WHERE tenant_id=$1 AND user_id=$2 AND purpose='change-email'`, [tenantId, userId]);
    assert.deepEqual(intent.rows[0], { expected_revision: activeBefore.revision, previous_delivery_email: oldDelivery,
      next_delivery_email: nextDelivery });

    // The native Better Auth token and revision-bound server intent already exist before begin.
    const targetPolicy = createEmailPolicy({ 'company.test': { lowercase: true, stripPlusTag: true } });
    const begun = await gate.migration.begin({ tenantId, targetPolicy });
    assert.ok(begun.pendingEpoch);
    let status = begun;
    for (let i = 0; i < 20 && status.phase === 'building'; i++) {
      status = await gate.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 10 });
    }
    assert.equal(status.phase, 'ready');
    await gate.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
    const afterFlip = await gate.getOwnership({ tenantId, userId });
    assert.deepEqual(afterFlip.status === 'active' ? { canonical: afterFlip.canonical, revision: afterFlip.revision } : afterFlip,
      { canonical: 'user@company.test', revision: activeBefore.revision });

    // No restart, token reissue, or new intent: the provider-native verification URL
    // created before cutover completes using the unchanged expected user revision.
    const result = await verify(1);
    assert.equal(result.status, 302, result.headers.get('location') ?? 'native verification did not redirect');
    assert.equal(await dbUser(oldDelivery), undefined);
    const changedUser = await dbUser(nextDelivery);
    assert.ok(changedUser);
    assert.equal(changedUser.emailVerified, true);
    assert.equal(changedUser.gateDeliveryEmail, nextDelivery);
    const afterProof = await gate.getOwnership({ tenantId, userId });
    assert.deepEqual(afterProof.status === 'active' ? { canonical: afterProof.canonical, revision: afterProof.revision } : afterProof,
      { canonical: 'next@company.test', revision: String(BigInt(activeBefore.revision) + 1n) });
  });
});
