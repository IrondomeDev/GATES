import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import test from 'node:test';
import { betterAuth } from 'better-auth';
import { getMigrations } from 'better-auth/db/migration';
import { toNodeHandler } from 'better-auth/node';
import { createGate } from '../src/core/engine.js';
import { createLifecycleGate } from '../src/core/lifecycle.js';
import { createPostgresIdentityRegistry, type PgPool } from '../src/storage/postgres/identity.js';
import { createPostgresBetterAuthChangeStore } from '../src/storage/postgres/better-auth.js';
import { createBetterAuthGate } from '../src/connectors/better-auth/index.js';
import type { BetterAuthChangeStore } from '../src/connectors/better-auth/store.js';
import { startLocalOAuthProvider, type LocalOAuthProvider } from './oauth-provider.js';

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
type PoolLike = PgPool & { end(): Promise<void> };

test('real Better Auth routes + PostgreSQL lifecycle: email change, deletion and local OIDC', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL unset; real auth workflow not run', timeout: 60_000,
}, async t => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only explicitly supplied loopback PostgreSQL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  const pgModule = 'pg';
  const { Pool } = await import(pgModule) as { Pool: new (options: Record<string, unknown>) => PoolLike };
  const schema = `gate_ba_flow_${process.pid}_${Date.now()}`;
  const options = { connectionString: databaseUrl, max: 16, connectionTimeoutMillis: 2_000,
    statement_timeout: 5_000, query_timeout: 6_000, lock_timeout: 3_000 };
  const admin = new Pool(options);
  let pool: PoolLike | undefined;
  let schemaCreated = false;
  let appServer: Server | undefined;
  let provider: LocalOAuthProvider | undefined;
  try {
    await admin.query(`CREATE SCHEMA "${schema}"`);
    schemaCreated = true;
    pool = new Pool({ ...options, options: `-c search_path=${schema}` });
    await pool.query(await (await import('node:fs/promises')).readFile('migrations/001_identity.sql', 'utf8'));
    await pool.query(await (await import('node:fs/promises')).readFile('migrations/002_lifecycle.sql', 'utf8'));
    await pool.query(await (await import('node:fs/promises')).readFile('migrations/003_better_auth.sql', 'utf8'));
    await pool.query(await (await import('node:fs/promises')).readFile('migrations/005_tenant_policy.sql', 'utf8'));
    const registry = createPostgresIdentityRegistry(pool, { schema });
    const changeStore = createPostgresBetterAuthChangeStore(pool, { schema });
    const screened: string[] = [];
    const deliveries: { email: string; url: string; token: string }[] = [];
    const gate = createLifecycleGate({ registry, screening: { async screen(email) {
      screened.push(email);
      return { allowed: true, reason: 'not_listed' };
    } } });

    provider = await startLocalOAuthProvider();
    const integration = createBetterAuthGate({
      tenantId: 'better-auth-flow-test', engine: gate, changes: changeStore,
      oauthProviders: [{ providerId: 'local-oidc', discoveryUrl: provider.discoveryUrl,
        clientId: provider.clientId, clientSecret: provider.clientSecret, scopes: ['openid', 'email', 'profile'],
        tokenEndpointAuth: { method: 'client_secret_post' } }],
      trustedOAuthProviders: ['local-oidc'], allowLocalOAuth: true,
      async sendVerificationEmail({ user, url, token }) { deliveries.push({ email: user.email, url, token }); },
    });
    let nodeHandler: ReturnType<typeof toNodeHandler> | undefined;
    appServer = createServer((request, response) => {
      if (!nodeHandler) { response.writeHead(503); response.end(); return; }
      void nodeHandler(request, response).catch(() => {
        if (!response.headersSent) { response.writeHead(500); response.end(); }
        else response.destroy();
      });
    });
    await new Promise<void>((resolve, reject) => {
      appServer!.once('error', reject);
      appServer!.listen(0, '127.0.0.1', () => { appServer!.off('error', reject); resolve(); });
    });
    const address = appServer.address();
    assert.ok(address && typeof address !== 'string');
    const origin = `http://127.0.0.1:${address.port}`;
    const authOptions = {
      baseURL: `${origin}/api/auth`,
      secret: 'local-integration-test-secret-not-for-production-0123456789',
      database: pool as unknown as NonNullable<import('better-auth').BetterAuthOptions['database']>,
      ...integration.authOptions,
    };
    const migration = await getMigrations(authOptions);
    assert.equal(migration.unsafeChanges.length, 0);
    await migration.runMigrations();
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
          const name = pair.slice(0, split);
          const value = pair.slice(split + 1);
          if (!value || /max-age=0/i.test(item)) this.values.delete(name);
          else this.values.set(name, value);
        }
      }
      header(): string { return [...this.values].map(([name, value]) => `${name}=${value}`).join('; '); }
    }
    async function call(path: string, method = 'GET', body?: unknown, cookies?: CookieJar): Promise<{ response: Response; data: any }> {
      const headers = new Headers({ origin, accept: 'application/json' });
      if (body !== undefined) headers.set('content-type', 'application/json');
      if (cookies?.header()) headers.set('cookie', cookies.header());
      const response = await fetch(`${origin}/api/auth${path}`, { method, headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}), redirect: 'manual' });
      cookies?.update(response);
      let data: any = null;
      try { data = await response.clone().json(); } catch { /* redirects intentionally have no JSON body */ }
      return { response, data };
    }
    async function signup(email: string): Promise<void> {
      const result = await call('/sign-up/email', 'POST', { email, password: 'local-auth-test-password-123', name: 'Local Workflow' });
      assert.equal(result.response.status, 200, JSON.stringify(result.data));
    }
    async function verifyDelivery(index: number, cookies?: CookieJar): Promise<Response> {
      const message = deliveries[index];
      assert.ok(message);
      const verifyUrl = new URL(message.url);
      return (await call(`/verify-email?${verifyUrl.searchParams.toString()}`, 'GET', undefined, cookies)).response;
    }
    async function signIn(email: string, jar = new CookieJar()): Promise<CookieJar> {
      const result = await call('/sign-in/email', 'POST', { email, password: 'local-auth-test-password-123' }, jar);
      assert.equal(result.response.status, 200, JSON.stringify(result.data));
      assert.ok(jar.header());
      return jar;
    }
    async function dbUser(email: string): Promise<Record<string, unknown> | undefined> {
      return (await pool!.query('SELECT id,email,"emailVerified","gateDeliveryEmail" FROM "user" WHERE email=$1', [email.toLowerCase()])).rows[0];
    }

    await t.test('email/password signup and native-shaped change proof preserve exact delivery and CAS claims', async () => {
      await signup('Old.Address+tag@Example.com');
      assert.equal(deliveries[0]?.email, 'Old.Address+tag@Example.com');
      assert.equal((await dbUser('old.address+tag@example.com'))?.gateDeliveryEmail, 'Old.Address+tag@Example.com');
      assert.equal((await pool!.query('SELECT count(*)::int AS n FROM irondome_gate_identity')).rows[0]?.n, 0);
      const tamperedUrl = new URL(deliveries[0]!.url);
      const token = tamperedUrl.searchParams.get('token')!;
      const segments = token.split('.');
      assert.equal(segments.length, 3);
      const signature = segments[2]!;
      segments[2] = `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;
      tamperedUrl.searchParams.set('token', segments.join('.'));
      const tampered = await call(`/verify-email?${tamperedUrl.searchParams.toString()}`);
      assert.equal(new URL(tampered.response.headers.get('location')!, origin).searchParams.get('error'), 'INVALID_TOKEN', 'tampered native proof redirects with an error');
      assert.equal((await dbUser('old.address+tag@example.com'))?.emailVerified, false);
      assert.deepEqual(await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: String((await dbUser('old.address+tag@example.com'))!.id) }), { status: 'unclaimed' });
      await verifyDelivery(0);
      const user = await dbUser('old.address+tag@example.com');
      assert.ok(user?.emailVerified);
      const id = String(user.id);
      const oldEmail = 'Old.Address+tag@Example.com';
      const jar = await signIn(oldEmail);
      const initialState = await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: id });
      assert.equal(initialState.status, 'active');
      const screenCountBeforeCsrf = screened.length;
      const csrf = await fetch(`${origin}/api/auth/change-email`, { method: 'POST', redirect: 'manual', headers: {
        origin: 'https://attacker.invalid', cookie: jar.header(), 'content-type': 'application/json', accept: 'application/json',
      }, body: JSON.stringify({ newEmail: 'Csrf.Target@example.com' }) });
      assert.notEqual(csrf.status, 200, 'wrong-origin change request is rejected');
      assert.equal(screened.length, screenCountBeforeCsrf, 'CSRF rejection happens before the screening call');
      const changed = await call('/change-email', 'POST', { newEmail: 'New.Case+Next@Example.com', callbackURL: `${origin}/change-done` }, jar);
      assert.equal(changed.response.status, 200, JSON.stringify(changed.data));
      assert.equal(deliveries[1]?.email, 'New.Case+Next@Example.com');
      await verifyDelivery(1);
      assert.equal(await dbUser('new.case+next@example.com').then(row => row?.gateDeliveryEmail), 'New.Case+Next@Example.com');
      assert.equal(await registry.owns({ tenantId: 'better-auth-flow-test', userId: id, canonical: 'Old.Address+tag@example.com' }), false);
      assert.equal(await registry.owns({ tenantId: 'better-auth-flow-test', userId: id, canonical: 'New.Case+Next@example.com' }), true);
      const staleSignupProof = await verifyDelivery(0, jar);
      assert.ok(staleSignupProof.status >= 400 || new URL(staleSignupProof.headers.get('location')!, origin).searchParams.has('error'), 'the old signup proof must fail or redirect with an error');
      const active = await bound.getActiveSession(new Headers({ cookie: jar.header() }));
      assert.ok(active, 'existing session remains gated against the new address');
      assert.ok(screened.includes('New.Case+Next@Example.com'));
      const nextJar = await signIn('New.Case+Next@Example.com');
      const secondChange = await call('/change-email', 'POST', { newEmail: 'Last.Change@Example.com' }, nextJar);
      assert.equal(secondChange.response.status, 200, JSON.stringify(secondChange.data));
      assert.equal(deliveries.at(-1)?.email, 'Last.Change@Example.com');
      assert.equal((await verifyDelivery(deliveries.length - 1)).status, 302);
      const secondState = await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: id });
      assert.equal(secondState.status, 'active');
      if (secondState.status === 'active') assert.equal(secondState.canonical, 'Last.Change@example.com');
      assert.equal((await dbUser('last.change@example.com'))?.gateDeliveryEmail, 'Last.Change@Example.com');
    });

    await t.test('change verification works without a browser session and competing old-revision proofs cannot both win', async () => {
      const signupDelivery = deliveries.length;
      await signup('Concurrent.Owner@example.com');
      await verifyDelivery(signupDelivery);
      const record = await dbUser('concurrent.owner@example.com');
      assert.ok(record);
      const id = String(record.id);
      const jar = await signIn('Concurrent.Owner@example.com');
      for (const target of ['Winner+Case@example.com', 'Loser+Case@example.com']) {
        const requested = await call('/change-email', 'POST', { newEmail: target }, jar);
        assert.equal(requested.response.status, 200, JSON.stringify(requested.data));
      }
      const winnerIndex = deliveries.findIndex(item => item.email === 'Winner+Case@example.com');
      const loserIndex = deliveries.findIndex(item => item.email === 'Loser+Case@example.com');
      assert.ok(winnerIndex >= 0 && loserIndex >= 0);
      const first = await verifyDelivery(winnerIndex);
      assert.equal(first.status, 302);
      // No Cookie header: Better Auth may create a callback session after it validates the proof.
      const second = await verifyDelivery(loserIndex);
      assert.notEqual(second.status, 200);
      const state = await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: id });
      assert.equal(state.status, 'active');
      if (state.status === 'active') assert.equal(state.canonical, 'Winner+Case@example.com');
      assert.equal((await dbUser('winner+case@example.com'))?.gateDeliveryEmail, 'Winner+Case@example.com');
      assert.equal(await dbUser('concurrent.owner@example.com'), undefined);
    });

    await t.test('destination canonical conflict retains old claim; terminal deletion fences stale verification', async () => {
      const ownerDelivery = deliveries.length;
      await signup('Claimed.Alias+one@gmail.com');
      await verifyDelivery(ownerDelivery);
      const deleteDelivery = deliveries.length;
      await signup('Deletion.Owner@example.com');
      await verifyDelivery(deleteDelivery);
      const owner = await dbUser('claimed.alias+one@gmail.com');
      const deleting = await dbUser('deletion.owner@example.com');
      assert.ok(owner && deleting);
      const deletionId = String(deleting.id);
      const jarOwner = await signIn('Deletion.Owner@example.com');
      const changed = await call('/change-email', 'POST', { newEmail: 'claimedalias+two@googlemail.com' }, jarOwner);
      assert.equal(changed.response.status, 200);
      assert.equal(deliveries.at(-1)?.email, 'claimedalias+two@googlemail.com');
      const conflictResult = await verifyDelivery(deliveries.length - 1);
      assert.notEqual(conflictResult.status, 200, 'the conflicting verified change must fail closed');
      const retained = await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: String(owner.id) });
      assert.equal(retained.status, 'active');
      if (retained.status === 'active') assert.equal(retained.canonical, 'claimedalias@gmail.com', 'the prior canonical claim must remain');
      const retainedRow = await dbUser('claimed.alias+one@gmail.com');
      assert.ok(retainedRow, JSON.stringify((await pool!.query('SELECT id,email,"emailVerified","gateDeliveryEmail" FROM "user"')).rows));
      assert.equal(retainedRow.gateDeliveryEmail, 'Claimed.Alias+one@gmail.com', JSON.stringify(retainedRow));

      const jarDelete = await signIn('Deletion.Owner@example.com');
      const beforeBadPassword = await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: deletionId });
      const badPassword = await call('/delete-user', 'POST', { password: 'wrong-password' }, jarDelete);
      assert.notEqual(badPassword.response.status, 200);
      assert.deepEqual(await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: deletionId }), beforeBadPassword,
        'a rejected password must not revoke the identity');
      assert.ok(await dbUser('deletion.owner@example.com'));
      const deleteResult = await call('/delete-user', 'POST', { password: 'local-auth-test-password-123' }, jarDelete);
      assert.equal(deleteResult.response.status, 200, JSON.stringify(deleteResult.data));
      assert.equal(await dbUser('deletion.owner@example.com'), undefined);
      assert.deepEqual(await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: deletionId }), { status: 'revoked' });
      await assert.rejects(gate.claimVerified({ tenantId: 'better-auth-flow-test', userId: deletionId, email: 'Deletion.Owner@example.com' }), { code: 'identity_revoked' });
      const deletionBindings = await pool!.query('SELECT user_id,purpose FROM irondome_gate_better_auth_change WHERE user_id=$1', [deletionId]);
      assert.equal(deletionBindings.rows.length, 0, JSON.stringify(deletionBindings.rows));
    });

    await t.test('a stale change proof cannot update a replacement account after the Gate CAS committed', async () => {
      const originalDelivery = deliveries.length;
      await signup('Replace.Me@example.com');
      await verifyDelivery(originalDelivery);
      const original = await dbUser('replace.me@example.com');
      assert.ok(original);
      const originalId = String(original.id);
      const jar = await signIn('Replace.Me@example.com');
      const requested = await call('/change-email', 'POST', { newEmail: 'Replace.Target@example.com' }, jar);
      assert.equal(requested.response.status, 200, JSON.stringify(requested.data));
      const staleProofIndex = deliveries.length - 1;
      const faultEngine = {
        ...gate,
        async changeVerifiedEmail(input: Parameters<typeof gate.changeVerifiedEmail>[0]) {
          const committed = await gate.changeVerifiedEmail(input);
          if (input.userId === originalId) throw new Error('injected lost acknowledgement after Gate commit');
          return committed;
        },
      };
      const faultIntegration = createBetterAuthGate({
        tenantId: 'better-auth-flow-test', engine: faultEngine, changes: changeStore,
        async sendVerificationEmail({ user, url, token }) { deliveries.push({ email: user.email, url, token }); },
      });
      const faultAuth = betterAuth({ ...authOptions, ...faultIntegration.authOptions });
      const faultBound = faultIntegration.bind(faultAuth);
      const originalHandler = nodeHandler;
      nodeHandler = toNodeHandler(faultBound.handler);
      try {
        const failedCommit = await verifyDelivery(staleProofIndex);
        assert.notEqual(failedCommit.status, 302, 'provider update must stop after the injected post-CAS failure');
      } finally { nodeHandler = originalHandler; }

      // Simulate an administrator removing the stale provider row after fencing its Gate identity.
      // Keep the unexpired proof binding to exercise the stable-user lookup guard.
      await gate.revokeUser({ tenantId: 'better-auth-flow-test', userId: originalId });
      await pool!.query('DELETE FROM "user" WHERE id=$1', [originalId]);
      const replacementDelivery = deliveries.length;
      await signup('Replace.Me@example.com');
      const replacement = await dbUser('replace.me@example.com');
      assert.ok(replacement);
      assert.notEqual(replacement.id, originalId);
      assert.equal(replacement.emailVerified, false);
      const staleCallback = await verifyDelivery(staleProofIndex);
      assert.notEqual(staleCallback.status, 302, 'the old user-bound proof must not verify the replacement account');
      const afterStale = await dbUser('replace.me@example.com');
      assert.equal(afterStale?.id, replacement.id);
      assert.equal(afterStale?.emailVerified, false);
      assert.equal(deliveries[replacementDelivery]?.email, 'Replace.Me@example.com');
    });

    await t.test('same change proof retries after a lost Gate acknowledgement without advancing revision twice', async () => {
      const delivery = deliveries.length;
      await signup('Retry.Owner@example.com');
      await verifyDelivery(delivery);
      const original = await dbUser('retry.owner@example.com');
      assert.ok(original);
      const userId = String(original.id);
      const jar = await signIn('Retry.Owner@example.com');
      const requested = await call('/change-email', 'POST', { newEmail: 'Retry.Target@example.com' }, jar);
      assert.equal(requested.response.status, 200);
      const proofIndex = deliveries.length - 1;
      let loseFirstAcknowledgement = true;
      const retryEngine = {
        ...gate,
        async changeVerifiedEmail(input: Parameters<typeof gate.changeVerifiedEmail>[0]) {
          const result = await gate.changeVerifiedEmail(input);
          if (input.userId === userId && loseFirstAcknowledgement) {
            loseFirstAcknowledgement = false;
            throw new Error('injected lost acknowledgement after Gate commit');
          }
          return result;
        },
      };
      const retryIntegration = createBetterAuthGate({ tenantId: 'better-auth-flow-test', engine: retryEngine, changes: changeStore,
        async sendVerificationEmail({ user, url, token }) { deliveries.push({ email: user.email, url, token }); } });
      const retryAuth = betterAuth({ ...authOptions, ...retryIntegration.authOptions });
      const retryBound = retryIntegration.bind(retryAuth);
      const originalHandler = nodeHandler;
      nodeHandler = toNodeHandler(retryBound.handler);
      try {
        const firstAttempt = await verifyDelivery(proofIndex, jar);
        assert.notEqual(firstAttempt.status, 302);
        assert.equal((await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId })).status, 'active');
        const retry = await verifyDelivery(proofIndex, jar);
        assert.equal(retry.status, 302);
      } finally { nodeHandler = originalHandler; }
      const state = await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId });
      assert.equal(state.status, 'active');
      if (state.status === 'active') {
        assert.equal(state.canonical, 'Retry.Target@example.com');
        assert.equal(state.revision, '2', 'idempotent retry must not advance the first committed revision');
      }
      assert.equal((await dbUser('retry.target@example.com'))?.gateDeliveryEmail, 'Retry.Target@example.com');
    });

    await t.test('an account recreated during verification cannot receive the original user update', async () => {
      const delivery = deliveries.length;
      await signup('InRequest.Race@example.com');
      await verifyDelivery(delivery);
      const original = await dbUser('inrequest.race@example.com');
      assert.ok(original);
      const originalId = String(original.id);
      const jar = await signIn('InRequest.Race@example.com');
      const requested = await call('/change-email', 'POST', { newEmail: 'InRequest.Target@example.com' }, jar);
      assert.equal(requested.response.status, 200);
      const proofIndex = deliveries.length - 1;
      let replacementId: string | undefined;
      const raceEngine = {
        ...gate,
        async changeVerifiedEmail(input: Parameters<typeof gate.changeVerifiedEmail>[0]) {
          const result = await gate.changeVerifiedEmail(input);
          if (input.userId === originalId) {
            await gate.revokeUser({ tenantId: 'better-auth-flow-test', userId: originalId });
            await pool!.query('DELETE FROM "user" WHERE id=$1', [originalId]);
            await signup('InRequest.Race@example.com');
            const replacement = await dbUser('inrequest.race@example.com');
            assert.ok(replacement);
            replacementId = String(replacement.id);
          }
          return result;
        },
      };
      const raceIntegration = createBetterAuthGate({ tenantId: 'better-auth-flow-test', engine: raceEngine, changes: changeStore,
        async sendVerificationEmail({ user, url, token }) { deliveries.push({ email: user.email, url, token }); } });
      const raceAuth = betterAuth({ ...authOptions, ...raceIntegration.authOptions });
      const raceBound = raceIntegration.bind(raceAuth);
      const originalHandler = nodeHandler;
      nodeHandler = toNodeHandler(raceBound.handler);
      let result: Response;
      try { result = await verifyDelivery(proofIndex, jar); }
      finally { nodeHandler = originalHandler; }
      assert.notEqual(result!.status, 302, 'the old callback must fail after its user row was replaced mid-request');
      assert.ok(replacementId && replacementId !== originalId);
      const replacement = await dbUser('inrequest.race@example.com');
      assert.equal(replacement?.id, replacementId);
      assert.equal(replacement?.email, 'inrequest.race@example.com');
      assert.equal(replacement?.emailVerified, false);
      assert.equal(replacement?.gateDeliveryEmail, 'InRequest.Race@example.com');
      assert.deepEqual(await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: replacementId! }), { status: 'unclaimed' });
    });

    await t.test('expired signed signup proof cannot verify or claim an identity, including on replay', async () => {
      const expiryIntegration = createBetterAuthGate({ tenantId: 'better-auth-flow-test', engine: gate, changes: changeStore,
        verificationExpiresIn: 1,
        async sendVerificationEmail({ user, url, token }) { deliveries.push({ email: user.email, url, token }); } });
      const expiryAuth = betterAuth({ ...authOptions, ...expiryIntegration.authOptions });
      const expiryBound = expiryIntegration.bind(expiryAuth);
      const originalHandler = nodeHandler;
      nodeHandler = toNodeHandler(expiryBound.handler);
      const delivery = deliveries.length;
      try {
        await signup('Expired.Proof@example.com');
        const row = await dbUser('expired.proof@example.com');
        assert.ok(row);
        await new Promise(resolve => setTimeout(resolve, 1_200));
        const expired = await verifyDelivery(delivery);
        assert.ok(expired.status >= 400 || new URL(expired.headers.get('location')!, origin).searchParams.has('error'), 'expired native proof must fail or redirect with an error');
        assert.equal((await dbUser('expired.proof@example.com'))?.emailVerified, false);
        assert.deepEqual(await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId: String(row.id) }), { status: 'unclaimed' });
        const replay = await verifyDelivery(delivery);
        assert.ok(replay.status >= 400 || new URL(replay.headers.get('location')!, origin).searchParams.has('error'), 'expired proof replay must fail or redirect with an error');
      } finally { nodeHandler = originalHandler; }
    });

    await t.test('change-store save/find outages return retryable errors and the same proof recovers', async () => {
      const signupDelivery = deliveries.length;
      await signup('Storage.Owner@example.com');
      await verifyDelivery(signupDelivery);
      const jar = await signIn('Storage.Owner@example.com');
      let failSave = true;
      let failFind = false;
      const unstableStore: BetterAuthChangeStore = {
        async save(input) {
          if (input.purpose === 'change-email' && failSave) { failSave = false; throw new Error('injected change-store save outage'); }
          return changeStore.save(input);
        },
        async find(input) {
          if (failFind) { failFind = false; throw new Error('injected change-store find outage'); }
          return changeStore.find(input);
        },
        deleteUser: input => changeStore.deleteUser(input),
        deleteExpired: () => changeStore.deleteExpired(),
      };
      const storageIntegration = createBetterAuthGate({ tenantId: 'better-auth-flow-test', engine: gate, changes: unstableStore,
        async sendVerificationEmail({ user, url, token }) { deliveries.push({ email: user.email, url, token }); } });
      const storageAuth = betterAuth({ ...authOptions, ...storageIntegration.authOptions });
      const storageBound = storageIntegration.bind(storageAuth);
      const originalHandler = nodeHandler;
      nodeHandler = toNodeHandler(storageBound.handler);
      try {
        const beforeFailedSave = deliveries.length;
        const failedSave = await call('/change-email', 'POST', { newEmail: 'Storage.Target@example.com' }, jar);
        assert.equal(failedSave.response.status, 503, JSON.stringify(failedSave.data));
        assert.equal(deliveries.length, beforeFailedSave, 'no email is sent without a durable proof binding');
        const requested = await call('/change-email', 'POST', { newEmail: 'Storage.Target@example.com' }, jar);
        assert.equal(requested.response.status, 200, JSON.stringify(requested.data));
        const proof = deliveries.length - 1;
        failFind = true;
        const failedFind = await verifyDelivery(proof, jar);
        assert.equal(failedFind.status, 503, 'change proof lookup outage is retryable');
        assert.equal((await dbUser('storage.owner@example.com'))?.emailVerified, true);
        const recovered = await verifyDelivery(proof, jar);
        assert.equal(recovered.status, 302, 'the same durable proof succeeds once storage recovers');
        assert.equal((await dbUser('storage.target@example.com'))?.gateDeliveryEmail, 'Storage.Target@example.com');
      } finally { nodeHandler = originalHandler; }
    });

    await t.test('terminal deletion can resume after provider sessions/accounts were removed but user deletion failed', async () => {
      const delivery = deliveries.length;
      await signup('Cleanup.Recovery@example.com');
      await verifyDelivery(delivery);
      const row = await dbUser('cleanup.recovery@example.com');
      assert.ok(row);
      const userId = String(row.id);
      const jar = await signIn('Cleanup.Recovery@example.com');
      await assert.rejects(bound.resumeDeletion({ userId }), { statusCode: 403 });
      await pool!.query("CREATE FUNCTION block_gate_user_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected provider deletion failure'; END; $$");
      await pool!.query('CREATE TRIGGER block_gate_user_delete BEFORE DELETE ON "user" FOR EACH ROW EXECUTE FUNCTION block_gate_user_delete()');
      const rawLogs: unknown[][] = [];
      const previousConsoleError = console.error;
      console.error = (...args: unknown[]) => { rawLogs.push(args); };
      try {
        const failed = await call('/delete-user', 'POST', { password: 'local-auth-test-password-123' }, jar);
        assert.equal(failed.response.status, 503);
        assert.doesNotMatch(JSON.stringify(failed.data), /injected|provider deletion|PL\/pgSQL/);
        assert.equal(rawLogs.length, 0, 'raw driver errors must not reach Better Call console fallback');
        assert.ok(await dbUser('cleanup.recovery@example.com'));
        assert.deepEqual(await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId }), { status: 'revoked' });
        assert.equal((await pool!.query('SELECT count(*)::int AS n FROM "session" WHERE "userId"=$1', [userId])).rows[0]?.n, 0);
        assert.equal((await pool!.query('SELECT count(*)::int AS n FROM account WHERE "userId"=$1', [userId])).rows[0]?.n, 0);
        assert.equal(await bound.getActiveSession(new Headers({ cookie: jar.header() })), null);
      } finally {
        console.error = previousConsoleError;
        await pool!.query('DROP TRIGGER block_gate_user_delete ON "user"');
        await pool!.query('DROP FUNCTION block_gate_user_delete()');
      }
      await bound.resumeDeletion({ userId });
      await bound.resumeDeletion({ userId });
      assert.equal(await dbUser('cleanup.recovery@example.com'), undefined);
      assert.deepEqual(await registry.getOwnership({ tenantId: 'better-auth-flow-test', userId }), { status: 'revoked' });
    });

    async function oauth(profile: Parameters<LocalOAuthProvider['setProfile']>[0], tamper?: 'state') {
      provider!.setProfile(profile);
      const jar = new CookieJar();
      const started = await call('/sign-in/social', 'POST', { provider: 'local-oidc', callbackURL: `${origin}/oauth-done`, disableRedirect: true }, jar);
      assert.equal(started.response.status, 200, JSON.stringify(started.data));
      assert.equal(typeof started.data.url, 'string');
      const authorized = await provider!.authorize(started.data.url as string);
      const callback = new URL(authorized.callbackURL);
      if (tamper === 'state') callback.searchParams.set('state', 'tampered-state');
      const response = await fetch(callback, { redirect: 'manual', headers: jar.header() ? { cookie: jar.header() } : {} });
      jar.update(response);
      return { response, jar };
    }

    await t.test('local OIDC accepts verified profile and denies unverified, bad signature/nonce/issuer, bad state, alias collision and implicit linking', async () => {
      const valid = await oauth({ sub: 'oidc-primary', email: 'OAuth.User+one@gmail.com', email_verified: true, name: 'OIDC Primary' });
      assert.equal(valid.response.status, 302);
      assert.ok(valid.jar.header());
      const oidcUser = await dbUser('oauth.user+one@gmail.com');
      assert.ok(oidcUser?.emailVerified);
      assert.equal(oidcUser?.gateDeliveryEmail, 'OAuth.User+one@gmail.com');
      assert.equal((await bound.getActiveSession(new Headers({ cookie: valid.jar.header() }))) !== null, true);

      const before = (await pool!.query('SELECT count(*)::int AS n FROM "user"')).rows[0]?.n;
      const sessionCount = async () => (await pool!.query('SELECT count(*)::int AS n FROM "session"')).rows[0]?.n;
      let sessionsBefore = await sessionCount();
      const changedEmail = await oauth({ sub: 'oidc-primary', email: 'Changed.Profile@example.test', email_verified: true });
      assert.equal(await sessionCount(), sessionsBefore, 'a returning subject with a changed email cannot receive a session');
      assert.equal(await dbUser('changed.profile@example.test'), undefined);
      assert.equal((await dbUser('oauth.user+one@gmail.com'))?.gateDeliveryEmail, 'OAuth.User+one@gmail.com');
      const unverifiedExisting = await oauth({ sub: 'oidc-primary', email: 'OAuth.User+one@gmail.com', email_verified: false });
      assert.equal(await sessionCount(), sessionsBefore, 'a returning subject with a now-unverified email cannot receive a session');
      assert.equal((await dbUser('oauth.user+one@gmail.com'))?.emailVerified, true);
      const restored = await oauth({ sub: 'oidc-primary', email: 'OAuth.User+one@gmail.com', email_verified: true });
      assert.equal(restored.response.status, 302, 'the trusted profile can retry after restoring its verified address');
      assert.equal(await sessionCount(), Number(sessionsBefore) + 1);
      sessionsBefore = await sessionCount();
      const unverified = await oauth({ sub: 'oidc-unverified', email: 'unverified@example.test', email_verified: false });
      assert.equal(await sessionCount(), sessionsBefore);
      assert.equal((await pool!.query('SELECT count(*)::int AS n FROM "user"')).rows[0]?.n, before);

      for (const [fault, email] of [
        ['bad-signature', 'bad-signature@example.test'],
        ['wrong-nonce', 'wrong-nonce@example.test'],
        ['wrong-issuer', 'wrong-issuer@example.test'],
        ['wrong-audience', 'wrong-audience@example.test'],
        ['expired', 'expired-oidc@example.test'],
      ] as const) {
        const failure = await oauth({ sub: `oidc-${fault}`, email, email_verified: true, idTokenFault: fault });
        assert.equal(await sessionCount(), sessionsBefore);
        assert.equal(await dbUser(email), undefined);
      }
      const badState = await oauth({ sub: 'oidc-bad-state', email: 'bad-state@example.test', email_verified: true }, 'state');
      assert.equal(await sessionCount(), sessionsBefore);
      assert.equal(await dbUser('bad-state@example.test'), undefined);

      const alias = await oauth({ sub: 'oidc-alias-loser', email: 'oa.uthuser+two@googlemail.com', email_verified: true });
      assert.equal(await sessionCount(), sessionsBefore, 'the rejected alias gets no additional session');
      const aliasUser = await dbUser('oa.uthuser+two@googlemail.com');
      assert.ok(aliasUser, 'provider row may exist after Gate rejects session creation');
      assert.equal((await bound.getActiveSession(new Headers({ cookie: valid.jar.header() }))) !== null, true);
      assert.equal(await registry.owns({ tenantId: 'better-auth-flow-test', userId: String(oidcUser!.id), canonical: 'oauthuser@gmail.com' }), true);
      assert.equal(await registry.owns({ tenantId: 'better-auth-flow-test', userId: String(aliasUser.id), canonical: 'oauthuser@gmail.com' }), false);
      const aliasRetry = await oauth({ sub: 'oidc-alias-loser', email: 'oa.uthuser+two@googlemail.com', email_verified: true });
      assert.equal(await sessionCount(), sessionsBefore, 'retrying an already-created alias-collision account still gives no session');
      assert.equal(aliasRetry.jar.header(), '');
      assert.equal((await bound.getActiveSession(new Headers({ cookie: valid.jar.header() }))) !== null, true);

      // A new OAuth identity with an email matching a password account cannot be implicitly linked.
      const explicitDelivery = deliveries.length;
      await signup('Explicit.Link@example.test');
      await verifyDelivery(explicitDelivery);
      const link = await oauth({ sub: 'oidc-link-attempt', email: 'explicit.link@example.test', email_verified: true });
      assert.equal(link.jar.header(), '');
      const links = await pool!.query('SELECT count(*)::int AS n FROM account WHERE "userId"=$1', [String((await dbUser('explicit.link@example.test'))!.id)]);
      assert.equal(links.rows[0]?.n, 1, 'only the credential account exists');
    });

    assert.equal((await pool.query('SELECT count(*)::int AS n FROM "user" WHERE "gateDeliveryEmail" IS NULL')).rows[0]?.n, 0);
  } finally {
    await provider?.close();
    if (appServer?.listening) await new Promise<void>(resolve => appServer!.close(() => resolve()));
    await pool?.end();
    try { if (schemaCreated) await admin.query(`DROP SCHEMA "${schema}" CASCADE`); }
    finally { await admin.end(); }
  }
});
