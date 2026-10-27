import assert from 'node:assert/strict';
import test, { after } from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getDefaultArguments as defaultPostLoginArguments, loadAction as loadPostLoginAction } from '@auth0/actions/post-login/v3/test';
import { createAuth0Gate, type Auth0PostLoginApi, type Auth0PostLoginEvent } from '../src/connectors/auth0/index.js';
import { createLifecycleGate } from '../src/core/lifecycle.js';
import { createPostgresIdentityRegistry, type PgPool } from '../src/storage/postgres/identity.js';
import { createProviderLifecycle, type ProviderUser } from '../src/core/provider-lifecycle.js';
import { createPostgresProviderOperationStore } from '../src/storage/postgres/provider-lifecycle.js';

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
type TestPool = PgPool & { end(): Promise<void> };

test('Auth0 Action + PostgreSQL provider lifecycle integration', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL unset; real PostgreSQL Action lifecycle not run', timeout: 60_000,
}, async () => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only explicitly supplied loopback PostgreSQL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  const pgModule = 'pg';
  const { Pool } = await import(pgModule) as { Pool: new (options: Record<string, unknown>) => TestPool };
  const schema = `gate_auth0_flow_${process.pid}_${Date.now()}`;
  const poolOptions = { connectionString: databaseUrl, max: 12, connectionTimeoutMillis: 2_000,
    statement_timeout: 5_000, query_timeout: 6_000, lock_timeout: 3_000 };
  const admin = new Pool(poolOptions);
  let pool: TestPool | undefined;
  let schemaCreated = false;
  let wrapperDir: string | undefined;
  try {
    await admin.query(`CREATE SCHEMA "${schema}"`);
    schemaCreated = true;
    pool = new Pool({ ...poolOptions, options: `-c search_path=${schema}` });
    for (const migration of ['001_identity.sql', '002_lifecycle.sql', '004_provider_operations.sql', '005_tenant_policy.sql']) {
      await pool.query(await readFile(`migrations/${migration}`, 'utf8'));
    }

    const registry = createPostgresIdentityRegistry(pool, { schema });
    const operations = createPostgresProviderOperationStore(pool, { schema });
    const screened: string[] = [];
    const profiles = new Map<string, { id: string; email: string; emailVerified: boolean; generation: string }>();
    const currentProfile = (id: string) => {
      const user = profiles.get(id);
      return user ? { ...user } : null;
    };
    const engine = createLifecycleGate({ registry, screening: { async screen(email) {
      screened.push(email);
      return { allowed: true, reason: 'not_listed' };
    } } });
    let failDeleteOnce = false;
    let deleteObservedRevoked = false;
    const providerLifecycle = createProviderLifecycle({
      tenantId: 't', namespace: 'auth0.example.test', engine, operations,
      async getUserById(id): Promise<ProviderUser | null> {
        const user = currentProfile(id);
        return user ? { id: user.id, email: user.email, emailVerified: user.emailVerified, generation: user.generation } : null;
      },
      async deleteUser(id, generation) {
        const state = await engine.getOwnership({ tenantId: 't', userId: id });
        deleteObservedRevoked ||= state.status === 'revoked';
        const user = profiles.get(id);
        if (!user || user.generation !== generation) throw new Error('provider generation changed');
        if (failDeleteOnce) { failDeleteOnce = false; throw new Error('injected provider delete outage'); }
        profiles.delete(id);
      },
    });
    const actionGate = createAuth0Gate({ tenantId: 't', engine, trustedConnections: ['con_local_database'],
      lifecycle: providerLifecycle,
      async getUserById(userId) {
        const user = currentProfile(userId);
        return user ? { user_id: user.id, email: user.email, email_verified: user.emailVerified, created_at: user.generation } : null;
      } });

    wrapperDir = await mkdtemp(join(tmpdir(), 'irondome-auth0-pg-action-'));
    const wrapperFile = join(wrapperDir, 'action.cjs');
    await writeFile(wrapperFile,
      'exports.onExecutePostLogin = async (event, api) => globalThis.__irondomeAuth0PostLogin(event, api);');
    const loadedAction = await loadPostLoginAction(wrapperFile);
    const runPostLogin = async (id: string) => {
      const user = profiles.get(id);
      assert.ok(user);
      const [event, api] = defaultPostLoginArguments();
      Object.assign(event.user, { user_id: user.id, email: user.email, email_verified: user.emailVerified, created_at: user.generation });
      event.connection.id = 'con_local_database';
      const denied: string[] = [];
      (api.access as unknown as { deny(reason: string): unknown }).deny = (reason: string) => { denied.push(reason); return api; };
      (globalThis as Record<string, unknown>).__irondomeAuth0PostLogin = actionGate.onExecutePostLogin;
      try { await loadedAction.execute('onExecutePostLogin', event as never, api as never); }
      finally { delete (globalThis as Record<string, unknown>).__irondomeAuth0PostLogin; }
      return denied;
    };
    function addProfile(id: string, email: string, emailVerified = true): void {
      profiles.set(id, { id, email, emailVerified, generation: '2026-10-26T12:00:00.000Z' });
    }
    async function operationFor(userId: string) {
      return operations.withUserLock({ namespace: 'auth0.example.test', tenantId: 't', userId }, tx => tx.read());
    }

    const firstId = 'auth0|first';
    const secondId = 'auth0|second';
    addProfile(firstId, 'Claimed.Alias+one@gmail.com');
    addProfile(secondId, 'claimedalias+two@googlemail.com');
    const race = await Promise.all([runPostLogin(firstId), runPostLogin(secondId)]);
    assert.equal(race.flat().length, 1, 'one canonical alias race participant is denied');
    const states = await Promise.all([registry.getOwnership({ tenantId: 't', userId: firstId }), registry.getOwnership({ tenantId: 't', userId: secondId })]);
    const activeIndexes = states.flatMap((state, index) => state.status === 'active' ? [index] : []);
    assert.equal(activeIndexes.length, 1, 'the PostgreSQL canonical claim has exactly one owner');
    const ownerId = activeIndexes[0] === 0 ? firstId : secondId;
    const ownerProfile = profiles.get(ownerId)!;

    const aliasTarget = 'cl.ai.med.alias+changed@gmail.com';
    await providerLifecycle.beginEmailChange({ userId: ownerId, email: aliasTarget });
    ownerProfile.email = aliasTarget;
    assert.deepEqual(await runPostLogin(ownerId), [], 'same canonical delivery changes complete their authorized revision too');
    const aliasState = await registry.getOwnership({ tenantId: 't', userId: ownerId });
    if (aliasState.status === 'active') assert.equal(aliasState.revision, '2'); else assert.fail();
    assert.equal((await operationFor(ownerId))?.status, 'complete');

    const staged = await providerLifecycle.beginEmailChange({ userId: ownerId, email: 'Fresh.Change@example.test' });
    assert.equal((await operationFor(ownerId))?.expectedRevision, '2', 'the server captures the current revision before provider change');
    ownerProfile.email = 'Fresh.Change@example.test';
    ownerProfile.emailVerified = true;
    assert.deepEqual(await runPostLogin(ownerId), [], 'the trusted Action completes only the pre-authorized matching change');
    const changedState = await registry.getOwnership({ tenantId: 't', userId: ownerId });
    assert.equal(changedState.status, 'active');
    if (changedState.status === 'active') assert.equal(changedState.revision, '3');
    assert.equal((await operationFor(ownerId))?.status, 'complete');
    assert.equal(await operationFor(ownerId).then(operation => operation?.id), staged.operationId);

    assert.deepEqual(await runPostLogin(ownerId), [], 'same provider proof retry succeeds without another swap');
    const retriedState = await registry.getOwnership({ tenantId: 't', userId: ownerId });
    if (retriedState.status === 'active') assert.equal(retriedState.revision, '3');

    ownerProfile.email = 'Untracked.Change@example.test';
    assert.equal((await runPostLogin(ownerId)).length, 1, 'raw provider email changes without a durable intent are denied');
    const afterUntracked = await registry.getOwnership({ tenantId: 't', userId: ownerId });
    if (afterUntracked.status === 'active') {
      assert.equal(afterUntracked.canonical, 'Fresh.Change@example.test');
      assert.equal(afterUntracked.revision, '3');
    } else assert.fail('untracked change must preserve the existing claim');

    ownerProfile.email = 'Fresh.Change@example.test';
    const pendingUnverified = await providerLifecycle.beginEmailChange({ userId: ownerId, email: 'Unverified.Target@example.test' });
    ownerProfile.email = 'Unverified.Target@example.test';
    ownerProfile.emailVerified = false;
    assert.equal((await runPostLogin(ownerId)).length, 1, 'an unverified new provider address cannot complete a staged change');
    const afterUnverified = await registry.getOwnership({ tenantId: 't', userId: ownerId });
    if (afterUnverified.status === 'active') {
      assert.equal(afterUnverified.canonical, 'Fresh.Change@example.test');
      assert.equal(afterUnverified.revision, '3');
    }
    assert.equal((await operationFor(ownerId))?.id, pendingUnverified.operationId);

    ownerProfile.email = 'Fresh.Change@example.test';
    ownerProfile.emailVerified = true;
    const staleCachedToken = { sub: ownerId, email: ownerProfile.email, email_verified: true };
    failDeleteOnce = true;
    await assert.rejects(providerLifecycle.deleteAccount({ userId: ownerId }), { code: 'storage_unavailable' });
    assert.equal(deleteObservedRevoked, true, 'Gate revocation happens before the provider delete callback');
    assert.deepEqual(await registry.getOwnership({ tenantId: 't', userId: ownerId }), { status: 'revoked' });
    assert.ok(profiles.has(ownerId), 'provider remains while the simulated provider delete is failing');
    assert.equal((await operationFor(ownerId))?.kind, 'delete', 'durable delete intent survives provider failure');
    await providerLifecycle.resumeDeletion({ userId: ownerId });
    assert.equal(profiles.has(ownerId), false);
    assert.equal((await operationFor(ownerId))?.status, 'deleted');
    await assert.rejects(actionGate.assertActive(staleCachedToken), { code: 'ownership_required' });
    assert.equal(screened.length >= 4, true, 'screening occurred on initial claims and authorized address changes');
  } finally {
    if (wrapperDir) await rm(wrapperDir, { recursive: true, force: true });
    await pool?.end();
    try { if (schemaCreated) await admin.query(`DROP SCHEMA "${schema}" CASCADE`); }
    finally { await admin.end(); }
  }
});
