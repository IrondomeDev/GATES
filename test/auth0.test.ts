import assert from 'node:assert/strict';
import test, { after } from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getDefaultArguments as defaultPreRegistrationArguments, loadAction as loadPreRegistrationAction } from '@auth0/actions/pre-user-registration/v2/test';
import { getDefaultArguments as defaultPostLoginArguments, loadAction as loadPostLoginAction } from '@auth0/actions/post-login/v3/test';
import { createAuth0Gate, type Auth0PostLoginApi, type Auth0PostLoginEvent, type Auth0PreUserRegistrationApi,
  type Auth0PreUserRegistrationEvent, type Auth0GateOptions } from '../src/connectors/auth0/index.js';
import { GateError } from '../src/core/errors.js';
import { createLifecycleGate } from '../src/core/lifecycle.js';
import type { LifecycleIdentityRegistry, OwnershipState } from '../src/core/registry.js';

const wrapperDir = await mkdtemp(join(tmpdir(), 'irondome-auth0-actions-'));
const actionWrapper = join(wrapperDir, 'gate-action.cjs');
await writeFile(actionWrapper, [
  'exports.onExecutePreUserRegistration = async (event, api) => globalThis.__irondomeAuth0Gate.onExecutePreUserRegistration(event, api);',
  'exports.onExecutePostLogin = async (event, api) => globalThis.__irondomeAuth0Gate.onExecutePostLogin(event, api);',
].join('\n'));
const preAction = await loadPreRegistrationAction(actionWrapper);
const postAction = await loadPostLoginAction(actionWrapper);
after(async () => rm(wrapperDir, { recursive: true, force: true }));

async function runPre(gate: ReturnType<typeof createAuth0Gate>, event: Auth0PreUserRegistrationEvent, api: Auth0PreUserRegistrationApi) {
  (globalThis as Record<string, unknown>).__irondomeAuth0Gate = gate;
  try { await preAction.execute('onExecutePreUserRegistration', event as never, api as never); }
  finally { delete (globalThis as Record<string, unknown>).__irondomeAuth0Gate; }
}

async function runPost(gate: ReturnType<typeof createAuth0Gate>, event: Auth0PostLoginEvent, api: Auth0PostLoginApi) {
  (globalThis as Record<string, unknown>).__irondomeAuth0Gate = gate;
  try { await postAction.execute('onExecutePostLogin', event as never, api as never); }
  finally { delete (globalThis as Record<string, unknown>).__irondomeAuth0Gate; }
}

function fixture() {
  const byUser = new Map<string, OwnershipState>();
  const byCanonical = new Map<string, string>();
  const revoked = new Set<string>();
  const screened: string[] = [];
  let block = false;
  const key = (tenantId: string, userId: string) => `${tenantId}\0${userId}`;
  const registry: LifecycleIdentityRegistry = {
    async claim(input) {
      const ownerKey = key(input.tenantId, input.userId);
      if (revoked.has(ownerKey)) return 'revoked';
      const prior = byCanonical.get(`${input.tenantId}\0${input.canonical}`);
      if (prior && prior !== ownerKey) return 'conflict';
      const current = byUser.get(ownerKey);
      if (current?.status === 'active' && current.canonical !== input.canonical) return 'conflict';
      byCanonical.set(`${input.tenantId}\0${input.canonical}`, ownerKey);
      byUser.set(ownerKey, { status: 'active', canonical: input.canonical, policyVersion: input.policyVersion, revision: '1' });
      return current?.status === 'active' ? 'already-owned' : 'claimed';
    },
    async owns(input) {
      return byCanonical.get(`${input.tenantId}\0${input.canonical}`) === key(input.tenantId, input.userId);
    },
    async releaseUser(input) {
      const ownerKey = key(input.tenantId, input.userId);
      const old = byUser.get(ownerKey);
      if (old?.status === 'active') byCanonical.delete(`${input.tenantId}\0${old.canonical}`);
      byUser.delete(ownerKey); revoked.add(ownerKey);
    },
    async getOwnership(input) { return byUser.get(key(input.tenantId, input.userId)) ?? { status: 'unclaimed' }; },
    async replaceVerified(input) {
      const ownerKey = key(input.tenantId, input.userId);
      if (revoked.has(ownerKey)) return 'revoked';
      const current = byUser.get(ownerKey);
      if (!current || current.status !== 'active' || current.revision !== input.expectedRevision) return 'stale';
      const nextKey = `${input.tenantId}\0${input.canonical}`;
      const priorOwner = byCanonical.get(nextKey);
      if (priorOwner && priorOwner !== ownerKey) return 'conflict';
      byCanonical.delete(`${input.tenantId}\0${current.canonical}`);
      byCanonical.set(nextKey, ownerKey);
      byUser.set(ownerKey, { status: 'active', canonical: input.canonical, policyVersion: input.policyVersion,
        revision: String(BigInt(current.revision) + 1n) });
      return 'replaced';
    },
    async revokeUser(input) {
      await this.releaseUser(input);
      return 'revoked';
    },
  };
  const engine = createLifecycleGate({ registry, screening: { async screen(email) {
    screened.push(email);
    return { allowed: !block, reason: block ? 'synthetic_block' : 'not_listed' };
  } } });
  return { engine, registry, screened, blockScreening() { block = true; } };
}

function postApi() {
  const denied: string[] = [];
  const [, api] = defaultPostLoginArguments();
  (api.access as unknown as { deny(reason: string): unknown }).deny = (reason: string) => { denied.push(reason); return api; };
  return { api: api as unknown as Auth0PostLoginApi, denied };
}

function preApi() {
  const denied: { reason: string; userMessage: string }[] = [];
  const [, api] = defaultPreRegistrationArguments();
  (api.access as unknown as { deny(reason: string, userMessage: string): unknown }).deny = (reason: string, userMessage: string) => {
    denied.push({ reason, userMessage }); return api;
  };
  return { api: api as unknown as Auth0PreUserRegistrationApi, denied };
}

function loginEvent(user: Partial<NonNullable<Auth0PostLoginEvent['user']>>, connection = 'con-db'): Auth0PostLoginEvent {
  const [event] = defaultPostLoginArguments();
  Object.assign(event.user, { user_id: 'auth0|user-1', email: 'Current.User+tag@gmail.com', email_verified: true, ...user });
  event.connection.id = connection;
  return event as unknown as Auth0PostLoginEvent;
}

test('Auth0 pre-user-registration screens only and denies blocked, malformed, or unavailable requests', async () => {
  const f = fixture();
  const gate = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'] });
  const api = preApi();
  const [event] = defaultPreRegistrationArguments();
  event.user.email = 'New.User@example.com';
  await runPre(gate, event as unknown as Auth0PreUserRegistrationEvent, api.api);
  assert.deepEqual(f.screened, ['New.User@example.com']);
  assert.equal((await f.registry.getOwnership({ tenantId: 'test-tenant', userId: 'auth0|user-1' })).status, 'unclaimed',
    'pre-registration cannot claim before Auth0 email verification');

  f.blockScreening();
  const [blockedEvent] = defaultPreRegistrationArguments();
  blockedEvent.user.email = 'Blocked@example.com';
  await runPre(gate, blockedEvent as unknown as Auth0PreUserRegistrationEvent, api.api);
  const [invalidEvent] = defaultPreRegistrationArguments();
  delete invalidEvent.user.email;
  await runPre(gate, invalidEvent as unknown as Auth0PreUserRegistrationEvent, api.api);
  assert.equal(api.denied.length, 2);
  assert.equal(api.denied[0]?.reason, 'screening_denied');
  assert.equal(api.denied[1]?.reason, 'gate_access_denied');
  assert.equal(api.denied[0]?.userMessage, 'Unable to complete this request.');
  assert.equal(f.screened.length, 2, 'malformed email does not reach the billable screen');
});

test('Auth0 post-login claims only trusted verified identities and refuses changed email or alias collisions', async () => {
  const f = fixture();
  const gate = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db', 'con-social'] });
  const { api, denied } = postApi();

  await runPost(gate, loginEvent({ email_verified: false }), api);
  await runPost(gate, loginEvent({}, 'con-untrusted'), api);
  assert.equal(denied.length, 2);
  assert.equal(f.screened.length, 0);

  await runPost(gate, loginEvent({}), api);
  assert.equal(denied.length, 2);
  const userId = 'auth0|user-1';
  const active = await f.registry.getOwnership({ tenantId: 'test-tenant', userId });
  assert.equal(active.status, 'active');
  if (active.status === 'active') assert.equal(active.revision, '1');
  assert.equal(f.screened.length, 1, 'first trusted login claims with a fresh screening call');

  await runPost(gate, loginEvent({}), api);
  assert.equal(f.screened.length, 1, 'subsequent active login checks the live claim without another screening call');
  await runPost(gate, loginEvent({ email: 'Changed.Address@example.com' }), api);
  assert.equal(denied.length, 3, 'post-login does not silently apply email changes');
  assert.equal(await f.registry.owns({ tenantId: 'test-tenant', userId, canonical: 'currentuser@gmail.com' }), true);
  assert.equal(await f.registry.owns({ tenantId: 'test-tenant', userId, canonical: 'changed.address@example.com' }), false);

  await runPost(gate, {
    user: { user_id: 'auth0|second', email: 'currentuser+two@googlemail.com', email_verified: true },
    connection: { id: 'con-social' },
  }, api);
  assert.equal(denied.length, 4, 'canonical Gmail alias cannot acquire a second Auth0 identity');
  assert.equal((await f.registry.getOwnership({ tenantId: 'test-tenant', userId: 'auth0|second' })).status, 'unclaimed');

  await f.engine.revokeUser({ tenantId: 'test-tenant', userId });
  await runPost(gate, loginEvent({}), api);
  assert.equal(denied.length, 5, 'revoked Auth0 subject stays denied');
});

test('Auth0 Action maps temporary lifecycle outages to generic denial without exposing errors', async () => {
  const f = fixture();
  const errorEngine = Object.freeze({ ...f.engine, async getOwnership() { throw new GateError('storage_unavailable', true); } });
  const gate = createAuth0Gate({ tenantId: 'test-tenant', engine: errorEngine, trustedConnections: ['con-db'] });
  const { api, denied } = postApi();
  await runPost(gate, loginEvent({}), api);
  assert.deepEqual(denied, ['gate_unavailable']);
});

test('Auth0 resource helper checks current provider profile against the live claim', async () => {
  const f = fixture();
  const profile = { user_id: 'auth0|user-1', email: 'Current.User+tag@gmail.com', email_verified: true,
    created_at: '2026-01-02T03:04:05.000Z' };
  const gate = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'],
    async getUserById(userId) { return userId === profile.user_id ? profile : null; } });
  const { api } = postApi();
  await runPost(gate, loginEvent({ created_at: profile.created_at }), api);
  await gate.assertActive({ sub: 'auth0|user-1', email: 'Current.User+tag@gmail.com', email_verified: false });
  await gate.assertActive({ sub: 'auth0|user-1', email: 'Other.Address@example.com', email_verified: true });
});

test('Auth0 resource helper requires a fresh Management API profile and ignores token email proof', async () => {
  const f = fixture();
  const profile = { user_id: 'auth0|user-1', email: 'Current.User+tag@gmail.com', email_verified: true,
    created_at: '2026-01-02T03:04:05.000Z' };
  const gate = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'],
    async getUserById(userId) { return userId === profile.user_id ? profile : null; } });
  const { api } = postApi();
  await runPost(gate, loginEvent({ created_at: profile.created_at }), api);
  await gate.assertActive({ sub: profile.user_id, email: 'old.jwt.address@example.com', email_verified: false });

  const noReader = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'] });
  await assert.rejects(noReader.assertActive({ sub: profile.user_id }), { code: 'ownership_required' });

  const changedProfile = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'],
    async getUserById(userId) { return { ...profile, user_id: userId, email: 'new.current@example.com' }; } });
  await assert.rejects(changedProfile.assertActive({ sub: profile.user_id, email: profile.email, email_verified: true }),
    { code: 'ownership_required' });
});

test('Auth0 post-login compares authoritative profile and event proof when a reader is configured', async () => {
  const f = fixture();
  const gate = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'],
    async getUserById(userId) { return { user_id: userId, email: 'changed.now@example.com', email_verified: true,
      created_at: '2026-01-02T03:04:05.000Z' }; } });
  const { api, denied } = postApi();
  await runPost(gate, loginEvent({ created_at: '2026-01-02T03:04:05.000Z' }), api);
  assert.deepEqual(denied, ['gate_access_denied']);
  assert.equal(f.screened.length, 0, 'stale Action profile is rejected before claim or screening');
  assert.equal((await f.registry.getOwnership({ tenantId: 'test-tenant', userId: 'auth0|user-1' })).status, 'unclaimed');
});

test('Auth0 provider reads and action work honor the bounded deadline and abort signal', async () => {
  const f = fixture();
  let aborted = false;
  const gate = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'], actionTimeoutMs: 10,
    async getUserById(_userId, signal) {
      return await new Promise((_resolve, reject) => {
        signal?.addEventListener('abort', () => { aborted = true; reject(new GateError('cancelled')); }, { once: true });
      });
    } });
  await assert.rejects(gate.assertActive({ sub: 'auth0|user-1' }), { code: 'screening_unavailable' });
  assert.equal(aborted, true, 'the protected lookup receives and observes the abort signal');
  assert.throws(() => createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine,
    trustedConnections: ['con-db'], actionTimeoutMs: 15_001 }), /deadline/);

  const failingReader = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'],
    async getUserById() { throw new Error('private-user@example.test management-token'); } });
  await assert.rejects(failingReader.assertActive({ sub: 'auth0|private-id' }), error => {
    assert.equal((error as GateError).code, 'storage_unavailable');
    assert.doesNotMatch(String(error), /private-user|management-token/);
    return true;
  });
});

test('Auth0 snapshots event fields before an asynchronous Management API read', async () => {
  const f = fixture();
  const stableId = 'auth0|user-1';
  const victimId = 'auth0|victim';
  await f.engine.claimVerified({ tenantId: 'test-tenant', userId: stableId, email: 'Before.Change@example.test' });
  const generation = '2026-10-26T12:00:00.000Z';
  let releaseReader!: () => void;
  let startedReader!: () => void;
  const readerStarted = new Promise<void>(resolve => { startedReader = resolve; });
  const readerRelease = new Promise<void>(resolve => { releaseReader = resolve; });
  const operationUsers: string[] = [];
  const gate = createAuth0Gate({ tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'],
    async getUserById(userId) {
      startedReader();
      await readerRelease;
      return { user_id: userId, email: 'After.Change@example.test', email_verified: true, created_at: generation };
    },
    lifecycle: { async completePendingEmailChange(input) {
      operationUsers.push(input.userId);
      await f.engine.changeVerifiedEmail({ tenantId: 'test-tenant', userId: input.userId, email: input.email, expectedRevision: '1',
        ...(input.signal ? { signal: input.signal } : {}) });
      return true;
    } },
  });
  const event = loginEvent({ email: 'After.Change@example.test', email_verified: true, created_at: generation });
  const { api, denied } = postApi();
  const work = runPost(gate, event, api);
  await readerStarted;
  Object.assign(event.user!, { user_id: victimId, email: 'Victim@example.test', email_verified: false, created_at: 'replaced' });
  event.connection!.id = 'con-untrusted';
  releaseReader();
  await work;

  assert.deepEqual(denied, [], 'post-login keeps the original trusted event fields for the full operation');
  assert.deepEqual(operationUsers, [stableId]);
  const stable = await f.registry.getOwnership({ tenantId: 'test-tenant', userId: stableId });
  assert.equal(stable.status, 'active');
  if (stable.status === 'active') {
    assert.equal(stable.canonical, 'After.Change@example.test');
    assert.equal(stable.revision, '2');
  }
  assert.equal((await f.registry.getOwnership({ tenantId: 'test-tenant', userId: victimId })).status, 'unclaimed');
});

test('Auth0 snapshots Management reader and lifecycle callbacks at factory creation', async () => {
  const f = fixture();
  const userId = 'auth0|user-1';
  await f.engine.claimVerified({ tenantId: 'test-tenant', userId, email: 'Before.Change@example.test' });
  const generation = '2026-10-26T12:00:00.000Z';
  let readerCalls = 0;
  let lifecycleCalls = 0;
  let replacementReaderCalls = 0;
  let replacementLifecycleCalls = 0;
  const config: Auth0GateOptions = {
    tenantId: 'test-tenant', engine: f.engine, trustedConnections: ['con-db'],
    async getUserById(id) {
      readerCalls++;
      return { user_id: id, email: 'After.Change@example.test', email_verified: true, created_at: generation };
    },
    lifecycle: { async completePendingEmailChange(input) {
      lifecycleCalls++;
      await f.engine.changeVerifiedEmail({ tenantId: 'test-tenant', userId: input.userId, email: input.email,
        expectedRevision: '1', ...(input.signal ? { signal: input.signal } : {}) });
      return true;
    } },
  };
  const gate = createAuth0Gate(config);
  config.getUserById = async () => { replacementReaderCalls++; return null; };
  config.lifecycle = { async completePendingEmailChange() { replacementLifecycleCalls++; return false; } };

  const { api, denied } = postApi();
  await runPost(gate, loginEvent({ email: 'After.Change@example.test', created_at: generation }), api);
  assert.deepEqual(denied, []);
  assert.equal(readerCalls, 1);
  assert.equal(lifecycleCalls, 1);
  assert.equal(replacementReaderCalls, 0);
  assert.equal(replacementLifecycleCalls, 0);
  const state = await f.registry.getOwnership({ tenantId: 'test-tenant', userId });
  if (state.status === 'active') {
    assert.equal(state.canonical, 'After.Change@example.test');
    assert.equal(state.revision, '2');
  } else assert.fail('the factory-bound coordinator should complete the pending change');
});
