import assert from 'node:assert/strict';
import test from 'node:test';
import { createGate } from '../src/core/engine.js';
import { DEFAULT_EMAIL_POLICY } from '../src/core/policy.js';
import { createAuth0Gate } from '../src/connectors/auth0/index.js';
import { createSupabaseGate } from '../src/connectors/supabase/index.js';
import { createBetterAuthGate } from '../src/connectors/better-auth/index.js';
import { createProviderLifecycle, type ProviderOperation, type ProviderOperationStore, type ProviderTransaction } from '../src/core/provider-lifecycle.js';
import type { OwnershipState } from '../src/core/registry.js';

const tenantId = 'online-policy-test';
const userId = 'auth0|epoch-user';
const address = 'User@company.test';
const legacy = DEFAULT_EMAIL_POLICY.prepareEmail(address);

function makeOnlineEngine() {
  const base = createGate({
    screening: { async screen() { return { allowed: true, reason: 'not_listed' }; } },
    canonicalRules: { 'company.test': { lowercase: true } },
    registry: {
      async claim() { return 'claimed' as const; },
      async owns() { return true; },
      async releaseUser() {},
    },
  });
  const calls: string[] = [];
  const state: OwnershipState = { status: 'active', canonical: legacy.canonical, policyVersion: 'epoch-1', revision: '7' };
  return {
    ...base,
    calls,
    emailPolicy: base.emailPolicy,
    async prepareEmail(input: { tenantId: string; email: unknown; policyVersion?: string }) {
      calls.push(input.policyVersion ?? 'current');
      return input.policyVersion === 'epoch-1' ? DEFAULT_EMAIL_POLICY.prepareEmail(input.email) : base.emailPolicy.prepareEmail(input.email);
    },
    async getOwnership() { return state; },
  };
}

const operationStore = (): ProviderOperationStore => {
  let operation: ProviderOperation | null = null;
  const tx: ProviderTransaction = {
    async read() { return operation; },
    async write(value) { operation = value; },
  };
  return { async withUserLock(_scope, work) { return work(tx); } };
};

test('adapter ownership comparisons use the persisted policy epoch after a cutover', async t => {
  await t.test('Auth0 post-login selects the active owner policy before comparing canonical identity', async () => {
    const engine = makeOnlineEngine();
    const adapter = createAuth0Gate({ tenantId, engine: engine as never, trustedConnections: ['connection'],
      async getUserById(id) { return { user_id: id, email: address, email_verified: true, created_at: 'generation-1' }; } });
    const denied: string[] = [];
    await adapter.onExecutePostLogin({ user: { user_id: userId, email: address, email_verified: true, created_at: 'generation-1' },
      connection: { id: 'connection' } }, { access: { deny(reason) { denied.push(reason); } } });
    assert.deepEqual(denied, []);
    assert.deepEqual(engine.calls, ['epoch-1']);
  });

  await t.test('Supabase live access delegates policy selection to the engine without an extra read', async () => {
    const engine = makeOnlineEngine();
    const adapter = createSupabaseGate({ tenantId, gate: engine as never,
      webhookSecret: `whsec_${Buffer.from('local-online-policy-secret').toString('base64')}`,
      async getUserById(id) { return { id, email: address, email_confirmed_at: '2026-10-27T00:00:00Z' }; },
      async getUserForAccessToken() { return { id: userId, email: address, email_confirmed_at: '2026-10-27T00:00:00Z' }; } });
    await adapter.assertActive('synthetic-host-verified-token');
    assert.deepEqual(engine.calls, []);
  });

  await t.test('Better Auth session check uses the ownership version', async () => {
    const engine = makeOnlineEngine();
    const integration = createBetterAuthGate({ tenantId, engine: engine as never, async sendVerificationEmail() {} });
    const session = { user: { id: userId } };
    const auth = {
      options: integration.authOptions,
      async handler() { return new Response(); },
      api: { async getSession() { return session; } },
      $context: Promise.resolve({ secret: 'synthetic', internalAdapter: {
        async findUserById(id: string) { return { id, email: address.toLowerCase(), gateDeliveryEmail: address, emailVerified: true }; },
        async deleteUser() {},
      } }),
    } as never;
    const bound = integration.bind(auth);
    assert.equal(await bound.getActiveSession(new Headers()), session);
    assert.deepEqual(engine.calls, ['epoch-1']);
  });

  await t.test('provider email-change begin compares the old address using the owner epoch', async () => {
    const engine = makeOnlineEngine();
    const lifecycle = createProviderLifecycle({ tenantId, namespace: 'issuer.example.test', engine: engine as never,
      operations: operationStore(), async getUserById(id) { return { id, email: address, emailVerified: true, generation: 'generation-1' }; },
      async deleteUser() {} });
    const begun = await lifecycle.beginEmailChange({ userId, email: 'Next@other.test' });
    assert.match(begun.operationId, /^[0-9a-f-]{36}$/);
    assert.deepEqual(engine.calls, ['current', 'epoch-1']);
  });
});
