import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { betterAuth } from 'better-auth';
import { memoryAdapter, type MemoryDB } from 'better-auth/adapters/memory';
import { Webhook } from 'standardwebhooks';
import { createAuth0Gate } from '../src/connectors/auth0/index.js';
import { createBetterAuthGate } from '../src/connectors/better-auth/index.js';
import { createLifecycleGate } from '../src/core/lifecycle.js';
import { createSupabaseGate } from '../src/connectors/supabase/index.js';
import { createProviderLifecycle, type ProviderOperation, type ProviderOperationStore, type ProviderUser } from '../src/core/provider-lifecycle.js';
import type { LifecycleIdentityRegistry, OwnershipState, ReplaceInput, ReplaceResult, ClaimInput, ClaimResult, OwnershipInput } from '../src/core/registry.js';
import { createEmailPolicy } from '../src/core/policy.js';

class TestLifecycleRegistry implements LifecycleIdentityRegistry {
  private readonly byUser = new Map<string, OwnershipState>();
  private readonly byCanonical = new Map<string, string>();
  private readonly revoked = new Set<string>();
  private account(tenantId: string, userId: string) { return JSON.stringify([tenantId, userId]); }
  private identity(tenantId: string, canonical: string) { return JSON.stringify([tenantId, canonical]); }

  async claim(input: ClaimInput): Promise<ClaimResult> {
    const account = this.account(input.tenantId, input.userId);
    if (this.revoked.has(account)) return 'revoked';
    const current = this.byUser.get(account);
    if (current?.status === 'active') {
      if (current.policyVersion !== input.policyVersion) return 'policy-mismatch';
      return current.canonical === input.canonical ? 'already-owned' : 'conflict';
    }
    const identity = this.identity(input.tenantId, input.canonical);
    const owner = this.byCanonical.get(identity);
    if (owner && owner !== account) return 'conflict';
    this.byCanonical.set(identity, account);
    this.byUser.set(account, { status: 'active', canonical: input.canonical, policyVersion: input.policyVersion, revision: '1' });
    return 'claimed';
  }
  async owns(input: OwnershipInput): Promise<boolean> {
    return this.byCanonical.get(this.identity(input.tenantId, input.canonical)) === this.account(input.tenantId, input.userId);
  }
  async releaseUser(input: { tenantId: string; userId: string }): Promise<void> {
    const account = this.account(input.tenantId, input.userId);
    const current = this.byUser.get(account);
    if (current?.status === 'active') this.byCanonical.delete(this.identity(input.tenantId, current.canonical));
    this.byUser.delete(account);
    this.revoked.add(account);
  }
  async getOwnership(input: { tenantId: string; userId: string }): Promise<OwnershipState> {
    return this.byUser.get(this.account(input.tenantId, input.userId)) ??
      (this.revoked.has(this.account(input.tenantId, input.userId)) ? { status: 'revoked' } : { status: 'unclaimed' });
  }
  async replaceVerified(input: ReplaceInput): Promise<ReplaceResult> {
    const account = this.account(input.tenantId, input.userId);
    if (this.revoked.has(account)) return 'revoked';
    const current = this.byUser.get(account);
    if (current?.status !== 'active') return 'stale';
    if (current.policyVersion !== input.policyVersion) return 'policy-mismatch';
    if (current.revision !== input.expectedRevision) return 'stale';
    const identity = this.identity(input.tenantId, input.canonical);
    const owner = this.byCanonical.get(identity);
    if (owner && owner !== account) return 'conflict';
    this.byCanonical.delete(this.identity(input.tenantId, current.canonical));
    this.byCanonical.set(identity, account);
    this.byUser.set(account, { status: 'active', canonical: input.canonical, policyVersion: input.policyVersion,
      revision: String(BigInt(current.revision) + 1n) });
    return 'replaced';
  }
  async revokeUser(input: { tenantId: string; userId: string }): Promise<'revoked' | 'already-revoked'> {
    const prior = this.revoked.has(this.account(input.tenantId, input.userId));
    await this.releaseUser(input);
    return prior ? 'already-revoked' : 'revoked';
  }
}

const screening = { async screen() { return { allowed: true, reason: 'not_listed' }; } };
const makeEngine = () => createLifecycleGate({ registry: new TestLifecycleRegistry(), screening,
  canonicalRules: { 'company.test': { lowercase: true, stripPlusTag: true } } });
const email = 'Alice+tag@company.test';
const canonical = 'alice@company.test';

test('Auth0 and Supabase adapters inherit exact-domain canonical policy from their engine', async t => {
  await t.test('Auth0 post-login recognizes an active custom-domain owner', async () => {
    const engine = makeEngine();
    await engine.claimVerified({ tenantId: 'tenant', userId: 'auth0|alice', email });
    const adapter = createAuth0Gate({ tenantId: 'tenant', engine, trustedConnections: ['connection'],
      async getUserById(userId) { return { user_id: userId, email, email_verified: true, created_at: 'generation-1' }; } });
    const denied: string[] = [];
    await adapter.onExecutePostLogin({ user: { user_id: 'auth0|alice', email, email_verified: true,
      created_at: 'generation-1' }, connection: { id: 'connection' } }, { access: { deny(reason) { denied.push(reason); } } });
    assert.deepEqual(denied, []);
    assert.equal((await engine.getOwnership({ tenantId: 'tenant', userId: 'auth0|alice' })).status, 'active');
    const state = await engine.getOwnership({ tenantId: 'tenant', userId: 'auth0|alice' });
    assert.equal(state.status === 'active' ? state.canonical : undefined, canonical);
  });

  await t.test('Supabase custom access-token hook accepts matching custom-policy ownership', async () => {
    const engine = makeEngine();
    await engine.claimVerified({ tenantId: 'tenant', userId: 'supabase-user', email });
    const secret = `whsec_${Buffer.from('local-custom-policy-hook-key').toString('base64')}`;
    const payload = { user_id: 'supabase-user', authentication_method: 'password', claims: {
      aud: 'authenticated', exp: 2_000_000_000, iat: 1_900_000_000, sub: 'supabase-user', role: 'authenticated',
      aal: 'aal1', session_id: 'session', email, phone: '', is_anonymous: false,
    } };
    const body = JSON.stringify(payload);
    const id = randomUUID();
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = new Webhook(secret).sign(id, new Date(Number(timestamp) * 1000), body);
    const request = new Request('https://hooks.example.test/custom-access-token', { method: 'POST', body,
      headers: { 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': signature } });
    const adapter = createSupabaseGate({ tenantId: 'tenant', gate: engine, webhookSecret: secret,
      async getUserById(userId) { return { id: userId, email, email_confirmed_at: '2026-10-26T00:00:00Z' }; } });
    const response = await adapter.customAccessToken(request);
    assert.equal(response.status, 200);
    assert.deepEqual((await response.json() as { claims: unknown }).claims, payload.claims);
    const state = await engine.getOwnership({ tenantId: 'tenant', userId: 'supabase-user' });
    assert.equal(state.status === 'active' ? state.canonical : undefined, canonical);
  });
});

test('Better Auth and provider lifecycle inherit engine email preparation', async t => {
  await t.test('Better Auth preserves delivery spelling and claims the configured canonical identity', async () => {
    const engine = makeEngine();
    const db: MemoryDB = { user: [], account: [], session: [], verification: [] };
    const deliveries: Array<{ token: string; email: string }> = [];
    const integration = createBetterAuthGate({ tenantId: 'tenant', engine,
      async sendVerificationEmail({ token, user }) { deliveries.push({ token, email: user.email }); } });
    const auth = betterAuth({ baseURL: 'https://auth.example.test', secret: 'custom-policy-test-secret-not-for-production-0123456789',
      database: memoryAdapter(db), ...integration.authOptions });
    integration.bind(auth);
    const signup = await auth.api.signUpEmail({ body: { email, password: 'custom-policy-password-123', name: 'Custom Policy' } });
    assert.equal(signup.user.email, email.toLowerCase());
    assert.equal(db.user?.[0]?.gateDeliveryEmail, email);
    assert.equal(deliveries[0]?.email, email);
    assert.equal((await engine.getOwnership({ tenantId: 'tenant', userId: signup.user.id })).status, 'unclaimed');
    await auth.api.verifyEmail({ query: { token: deliveries[0]!.token } });
    const state = await engine.getOwnership({ tenantId: 'tenant', userId: signup.user.id });
    assert.equal(state.status === 'active' ? state.canonical : undefined, canonical);
  });

  await t.test('provider email-change coordination compares the current address under engine policy', async () => {
    const engine = makeEngine();
    const user: ProviderUser = { id: 'provider-user', email, emailVerified: true, generation: 'provider-generation-1' };
    await engine.claimVerified({ tenantId: 'tenant', userId: user.id, email: user.email });
    const stored: { operation: ProviderOperation | null } = { operation: null };
    const operations: ProviderOperationStore = { async withUserLock(_scope, work) {
      return work({ async read() { return stored.operation; }, async write(value) { stored.operation = value; } });
    } };
    const lifecycle = createProviderLifecycle({ tenantId: 'tenant', namespace: 'provider.company.test', engine, operations,
      async getUserById(id) { return id === user.id ? user : null; }, async deleteUser() {} });
    const begun = await lifecycle.beginEmailChange({ userId: user.id, email: 'Next+tag@company.test' });
    assert.ok(begun.operationId);
    assert.equal(stored.operation?.kind, 'email-change');
    assert.equal(stored.operation?.previousEmail, email);
    assert.equal(stored.operation?.nextEmail, 'Next+tag@company.test');
    assert.equal((await engine.getOwnership({ tenantId: 'tenant', userId: user.id })).status, 'active');
    const state = await engine.getOwnership({ tenantId: 'tenant', userId: user.id });
    assert.equal(state.status === 'active' ? state.canonical : undefined, canonical);
  });
});

test('configured custom rule applies only to its exact domain', () => {
  const policy = createEmailPolicy({ 'company.test': { lowercase: true, stripPlusTag: true } });
  assert.equal(policy.prepareEmail(email).canonical, canonical);
  assert.equal(policy.prepareEmail('Alice+tag@other.test').canonical, 'Alice+tag@other.test');
});
