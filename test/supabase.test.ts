import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { Webhook } from 'standardwebhooks';
import { createSupabaseGate, type SupabaseGateOptions, type SupabaseProviderUser } from '../src/connectors/supabase/index.js';
import { prepareEmail } from '../src/core/policy.js';
import type { OwnershipState } from '../src/core/registry.js';

const secret = `whsec_${Buffer.from('local-supabase-hook-key').toString('base64')}`;
const initialClaims = () => ({ iss: 'https://auth.example.test', aud: 'authenticated', exp: 2000000000, iat: 1900000000,
  sub: 'user-1', role: 'authenticated', aal: 'aal1', session_id: 'session-1', email: 'current@example.test',
  phone: '', is_anonymous: false, app_metadata: { provider: 'email' }, user_metadata: { display_name: 'test' }, custom: 'retained' });

function signedRequest(payload: unknown, id: string = randomUUID(), timestamp = String(Math.floor(Date.now() / 1000))) {
  const body = JSON.stringify(payload);
  const signature = new Webhook(secret).sign(id, new Date(Number(timestamp) * 1000), body);
  return new Request('https://hooks.example.test/hook', { method: 'POST', headers: {
    'content-type': 'application/json', 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': signature,
  }, body });
}

function fixture(user: SupabaseProviderUser | null = { id: 'user-1', email: 'current@example.test',
  email_confirmed_at: '2026-10-25T00:00:00Z' }, extra: Partial<Pick<SupabaseGateOptions, 'maxBodyBytes' | 'hookTimeoutMs' | 'webhookSecret' | 'now' | 'maxSignatureAgeSeconds' | 'maxReplayIds'>> = {}) {
  const calls: string[] = [];
  let ownership: OwnershipState = { status: 'unclaimed' };
  const gate = {
    async screenSignup({ email }: { email: unknown }) { calls.push(`screen:${String(email)}`); return prepareEmail(email as string); },
    async claimVerified({ email }: { email: unknown }) { calls.push(`claim:${String(email)}`); ownership = { status: 'active', canonical: prepareEmail(email).canonical, policyVersion: 'test', revision: '1' }; return prepareEmail(email); },
    async assertActive({ email }: { email: unknown }) {
      calls.push(`assert:${String(email)}`);
      if (ownership.status !== 'active' || ownership.canonical !== prepareEmail(email).canonical) throw new Error('inactive');
      return prepareEmail(email);
    },
    async getOwnership() { calls.push('ownership'); return ownership; },
  };
  const adapter = createSupabaseGate({ tenantId: 'tenant-fixed', gate,
    async getUserById(id) { calls.push(`lookup:${id}`); return user; },
    async getUserForAccessToken(token) { calls.push(`token:${token}`); return user; }, webhookSecret: secret, ...extra });
  return { adapter, calls, setOwnership(state: OwnershipState) { ownership = state; } };
}

test('Before User Created screens signup only and makes no identity claim', async () => {
  const f = fixture();
  const response = await f.adapter.beforeUserCreated(signedRequest({ user: { id: 'not-yet-created', email: 'first@example.test' }, metadata: {} }));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {});
  assert.deepEqual(f.calls, ['screen:first@example.test']);
});

test('Custom Access Token hook claims a fresh confirmed user before preserving and returning all claims', async () => {
  const f = fixture();
  const request = signedRequest({ user_id: 'user-1', authentication_method: 'password', claims: initialClaims() });
  const response = await f.adapter.customAccessToken(request);
  assert.equal(response.status, 200);
  const body = await response.json() as { claims: Record<string, unknown> };
  assert.equal(body.claims.email, 'current@example.test');
  assert.equal(body.claims.custom, 'retained');
  assert.deepEqual(body.claims.app_metadata, { provider: 'email' });
  assert.deepEqual(f.calls, ['lookup:user-1', 'ownership', 'claim:current@example.test', 'assert:current@example.test']);
});

test('custom token hook denies missing email confirmation but preserves an active identity during a pending email change', async () => {
  const unconfirmed = fixture({ id: 'user-1', email: 'current@example.test', email_confirmed_at: null,
    phone_confirmed_at: '2026-10-25T00:00:00Z' });
  const denied = await unconfirmed.adapter.customAccessToken(signedRequest({ user_id: 'user-1', authentication_method: 'password', claims: initialClaims() }));
  assert.ok((await denied.json() as { error?: unknown }).error);
  assert.deepEqual(unconfirmed.calls, ['lookup:user-1']);

  const pending = fixture({ id: 'user-1', email: 'current@example.test', email_confirmed_at: '2026-10-25T00:00:00Z', email_change: 'next@example.test' });
  pending.setOwnership({ status: 'active', canonical: 'current@example.test', policyVersion: 'test', revision: '4' });
  const allowed = await pending.adapter.customAccessToken(signedRequest({ user_id: 'user-1', authentication_method: 'password', claims: {
    ...initialClaims(), email: 'current@example.test' } }));
  assert.deepEqual((await allowed.json() as { claims: unknown }).claims, { ...initialClaims(), email: 'current@example.test' });
  assert.deepEqual(pending.calls, ['lookup:user-1', 'ownership', 'assert:current@example.test']);
});

test('custom token hook rejects subject mismatch and an active user email that changed outside coordinator', async () => {
  const mismatch = fixture();
  const badSub = { ...initialClaims(), sub: 'different-subject' };
  const response = await mismatch.adapter.customAccessToken(signedRequest({ user_id: 'user-1', authentication_method: 'password', claims: badSub }));
  assert.ok((await response.json() as { error?: unknown }).error);
  assert.deepEqual(mismatch.calls, []);

  const changed = fixture();
  changed.setOwnership({ status: 'active', canonical: 'old@example.test', policyVersion: 'test', revision: '2' });
  const response2 = await changed.adapter.customAccessToken(signedRequest({ user_id: 'user-1', authentication_method: 'password', claims: initialClaims() }));
  assert.ok((await response2.json() as { error?: unknown }).error);
  assert.deepEqual(changed.calls, ['lookup:user-1', 'ownership']);

  const mismatchedEmail = fixture();
  const emailMismatch = await mismatchedEmail.adapter.customAccessToken(signedRequest({ user_id: 'user-1', authentication_method: 'password', claims: {
    ...initialClaims(), email: 'other@example.test' } }));
  assert.ok((await emailMismatch.json() as { error?: unknown }).error);
  assert.deepEqual(mismatchedEmail.calls, ['lookup:user-1']);
});

test('hook signature requires exact raw body, fresh timestamp, and unique replay ID', async () => {
  const f = fixture();
  const payload = { user: { email: 'safe@example.test' } };
  const request = signedRequest(payload, 'delivery-1');
  assert.equal((await f.adapter.beforeUserCreated(request)).status, 200);
  const replay = await f.adapter.beforeUserCreated(signedRequest(payload, 'delivery-1'));
  assert.ok((await replay.json() as { error?: unknown }).error);

  const stale = await f.adapter.beforeUserCreated(signedRequest(payload, 'delivery-2', '1'));
  assert.ok((await stale.json() as { error?: unknown }).error);

  const tampered = signedRequest(payload, 'delivery-3');
  const body = JSON.stringify({ user: { email: 'changed@example.test' } });
  const broken = new Request(tampered.url, { method: 'POST', headers: tampered.headers, body });
  assert.ok((await (await f.adapter.beforeUserCreated(broken)).json() as { error?: unknown }).error);
});

test('hook body and provider lookup obey configured size and deadline bounds', async () => {
  const small = fixture(undefined, { maxBodyBytes: 80 });
  const tooLarge = await small.adapter.beforeUserCreated(signedRequest({ user: { email: 'x'.repeat(100) } }));
  assert.ok((await tooLarge.json() as { error?: unknown }).error);

  const core = {
    async screenSignup() { return prepareEmail('safe@example.test'); },
    async claimVerified() { return prepareEmail('safe@example.test'); },
    async assertActive() { return prepareEmail('safe@example.test'); },
    async getOwnership() { return { status: 'unclaimed' } as const; },
  };
  const slow = createSupabaseGate({ tenantId: 'tenant-fixed', gate: core, webhookSecret: secret, hookTimeoutMs: 20,
    async getUserById() { return await new Promise<null>(resolve => setTimeout(() => resolve(null), 100)); } });
  const started = Date.now();
  const timedOut = await slow.customAccessToken(signedRequest({ user_id: 'user-1', authentication_method: 'password', claims: initialClaims() }));
  assert.ok(Date.now() - started < 80);
  assert.ok((await timedOut.json() as { error?: unknown }).error);
});

test('empty chunks cannot evade body bounds and Supabase v1,whsec secret prefix is accepted', async () => {
  const f = fixture(undefined, { maxBodyBytes: 128, webhookSecret: `v1,${secret}` });
  const signed = signedRequest({ user: { email: 'x@example.test' } }, 'empty-chunks');
  const body = await signed.text();
  const headers = new Headers(signed.headers);
  const emptyBody = new ReadableStream<Uint8Array>({ start(controller) {
    for (let i = 0; i < 40; i++) controller.enqueue(new Uint8Array(0));
    controller.enqueue(new TextEncoder().encode(body));
    controller.close();
  } });
  const request = new Request(signed.url, { method: 'POST', headers, body: emptyBody, duplex: 'half' } as RequestInit);
  assert.ok((await (await f.adapter.beforeUserCreated(request)).json() as { error?: unknown }).error);

  const f2 = fixture(undefined, { webhookSecret: `v1,${secret}` });
  assert.deepEqual(await (await f2.adapter.beforeUserCreated(signedRequest({ user: { email: 'x@example.test' } }, 'prefixed-secret'))).json(), {});
});

test('protected requests require a fresh provider lookup and registry ownership', async () => {
  const f = fixture();
  await assert.rejects(f.adapter.assertActive('access-token'));
  const tokenHook = await f.adapter.customAccessToken(signedRequest({ user_id: 'user-1', authentication_method: 'password', claims: initialClaims() }));
  assert.equal(tokenHook.status, 200);
  assert.equal((await f.adapter.assertActive('live-token')).id, 'user-1');
  assert.deepEqual(f.calls.slice(-2), ['token:live-token', 'assert:current@example.test']);
});


test('replay IDs cover future-dated signatures and overload denies without evicting live IDs', async () => {
  let now = Math.floor(Date.now() / 1000) * 1000;
  const f = fixture(undefined, { now: () => now, maxSignatureAgeSeconds: 10, maxReplayIds: 1 });
  const id = randomUUID();
  const timestamp = String(now / 1000 + 10);
  const payload = { user: { email: 'capacity@example.test' } };
  assert.deepEqual(await (await f.adapter.beforeUserCreated(signedRequest(payload, id, timestamp))).json(), {});
  now += 11_000;
  assert.ok((await (await f.adapter.beforeUserCreated(signedRequest(payload, id, timestamp))).json() as { error?: unknown }).error);
  const overloaded = await (await f.adapter.beforeUserCreated(signedRequest(payload, randomUUID(), String(now / 1000)))).json() as { error: { http_code: number } };
  assert.equal(overloaded.error.http_code, 503);
  assert.equal(f.calls.length, 1);
  now += 10_000;
  assert.deepEqual(await (await f.adapter.beforeUserCreated(signedRequest(payload, randomUUID(), String(now / 1000)))).json(), {});
});
