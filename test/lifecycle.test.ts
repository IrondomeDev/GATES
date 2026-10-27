import assert from 'node:assert/strict';
import test from 'node:test';
import { createLifecycleGate } from '../src/core/lifecycle.js';
import type { LifecycleIdentityRegistry } from '../src/core/registry.js';

function fixture() {
  const calls: unknown[] = [];
  const registry: LifecycleIdentityRegistry = {
    async claim() { return 'claimed'; }, async owns() { return true; }, async releaseUser() {},
    async getOwnership() { return { status: 'unclaimed' }; },
    async replaceVerified(input) { calls.push(input); return 'replaced'; },
    async revokeUser(input) { calls.push(input); return 'revoked'; },
  };
  return { registry, calls };
}
const user = { tenantId: 't', userId: 'u', email: 'new@example.com', expectedRevision: '1' };
test('lifecycle snapshots user and revision before asynchronous screening', async () => {
  const { registry, calls } = fixture();
  let resolve!: () => void;
  const pending = new Promise<void>(done => { resolve = done; });
  const options = { registry, screening: { async screen() { await pending; return { allowed: true, reason: 'not_listed' }; } } };
  const gate = createLifecycleGate(options);
  const mutable = { ...user };
  const result = gate.changeVerifiedEmail(mutable);
  mutable.userId = 'changed'; mutable.expectedRevision = '2'; mutable.email = 'changed@example.com';
  resolve(); await result;
  assert.deepEqual(calls, [{ tenantId: user.tenantId, userId: user.userId, canonical: user.email,
    policyVersion: (await gate.screenSignup(user)).policyVersion, expectedRevision: '1' }]);
});
test('lifecycle rejects bad revisions and pre-cancellation before external work', async () => {
  const { registry, calls } = fixture();
  let screened = 0;
  const gate = createLifecycleGate({ registry, screening: { async screen() { screened++; return { allowed: true, reason: 'not_listed' }; } } });
  for (const revision of ['0', '01', '-1', '1.1', '9223372036854775807']) await assert.rejects(gate.changeVerifiedEmail({ ...user, expectedRevision: revision }), { code: 'invalid_context' });
  const signal = AbortSignal.abort('sensitive');
  await assert.rejects(gate.changeVerifiedEmail({ ...user, signal }), { code: 'cancelled' });
  await assert.rejects(gate.revokeUser({ ...user, signal }), { code: 'cancelled' });
  assert.equal(screened, 0); assert.equal(calls.length, 0);
});
test('lifecycle sanitizes storage failure and maps revoked/stale outcomes', async () => {
  const { registry } = fixture();
  const screening = { async screen() { return { allowed: true, reason: 'not_listed' }; } };
  const secretError = new Error('synthetic@example.com synthetic-secret');
  const gate = createLifecycleGate({ registry: { ...registry,
    async replaceVerified() { throw secretError; }, async revokeUser() { throw secretError; }, async getOwnership() { throw secretError; } }, screening });
  for (const work of [() => gate.getOwnership(user), () => gate.revokeUser(user), () => gate.changeVerifiedEmail(user)]) {
    await assert.rejects(work(), error => {
      assert.equal((error as { code: string }).code, 'storage_unavailable');
      assert.doesNotMatch(String(error), /synthetic/);
      assert.equal((error as Error).cause, undefined);
      return true;
    });
  }
  for (const [result, code] of [['stale', 'stale_revision'], ['revoked', 'identity_revoked'], ['conflict', 'identity_conflict']] as const) {
    const denied = createLifecycleGate({ registry: { ...registry, async replaceVerified() { return result; } }, screening });
    await assert.rejects(denied.changeVerifiedEmail(user), { code });
  }
});
