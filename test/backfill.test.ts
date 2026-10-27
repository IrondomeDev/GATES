import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createGate } from '../src/core/engine.js';
import { applyBackfill, dryRunBackfill, type BackfillRow } from '../src/migration/backfill.js';
import { MemoryRegistry } from './memory-registry.js';
const row = {tenantId:'t',userId:'u',email:'first.last@gmail.com',emailVerified:true};
test('dry-run finds equivalent collisions; pending accounts never reserve ownership', () => {
  const report = dryRunBackfill([row,{...row,userId:'other',email:'firstlast+tag@googlemail.com'},
    {...row,userId:'pending',emailVerified:false},{...row,tenantId:'other-tenant'}]);
  assert.deepEqual(report.collisionRows, [[0,1]]);
  assert.equal(report.pendingSkipped,1);
  assert.equal(report.verifiedEligible,3);
  assert.equal(report.ready,false);
  assert.equal(JSON.stringify(report).includes('gmail'),false);
});
test('dry-run reports invalid rows and duplicate users instead of selecting winner', () => {
  const report = dryRunBackfill([row,{...row,email:'different@example.com'},{...row,email:'not-email'},
    {...row,emailVerified:'true' as unknown as boolean}]);
  assert.deepEqual(report.duplicateUserRows,[[0,1]]);
  assert.deepEqual(report.invalidRows,[2,3]);
  assert.equal(report.ready,false);
});
test('clean dry-run performs no writes and never links custom/Apple aliases', () => {
  const rows = ['Name@me.com','Name@icloud.com','Name@custom.example','name@custom.example']
    .map((email,index)=>({...row,userId:`u${index}`,email}));
  const before = structuredClone(rows);
  assert.equal(dryRunBackfill(rows).ready,true);
  assert.deepEqual(rows,before);
});

function fakeGate(hooks: { claim?: (row: { tenantId: string; userId: string; email: unknown }) => Promise<unknown>;
  active?: (row: { tenantId: string; userId: string; email: unknown }) => Promise<unknown> } = {}) {
  const calls: string[] = [];
  return { calls, gate: {
    async claimVerified(input: { tenantId: string; userId: string; email: unknown }) {
      calls.push(`claim:${input.userId}`);
      await hooks.claim?.(input);
      return {};
    },
    async assertActive(input: { tenantId: string; userId: string; email: unknown }) {
      calls.push(`active:${input.userId}`);
      await hooks.active?.(input);
      return {};
    },
  } as unknown as import('../src/core/engine.js').Gate };
}
const applyRows: BackfillRow[] = [
  { tenantId: 't', userId: 'a', email: 'a@example.com', emailVerified: true },
  { tenantId: 't', userId: 'pending', email: 'p@example.com', emailVerified: false },
  { tenantId: 't', userId: 'b', email: 'b@example.com', emailVerified: true },
];

test('apply audits full input before writes and pending rows are excluded', async () => {
  const { gate, calls } = fakeGate();
  const result = await applyBackfill(gate, [applyRows[0]!, { ...applyRows[0]!, userId: 'collision' }, applyRows[1]!], {
    revalidate: async () => { throw new Error('must not run'); },
  });
  assert.equal(result.audit.ready, false);
  assert.deepEqual(result.audit.collisionRows, [[0, 1]]);
  assert.equal(result.attempted, 0);
  assert.deepEqual(calls, []);

  const clean = await applyBackfill(gate, applyRows, { revalidate: async row => row.emailVerified });
  assert.equal(clean.complete, true);
  assert.equal(clean.audit.pendingSkipped, 1);
  assert.deepEqual(clean.completedRowIndexes, [0, 2]);
  assert.equal(calls.some(value => value === 'claim:pending'), false);

  const sparse = new Array(2) as BackfillRow[];
  sparse[1] = applyRows[0]!;
  const sparseResult = await applyBackfill(gate, sparse, { revalidate: async () => true });
  assert.equal(sparseResult.audit.ready, false);
  assert.deepEqual(sparseResult.audit.invalidRows, [0]);
  assert.equal(sparseResult.attempted, 0);
});

test('provider mismatch prevents writes and report contains no row values', async () => {
  const { gate, calls } = fakeGate();
  const result = await applyBackfill(gate, [applyRows[0]!], { revalidate: async () => false });
  assert.equal(result.complete, false);
  assert.deepEqual(result.failures, [{ index: 0, code: 'revalidation_mismatch' }]);
  assert.deepEqual(calls, []);
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes('a@example.com'), false);
  assert.equal(serialized.includes('userId'), false);
});

test('partial failure stops new scheduling, waits for started work, and is resumable', async () => {
  const started: string[] = [];
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const { gate, calls } = fakeGate({ claim: async row => {
    if (row.userId === 'a') { started.push('a'); await held; }
    if (row.userId === 'b') throw new Error('PII user b@example.com');
  } });
  const promise = applyBackfill(gate, applyRows, { concurrency: 2, revalidate: async () => true });
  while (!started.length) await new Promise(resolve => setTimeout(resolve, 0));
  await new Promise(resolve => setTimeout(resolve, 0));
  release();
  const partial = await promise;
  assert.equal(partial.complete, false);
  assert.deepEqual(partial.completedRowIndexes, [0]);
  assert.deepEqual(partial.failures, [{ index: 2, code: 'apply_failed' }]);
  assert.equal(partial.attempted, 2);
  assert.equal(JSON.stringify(partial).includes('PII'), false);
  const retry = await applyBackfill(gate, applyRows.filter(r => r.userId === 'a'), { revalidate: async () => true });
  assert.equal(retry.complete, true);
  assert.ok(calls.includes('active:a'));
});

test('apply respects concurrency, cancellation, and typed error scrubbing', async () => {
  let active = 0;
  let maximum = 0;
  const { gate } = fakeGate({ claim: async () => {
    active++;
    maximum = Math.max(maximum, active);
    await new Promise(resolve => setTimeout(resolve, 5));
    active--;
    const error = new Error('raw secret user/email');
    Object.assign(error, { code: 'storage_unavailable' });
    throw error;
  } });
  const result = await applyBackfill(gate, applyRows, { concurrency: 2, revalidate: async () => true });
  assert.equal(maximum, 2);
  assert.equal(result.complete, false);
  assert.deepEqual(result.failures, [{ index: 0, code: 'storage_unavailable' }, { index: 2, code: 'storage_unavailable' }]);
  assert.equal(JSON.stringify(result).includes('raw secret'), false);

  const controller = new AbortController();
  let revalidated!: () => void;
  const wait = new Promise<void>(resolve => { revalidated = resolve; });
  const heldGate = fakeGate({ claim: async () => { await wait; } });
  const cancelled = applyBackfill(heldGate.gate, applyRows, { concurrency: 1, signal: controller.signal,
    revalidate: async () => { controller.abort(); return true; } });
  const cancelledResult = await cancelled;
  revalidated();
  assert.deepEqual(cancelledResult.failures, [{ index: 0, code: 'cancelled' }]);
  assert.equal(cancelledResult.attempted, 1);
});

test('apply snapshots all rows before awaiting revalidation and rejects oversized input', async () => {
  const mutable = { ...applyRows[0]! };
  let resume!: () => void;
  const hold = new Promise<void>(resolve => { resume = resolve; });
  let validationCalls = 0;
  const { gate, calls } = fakeGate();
  const options = { concurrency: 1, revalidate: async (row: Readonly<BackfillRow>) => {
    validationCalls++;
    assert.equal(row.email, validationCalls === 1 ? 'a@example.com' : 'b@example.com');
    assert.equal(Object.isFrozen(row), true);
    if (validationCalls === 1) await hold;
    return true;
  } };
  const pending = applyBackfill(gate, [mutable, applyRows[2]!], options);
  mutable.email = 'changed@example.com';
  options.revalidate = async () => false;
  resume();
  assert.equal((await pending).complete, true);
  assert.equal(validationCalls, 2);
  assert.ok(calls.some(value => value === 'claim:a'));

  const oversized = new Array(100_001).fill(applyRows[0]);
  const limited = await applyBackfill(gate, oversized, { revalidate: async () => true });
  assert.equal(limited.limitExceeded, true);
  assert.equal(limited.attempted, 0);
});

test('real Gate and MemoryRegistry make same-owner apply reruns idempotent', async () => {
  const registry = new MemoryRegistry();
  const gate = createGate({ registry, screening: { screen: async () => ({ allowed: true, reason: 'not_listed' }) } });
  let validations = 0;
  const first = await applyBackfill(gate, applyRows.filter(row => row.emailVerified), {
    revalidate: async () => { validations++; return true; }, concurrency: 1,
  });
  assert.equal(first.complete, true);
  assert.deepEqual(first.completedRowIndexes, [0, 1]);
  const second = await applyBackfill(gate, applyRows.filter(row => row.emailVerified), {
    revalidate: async () => { validations++; return true; }, concurrency: 1,
  });
  assert.equal(second.complete, true);
  assert.deepEqual(second.completedRowIndexes, [0, 1]);
  assert.equal(validations, 4);
});

test('cancelled empty backfill is not reported as a completed job', async () => {
  const { gate } = fakeGate();
  const result = await applyBackfill(gate, [], { signal: AbortSignal.abort(), revalidate: async () => true });
  assert.equal(result.complete, false);
  assert.equal(result.attempted, 0);
});
