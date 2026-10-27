import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createGate } from '../src/core/engine.js';
import { IronDomeClientError } from '../src/core/irondome.js';
import { GateError } from '../src/core/errors.js';
import { prepareEmail, POLICY_VERSION } from '../src/core/policy.js';
import { MemoryRegistry } from './memory-registry.js';

const allow = { screen: async () => ({ allowed: true, reason: 'not_listed' }) };
const isCode = (code: string) => (error: unknown) => error instanceof GateError && error.code === code;
const user = { tenantId: 'tenant-one', userId: 'user-1', email: 'First.Last+tag@Gmail.com' };

test('strict syntax rejects malformed inputs, wrappers and cleanup before paid screening', async () => {
  let calls = 0;
  const gate = createGate({ registry: new MemoryRegistry(), screening: { screen: async () => { calls++; return { allowed: true, reason: 'not_listed' }; } } });
  for (const email of ['', null, undefined, 42, {}, 'Name <a@example.com>', ' a@example.com', 'a@example.com ',
    'mailto:a@example.com', 'a\u200b@example.com', 'a\n@example.com', 'a..b@example.com', 'a@xn--gmail-.com',
    `${'x'.repeat(65)}@example.com`, '\ud800@example.com', 'user@localhost', 'a@b.com?query']) {
    await assert.rejects(gate.screenSignup({ tenantId: 'tenant-one', email }), isCode('invalid_email'));
  }
  assert.equal(calls, 0);
});

test('very large signup input is rejected before screening', async () => {
  let calls = 0;
  const gate = createGate({ registry: new MemoryRegistry(), screening: { screen: async () => {
    calls++;
    return { allowed: true, reason: 'not_listed' };
  } } });
  await assert.rejects(gate.screenSignup({ tenantId: 'tenant-one', email: 'x'.repeat(10_000_000) }), isCode('invalid_email'));
  assert.equal(calls, 0);
});

test('Gmail verified equivalence is independent from exact delivery destination', () => {
  const p = prepareEmail(user.email);
  assert.equal(p.canonical, 'firstlast@gmail.com');
  assert.equal(p.deliveryEmail, user.email);
  assert.equal(prepareEmail('first.last+other@googlemail.com').canonical, p.canonical);
  assert.equal(Object.isFrozen(p), true);
});

test('v2 preserves Gate-specific Apple, Yahoo, Gmail and custom mailbox policy', () => {
  const pairs = [
    ['Name@example.com','name@example.com'], ['a+b@example.com','a@example.com'],
    ['first.last@workspace.example','firstlast@workspace.example'],
    ['a@icloud.com','a@me.com'], ['a@icloud.com','a@mac.com'],
    ['a-tag@yahoo.com','a@yahoo.com'],
  ];
  for (const [a,b] of pairs) assert.notEqual(prepareEmail(a).canonical, prepareEmail(b).canonical);
  assert.equal(prepareEmail('Alice+tag@gmail.com').canonical, prepareEmail('alice@gmail.com').canonical);
  assert.equal(prepareEmail('A.B+tag@outlook.com').canonical, 'a.b@outlook.com');
  assert.notEqual(prepareEmail('A.B+tag@outlook.com').canonical, prepareEmail('a.b@hotmail.com').canonical);
  assert.equal(prepareEmail('User@EXAMPLE.COM').canonical, 'User@example.com');
  assert.equal(prepareEmail('User@bücher.de').canonical, 'User@xn--bcher-kva.de');
});

test('preverification screening sends original email and never reserves ownership', async () => {
  const registry = new MemoryRegistry();
  const addresses: string[] = [];
  const gate = createGate({ registry, screening: { screen: async email => { addresses.push(email); return { allowed: true, reason: 'allowed_domain' }; } } });
  await Promise.all(Array.from({length: 30}, () => gate.screenSignup(user)));
  assert.deepEqual(new Set(addresses), new Set([user.email]));
  assert.equal(registry.size, 0);
  await assert.rejects(gate.assertActive(user), isCode('ownership_required'));
});

test('concurrent verified equivalent claims: one owner, other account never active', async () => {
  const registry = new MemoryRegistry();
  const gate = createGate({ registry, screening: allow });
  const attempts = Array.from({length: 100}, (_, i) => ({ ...user, userId: `user-${i}`, email: `first.last+${i}@gmail.com` }));
  const results = await Promise.allSettled(attempts.map(value => gate.claimVerified(value)));
  assert.equal(results.filter(x => x.status === 'fulfilled').length, 1);
  assert.equal(results.filter(x => x.status === 'rejected' && isCode('identity_conflict')(x.reason)).length, 99);
  assert.equal(registry.size, 1);
  const sessions = await Promise.allSettled(attempts.map(value => gate.assertActive(value)));
  assert.equal(sessions.filter(x => x.status === 'fulfilled').length, 1);
});

test('same user retry idempotence and tenant isolation', async () => {
  const registry = new MemoryRegistry();
  const gate = createGate({ registry, screening: allow });
  await Promise.all(Array.from({length:20}, () => gate.claimVerified(user)));
  await gate.claimVerified({ ...user, tenantId: 'tenant-two', userId: 'other-user' });
  assert.equal(registry.size, 2);
  await gate.assertActive(user);
});

test('verified change cannot release old ownership on conflict or failed screening', async () => {
  const registry = new MemoryRegistry();
  const gate = createGate({ registry, screening: allow });
  await gate.claimVerified(user);
  await gate.claimVerified({ ...user, userId: 'user-other', email: 'new@example.com' });
  await assert.rejects(gate.claimVerified({ ...user, email: 'new@example.com' }), isCode('identity_conflict'));
  await gate.assertActive(user);
  const denied = createGate({ registry, screening: {screen: async () => ({allowed:false, reason:'blocked_domain'})} });
  await assert.rejects(denied.claimVerified({...user, email:'blocked@example.com'}), isCode('screening_blocked'));
  await gate.assertActive(user);
  // V1 intentionally rejects implicit replacement: stale callback retries cannot change identity.
  await assert.rejects(gate.claimVerified({ ...user, email: 'available@example.com' }), isCode('identity_conflict'));
  await gate.assertActive(user);
  await assert.rejects(gate.assertActive({ ...user, email: 'available@example.com' }), isCode('ownership_required'));
});

test('network/storage failure never allows claim or activity and errors omit PII', async () => {
  const registry = new MemoryRegistry();
  const offline = createGate({registry, screening: {screen: async () => {throw new Error(user.email);} }});
  await assert.rejects(offline.claimVerified(user), (error: unknown) => {
    assert.ok(error instanceof GateError);
    assert.equal(error.code, 'screening_unavailable');
    assert.equal(error.retryable, true);
    assert.equal(JSON.stringify(error).includes(user.email), false);
    assert.equal(error.cause, undefined);
    return true;
  });
  assert.equal(registry.size, 0);
  const broken = createGate({registry:{claim:async()=>{throw new Error(user.email)}, owns:async()=>{throw new Error(user.email)},releaseUser:async()=>{}},screening:allow});
  await assert.rejects(broken.claimVerified(user), isCode('storage_unavailable'));
  await assert.rejects(broken.assertActive(user), isCode('storage_unavailable'));
});

test('invalid tenant/user context is rejected before I/O', async () => {
  let calls = 0;
  const gate = createGate({registry:new MemoryRegistry(),screening:{screen:async()=>{calls++;return {allowed:true,reason:'not_listed'}}}});
  for (const tenantId of ['', 'a\n', "x'); DROP TABLE x; --", undefined]) {
    await assert.rejects(gate.screenSignup({...user, tenantId:tenantId as string}), isCode('invalid_context'));
  }
  for (const userId of ['', undefined, 'x\n']) {
    await assert.rejects(gate.claimVerified({...user,userId:userId as string}), isCode('invalid_context'));
  }
  assert.equal(calls,0);
});

test('policy version is metadata, not uniqueness namespace; cleanup permits new verified owner only', async () => {
  const registry = new MemoryRegistry();
  const identity = {tenantId:'tenant',userId:'u1',canonical:'test@example.com',policyVersion:POLICY_VERSION};
  assert.equal(await registry.claim(identity),'claimed');
  assert.equal(await registry.claim({...identity,userId:'u2',policyVersion:'future-v2'}),'conflict');
  await registry.releaseUser({tenantId:'tenant',userId:'u1'});
  await registry.releaseUser({tenantId:'tenant',userId:'u1'});
  assert.equal(await registry.claim({...identity,userId:'u2'}),'claimed');
});


test('maximum delivery and canonical lengths reject before billing; permanent errors stay permanent', async () => {
  let calls = 0;
  const oversized = 'x'.repeat(64) + '@' + ['a'.repeat(63),'b'.repeat(63),'c'.repeat(63),'d'.repeat(28)].join('.');
  const gate = createGate({registry:new MemoryRegistry(),screening:{screen:async()=>{calls++;return {allowed:true,reason:'not_listed'}}}});
  await assert.rejects(gate.screenSignup({...user,email:oversized}), isCode('invalid_email'));
  assert.equal(calls,0);
  for (const status of [401,403,429]) {
    const blocked = createGate({registry:new MemoryRegistry(),screening:{screen:async()=>{throw new IronDomeClientError('api',false,status)}}});
    await assert.rejects(blocked.screenSignup(user), (error:unknown) => error instanceof GateError && error.code === 'screening_unavailable' && !error.retryable);
  }
  const invalid = createGate({registry:new MemoryRegistry(),screening:{screen:async()=>{throw new IronDomeClientError('invalid_email',false,422)}}});
  await assert.rejects(invalid.screenSignup(user),isCode('invalid_email'));
});


test('engine honors cancellation even when injected screening ignores abort', async () => {
  const registry = new MemoryRegistry();
  const gate = createGate({registry,screening:allow});
  await assert.rejects(gate.claimVerified({...user,signal:AbortSignal.abort()}),isCode('cancelled'));
  assert.equal(registry.size,0);
  const controller = new AbortController();
  const during = createGate({registry,screening:{screen:async()=>{controller.abort();return {allowed:true,reason:'not_listed'}}}});
  await assert.rejects(during.claimVerified({...user,signal:controller.signal}),isCode('cancelled'));
  assert.equal(registry.size,0);
  const afterWrite = new AbortController();
  const uncertain = createGate({screening:allow,registry:{...registry,
    claim:async input=>{const value=await registry.claim(input);afterWrite.abort();return value;},
    owns:input=>registry.owns(input),releaseUser:input=>registry.releaseUser(input)}});
  await assert.rejects(uncertain.claimVerified({...user,signal:afterWrite.signal}),isCode('cancelled'));
  assert.equal(registry.size,1); // A begun write cannot be undone just by cancelling the caller.
  await gate.claimVerified(user);
  await gate.assertActive(user);
});


test('async proof context cannot change when the caller mutates its request object', async () => {
  const registry = new MemoryRegistry();
  let resolve!: (value: {allowed:boolean;reason:string}) => void;
  const gate = createGate({registry,screening:{screen:()=>new Promise(done=>{resolve=done})}});
  const input = {...user};
  const pending = gate.claimVerified(input);
  input.tenantId='other-tenant'; input.userId='other-user'; input.email='other@example.com';
  resolve({allowed:true,reason:'not_listed'});
  await pending;
  await gate.assertActive(user);
  await assert.rejects(gate.assertActive(input),isCode('ownership_required'));
});

test('opaque provider subjects retain pipes and byte bounds without truncation', async () => {
  const registry = new MemoryRegistry();
  const gate = createGate({ registry, screening: allow });
  for (const userId of ['auth0|12345', 'google-oauth2|a|b', 'samlp|connection|' + 'x'.repeat(255)]) {
    await gate.claimVerified({ ...user, userId, tenantId: 'provider-' + userId.length });
    await gate.assertActive({ ...user, userId, tenantId: 'provider-' + userId.length });
  }
  for (const userId of ['x'.repeat(513), 'é'.repeat(257), 'bad\ud800', 'bad\0subject', 'bad subject']) {
    await assert.rejects(gate.claimVerified({ ...user, userId }), isCode('invalid_context'));
  }
});
