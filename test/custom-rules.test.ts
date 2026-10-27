import assert from 'node:assert/strict';
import test from 'node:test';
import { createEmailPolicy, DEFAULT_EMAIL_POLICY, POLICY_VERSION, prepareEmail, type DomainCanonicalRules } from '../src/core/policy.js';
import { createGate } from '../src/core/engine.js';
import { GateError } from '../src/core/errors.js';
import { dryRunBackfill, applyBackfill } from '../src/migration/backfill.js';
import { MemoryRegistry } from './memory-registry.js';

const rules = { 'company.com': { lowercase: true, stripPlusTag: true, stripDots: true } };
const invalidEmail = (error: unknown) => error instanceof GateError && error.code === 'invalid_email';

test('custom domain rules preserve delivery, match exact domains, and produce idempotent keys', () => {
  const policy = createEmailPolicy(rules);
  const delivery = 'First.Last+newsletter@COMPANY.COM';
  const result = policy.prepareEmail(delivery);
  assert.equal(result.deliveryEmail, delivery);
  assert.equal(result.canonical, 'firstlast@company.com');
  assert.equal(result.domain, 'company.com');
  assert.equal(result.policyVersion, policy.version);
  assert.equal(policy.prepareEmail(result.canonical).canonical, result.canonical);
  assert.equal(Object.isFrozen(result), true);
  for (const domain of ['sub.company.com', 'othercompany.com', 'company.net', 'company.com.evil.test']) {
    assert.equal(policy.prepareEmail(`First.Last+tag@${domain}`).canonical, `First.Last+tag@${domain}`);
  }
  assert.equal(prepareEmail(delivery).canonical, 'First.Last+newsletter@company.com', 'global default is unchanged');
});

test('each custom transform can be enabled independently without changing other spelling', () => {
  for (const [rule, expected] of [
    [{ lowercase: true }, 'first.last+tag@company.com'],
    [{ stripPlusTag: true }, 'First.Last@company.com'],
    [{ stripDots: true }, 'FirstLast+tag@company.com'],
  ] as const) {
    assert.equal(createEmailPolicy({ 'company.com': rule }).prepareEmail('First.Last+Tag@company.com').canonical,
      expected.replace('+tag', rule.lowercase ? '+tag' : '+Tag'));
  }
});

test('custom policy composes with built-ins and Fastmail canonical domains', () => {
  const policy = createEmailPolicy({ 'fastmail.com': { stripDots: true }, 'gmail.com': { lowercase: true } });
  const direct = policy.prepareEmail('A.B+tag@fastmail.com');
  const alias = policy.prepareEmail('tag@a.b.fastmail.com');
  // Only one Fastmail subdomain level is supported; a.b is deliberately not an alias.
  assert.equal(direct.canonical, 'ab@fastmail.com');
  assert.notEqual(alias.canonical, direct.canonical);
  assert.equal(policy.prepareEmail('tag@alice.fastmail.com').canonical,
    policy.prepareEmail('alice+tag@fastmail.com').canonical);
  assert.equal(policy.prepareEmail('First.Last+tag@googlemail.com').canonical, 'firstlast@gmail.com');
});

test('policy versions fingerprint normalized settings independently of object order and mutation', () => {
  const mutable = { 'COMPANY.COM': { stripDots: true, lowercase: true }, 'other.com': { stripPlusTag: true } };
  const policy = createEmailPolicy(mutable);
  const reordered = createEmailPolicy({ 'other.com': { stripPlusTag: true }, 'company.com': { lowercase: true, stripDots: true, stripPlusTag: false } });
  assert.equal(policy.version, reordered.version);
  assert.notEqual(policy.version, POLICY_VERSION);
  assert.ok(policy.version.length <= 128);
  mutable['COMPANY.COM'].stripDots = false;
  mutable['COMPANY.COM'].lowercase = false;
  mutable['other.com'].stripPlusTag = false;
  assert.equal(policy.prepareEmail('A.B@company.com').canonical, 'ab@company.com');
  assert.equal(policy.version, reordered.version);
  assert.notEqual(createEmailPolicy(mutable).version, policy.version);
  assert.equal(Object.isFrozen(policy), true);
  assert.equal(createEmailPolicy(), DEFAULT_EMAIL_POLICY);
  assert.equal(createEmailPolicy({ 'company.com': { lowercase: false } }), DEFAULT_EMAIL_POLICY);
});

test('IDNA domain rules normalize once and reject duplicate normalized domains', () => {
  const unicode = createEmailPolicy({ 'bücher.example': { lowercase: true } });
  const ascii = createEmailPolicy({ 'xn--bcher-kva.example': { lowercase: true } });
  assert.equal(unicode.version, ascii.version);
  assert.equal(unicode.prepareEmail('Name@bücher.example').canonical, 'name@xn--bcher-kva.example');
  assert.throws(() => createEmailPolicy({ 'COMPANY.COM': { lowercase: true }, 'company.com': { stripDots: true } }), TypeError);
  const longest = [63, 63, 63, 60].map(length => 'a'.repeat(length)).join('.');
  assert.equal(createEmailPolicy({ [longest]: { lowercase: true } }).prepareEmail(`X@${longest}`).canonical, `x@${longest}`);
});

test('rule configuration rejects ambiguous domains, unknown flags, callbacks, accessors and unbounded maps', () => {
  const invalid: unknown[] = [null, [], new Map(), { '*.company.com': { lowercase: true } },
    { '.company.com': { lowercase: true } }, { 'company.com.': { lowercase: true } },
    { 'a@company.com': { lowercase: true } }, { 'company.com/path': { lowercase: true } },
    { 'googlemail.com': { stripDots: true } }, { 'alice.fastmail.com': { stripDots: true } },
    { 'company.com': { stripDotes: true } }, { 'company.com': { lowercase: 'true' } },
    { 'company.com': { lowercase: undefined } }, { 'company.com': () => 'anything' },
    Object.create({ 'company.com': { lowercase: true } }),
    Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`company${i}.com`, { lowercase: true }])),
  ];
  let accessed = false;
  invalid.push({ get 'company.com'() { accessed = true; return { lowercase: true }; } });
  for (const value of invalid) assert.throws(() => createEmailPolicy(value as DomainCanonicalRules), TypeError);
  assert.equal(accessed, false);
});

test('custom rules retain strict validation and cannot create empty or non-idempotent mailbox keys', () => {
  const policy = createEmailPolicy(rules);
  for (const value of ['+tag@company.com', '.+tag@company.com', 'bad..name@company.com', ' bad@company.com', 'a@company.com\n']) {
    assert.throws(() => policy.prepareEmail(value), invalidEmail);
  }
  const plusOnly = createEmailPolicy({ 'company.com': { stripPlusTag: true } });
  assert.throws(() => plusOnly.prepareEmail('a.+tag@company.com'), invalidEmail);
  assert.equal(policy.prepareEmail('a.+tag@company.com').canonical, 'a@company.com');
});

test('one engine setting enforces alias collisions, tenant isolation and original screening delivery', async () => {
  const screened: string[] = [];
  const gate = createGate({ registry: new MemoryRegistry(), canonicalRules: rules,
    screening: { async screen(email) { screened.push(email); return { allowed: true, reason: 'not_listed' }; } } });
  const first = { tenantId: 't', userId: 'first', email: 'First.Last+one@company.com' };
  await gate.claimVerified(first);
  await gate.assertActive({ ...first, email: 'firstlast+two@company.com' });
  await assert.rejects(gate.claimVerified({ ...first, userId: 'second', email: 'firstlast+two@company.com' }),
    (error: unknown) => error instanceof GateError && error.code === 'identity_conflict');
  await gate.claimVerified({ ...first, tenantId: 'other', userId: 'second', email: 'firstlast@company.com' });
  assert.equal(screened[0], first.email);
  assert.equal(gate.emailPolicy.prepareEmail(first.email).canonical, 'firstlast@company.com');
});

test('backfill audit and application inherit the engine rules before any screening or writes', async () => {
  let screened = 0;
  const registry = new MemoryRegistry();
  const gate = createGate({ registry, canonicalRules: rules,
    screening: { async screen() { screened++; return { allowed: true, reason: 'not_listed' }; } } });
  const rows = [
    { tenantId: 't', userId: 'a', email: 'First.Last+one@company.com', emailVerified: true },
    { tenantId: 't', userId: 'b', email: 'firstlast@company.com', emailVerified: true },
  ];
  assert.equal(dryRunBackfill(rows).ready, true, 'the default policy has separate identities');
  const audit = dryRunBackfill(rows, gate);
  assert.deepEqual(audit.collisionRows, [[0, 1]]);
  assert.equal(audit.policyVersion, gate.emailPolicy.version);
  const applied = await applyBackfill(gate, rows, { async revalidate() { return true; } });
  assert.equal(applied.complete, false);
  assert.equal(applied.attempted, 0);
  assert.deepEqual(applied.audit.collisionRows, [[0, 1]]);
  assert.equal(screened, 0);
  assert.equal(registry.size, 0);
});
