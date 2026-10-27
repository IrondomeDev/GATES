import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GateError } from '../src/core/errors.js';
import { validateContext } from '../src/core/policy.js';

function originalValidUserId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 512 &&
    !/[\s\u0000-\u001f\u007f]/u.test(value) && Buffer.byteLength(value, 'utf8') <= 512 &&
    Buffer.from(value, 'utf8').toString('utf8') === value;
}

function acceptedByGate(value: unknown): boolean {
  try { validateContext('tenant', value); return true; }
  catch (error) {
    if (error instanceof GateError && error.code === 'invalid_context') return false;
    throw error;
  }
}

test('context user-id validation matches the former UTF-8 round-trip predicate', () => {
  const values: unknown[] = [
    '', null, undefined, 42,
    'provider|subject', 'user-123', 'usér-東京', 'e\u0301', '\u{10400}',
    '\ud800', '\udc00', 'left\ud800right', 'left\udc00right',
    '\ud800\ud800', '\udc00\udc00', '\ud800x\udc00',
    'has space', 'has\ttab', 'has\nnewline', 'has\u0000nul', 'has\u007fdel',
    'a'.repeat(512), 'a'.repeat(513), '\u{10400}'.repeat(128),
    '\u{10400}'.repeat(129), '\u{10400}'.repeat(256),
  ];

  // deterministic unicode cases use a buffer round trip as the oracle,
  // including malformed sequences and byte-length boundaries.
  const units = ['a', '\u00e9', '\u0301', '\u{10401}', '\ud800', '\udc00', '\t', '\u007f'];
  let state = 0x51f15e;
  for (let i = 0; i < 1024; i++) {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    let value = '';
    const count = state % 20;
    for (let j = 0; j < count; j++) {
      state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
      value += units[state % units.length]!;
    }
    values.push(value);
  }

  for (const value of values) {
    assert.equal(acceptedByGate(value), originalValidUserId(value),
      `validation result differs for ${typeof value === 'string' ? JSON.stringify(value) : String(value)}`);
  }
});

test('context user-id validation preserves exact UTF-8 byte boundaries', () => {
  assert.doesNotThrow(() => validateContext('tenant', 'a'.repeat(512)));
  assert.throws(() => validateContext('tenant', 'a'.repeat(513)), { code: 'invalid_context' });
  assert.doesNotThrow(() => validateContext('tenant', '\u{10400}'.repeat(128))); // 512 UTF-8 bytes
  assert.throws(() => validateContext('tenant', '\u{10400}'.repeat(129)), { code: 'invalid_context' });
  assert.throws(() => validateContext('tenant', '\u{10400}'.repeat(256)), { code: 'invalid_context' }); // 512 code units, 1024 bytes
});
