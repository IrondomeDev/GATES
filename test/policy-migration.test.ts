import assert from 'node:assert/strict';
import test from 'node:test';
import * as api from '../src/index.js';
import { createEmailPolicy, POLICY_VERSION } from '../src/core/policy.js';
import { createPostgresPolicyMigrator } from '../src/storage/postgres/policy-migration.js';
import type { PgPool } from '../src/storage/postgres/identity.js';

function snapshotPool(version: string, canonicals = ['person+tag@company.example']) {
  const statements: string[] = [];
  const pool: PgPool = {
    async query(sql) {
      statements.push(sql);
      const rows = sql.startsWith('SELECT policy_version') ? [{ policy_version: version }] :
        sql.startsWith('SELECT user_id') ? canonicals.map((canonical, index) => ({
          user_id: `user-${index}`, canonical_email: canonical, policy_version: version,
          revision: '1', claimed_at: '2026-01-01 00:00:00.000000+00',
        })) : [];
      return { rows, rowCount: rows.length };
    },
    async connect() { return { query: pool.query, release() {} }; },
  };
  return { pool, statements };
}

test('public API exposes only the current built-in policy', () => {
  assert.equal('LEGACY_POLICY_VERSION' in api, false);
  assert.equal(api.DEFAULT_EMAIL_POLICY.version, api.POLICY_VERSION);
});

test('unsupported prior policy audit and migration reject without writing', async () => {
  const { pool, statements } = snapshotPool('gate-conservative-v1-mailcanon-0.1.1-tr46-5.1.1');
  const migrator = createPostgresPolicyMigrator(pool);
  const audit = await migrator.auditTenant({ tenantId: 'tenant' });
  assert.equal(audit.status, 'blocked');
  assert.equal(audit.unsupportedPolicy, true);
  assert.equal((await migrator.migrateTenant({ tenantId: 'tenant', expectedDigest: audit.digest })).status, 'blocked');
  assert.equal(statements.some(sql => /^(INSERT|UPDATE|DELETE)/.test(sql)), false);
});

test('current built-in policy supports additive custom-rule audit and collision detection', async () => {
  const emailPolicy = createEmailPolicy({ 'company.example': { stripPlusTag: true } });
  const source = snapshotPool(POLICY_VERSION);
  const migrator = createPostgresPolicyMigrator(source.pool, { emailPolicy });
  const audit = await migrator.auditTenant({ tenantId: 'tenant' });
  assert.equal(audit.status, 'ready');
  assert.equal(audit.unsupportedPolicy, false);
  assert.equal(audit.targetPolicyVersion, emailPolicy.version);
  const collision = snapshotPool(POLICY_VERSION, ['person@company.example', 'person+tag@company.example']);
  const blocked = await createPostgresPolicyMigrator(collision.pool, { emailPolicy }).auditTenant({ tenantId: 'tenant' });
  assert.equal(blocked.status, 'blocked');
  assert.deepEqual(blocked.collisionRows, [1, 2]);
});

test('already-current custom rules are idempotent but cannot conceal malformed canonical keys', async () => {
  const emailPolicy = createEmailPolicy({ 'company.example': { stripPlusTag: true } });
  const valid = snapshotPool(emailPolicy.version, ['person@company.example']);
  assert.equal((await createPostgresPolicyMigrator(valid.pool, { emailPolicy }).auditTenant({ tenantId: 'tenant' })).status, 'already-current');
  const invalid = snapshotPool(emailPolicy.version);
  const audit = await createPostgresPolicyMigrator(invalid.pool, { emailPolicy }).auditTenant({ tenantId: 'tenant' });
  assert.equal(audit.status, 'blocked');
  assert.deepEqual(audit.invalidRows, [1]);
});
