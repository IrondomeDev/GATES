import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createLifecycleGate } from '../src/core/lifecycle.js';
import { createPostgresPolicyMigrator } from '../src/storage/postgres/policy-migration.js';
import { createPostgresIdentityRegistry, type PgPool } from '../src/storage/postgres/identity.js';
import { POLICY_VERSION } from '../src/core/policy.js';

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
const allow = { async screen() { return { allowed: true, reason: 'not_listed' }; } };
const canonicalRules = {
  'company.com': { lowercase: true, stripPlusTag: true, stripDots: true },
} as const;

test('real PostgreSQL: exact-domain policy fingerprints, collision audit, and safe V2 migration', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL unset; custom policy migration not verified against PostgreSQL',
  timeout: 60_000,
}, async t => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only an explicitly supplied loopback PostgreSQL URL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  const driverName = 'pg';
  const { Pool } = await import(driverName) as { Pool: new (options: Record<string, unknown>) => PgPool & { end(): Promise<void> } };
  const schema = `gate_custom_policy_${process.pid}_${Date.now()}`;
  const config = { connectionString: databaseUrl, max: 8, connectionTimeoutMillis: 2_000,
    statement_timeout: 5_000, query_timeout: 6_000, lock_timeout: 3_000 };
  const admin = new Pool(config);
  let pool: (PgPool & { end(): Promise<void> }) | undefined;
  let created = false;
  t.after(async () => {
    try {
      await pool?.end();
      if (created) await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    } finally { await admin.end(); }
  });

  await admin.query(`CREATE SCHEMA ${schema}`);
  created = true;
  pool = new Pool({ ...config, options: `-c search_path=${schema}` });
  await pool.query(await readFile('migrations/001_identity.sql', 'utf8'));
  await pool.query(await readFile('migrations/002_lifecycle.sql', 'utf8'));
  await pool.query(await readFile('migrations/005_tenant_policy.sql', 'utf8'));

  const registry = createPostgresIdentityRegistry(pool, { schema });
  const engine = createLifecycleGate({ registry, screening: allow, canonicalRules });
  const migrator = createPostgresPolicyMigrator(pool, { schema, emailPolicy: engine.emailPolicy });

  await t.test('custom rules apply after built-ins at the exact canonical domain', async () => {
    const prepared = engine.emailPolicy.prepareEmail('A.B+tag@company.com');
    assert.deepEqual(prepared, {
      deliveryEmail: 'A.B+tag@company.com',
      canonical: 'ab@company.com',
      domain: 'company.com',
      policyVersion: engine.emailPolicy.version,
    });
    assert.equal(engine.emailPolicy.prepareEmail(prepared.canonical).canonical, prepared.canonical);
    assert.equal(engine.emailPolicy.prepareEmail('A.B+tag@sub.company.com').canonical, 'A.B+tag@sub.company.com');
    assert.equal(engine.emailPolicy.prepareEmail('A.B+tag@othercompany.com').canonical, 'A.B+tag@othercompany.com');
    assert.equal(engine.emailPolicy.prepareEmail('A.B+tag@company.net').canonical, 'A.B+tag@company.net');

    // Fastmail canonicalizes its one-level alias to the root before custom exact-domain lookup.
    const fastmailPolicy = createLifecycleGate({ registry, screening: allow,
      canonicalRules: { 'fastmail.com': { lowercase: true, stripDots: true } } }).emailPolicy;
    assert.equal(fastmailPolicy.prepareEmail('X+tag@User.fastmail.com').canonical, 'user@fastmail.com');
    assert.equal(fastmailPolicy.prepareEmail('x+tag@user.fastmail.com').canonical, 'user@fastmail.com');
  });

  await t.test('audit blocks V2 rows colliding under custom rules and migration writes nothing', async () => {
    await registry.claim({ tenantId: 'custom-collision', userId: 'one', canonical: 'A.B+tag@company.com', policyVersion: POLICY_VERSION });
    await registry.claim({ tenantId: 'custom-collision', userId: 'two', canonical: 'ab@company.com', policyVersion: POLICY_VERSION });
    const before = await pool!.query(
      `SELECT user_id, canonical_email, policy_version, revision::pg_catalog.text AS revision,
         pg_catalog.to_char(claimed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') AS claimed_at
       FROM "${schema}".irondome_gate_identity WHERE tenant_id = $1 ORDER BY user_id COLLATE "C"`,
      ['custom-collision']);
    const audit = await migrator.auditTenant({ tenantId: 'custom-collision' });
    assert.equal(audit.status, 'blocked');
    assert.equal(audit.unsupportedPolicy, false);
    assert.deepEqual(audit.collisionRows, [1, 2]);
    assert.equal(JSON.stringify(audit).includes('@'), false);
    assert.equal((await migrator.migrateTenant({ tenantId: 'custom-collision', expectedDigest: audit.digest })).status, 'blocked');
    const after = await pool!.query(
      `SELECT user_id, canonical_email, policy_version, revision::pg_catalog.text AS revision,
         pg_catalog.to_char(claimed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') AS claimed_at
       FROM "${schema}".irondome_gate_identity WHERE tenant_id = $1 ORDER BY user_id COLLATE "C"`,
      ['custom-collision']);
    assert.deepEqual(after.rows, before.rows);
    assert.equal((await pool!.query('SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['custom-collision'])).rows[0]?.policy_version, POLICY_VERSION);
    // A target rule must not silently repair rows falsely labeled as valid V2 keys.
    await registry.claim({ tenantId: 'corrupt-base', userId: 'owner', canonical: 'A.Lias+tag@gmail.com', policyVersion: POLICY_VERSION });
    const corrupt = await migrator.auditTenant({ tenantId: 'corrupt-base' });
    assert.equal(corrupt.status, 'blocked');
    assert.deepEqual(corrupt.invalidRows, [1]);
    assert.equal((await migrator.migrateTenant({ tenantId: 'corrupt-base', expectedDigest: corrupt.digest })).status, 'blocked');
    assert.equal((await registry.getOwnership({ tenantId: 'corrupt-base', userId: 'owner' })).status, 'active');
    assert.equal((await pool!.query('SELECT canonical_email FROM irondome_gate_identity WHERE tenant_id=$1', ['corrupt-base'])).rows[0]?.canonical_email, 'A.Lias+tag@gmail.com');
  });

  await t.test('built-in V2 rekeys atomically, preserves claim metadata and tombstones, and fences old writers', async () => {
    await registry.claim({ tenantId: 'custom-success', userId: 'owner', canonical: 'Original.Name+tag@company.com', policyVersion: POLICY_VERSION });
    await registry.revokeUser({ tenantId: 'custom-success', userId: 'deleted-user' });
    await pool!.query(
      `UPDATE "${schema}".irondome_gate_identity SET claimed_at = $1::pg_catalog.timestamptz
       WHERE tenant_id = $2 AND user_id = $3`,
      ['2024-03-04 05:06:07.123456+00', 'custom-success', 'owner']);
    const beforeRevision = (await pool!.query(
      `SELECT revision::pg_catalog.text AS revision FROM "${schema}".irondome_gate_identity
       WHERE tenant_id=$1 AND user_id=$2`, ['custom-success', 'owner'])).rows[0]?.revision;
    assert.equal(beforeRevision, '1');

    const audit = await migrator.auditTenant({ tenantId: 'custom-success' });
    assert.equal(audit.status, 'ready');
    assert.equal(audit.currentPolicyVersion, POLICY_VERSION);
    assert.equal(audit.targetPolicyVersion, engine.emailPolicy.version);
    const migrated = await migrator.migrateTenant({ tenantId: 'custom-success', expectedDigest: audit.digest });
    assert.equal(migrated.status, 'migrated');
    assert.equal(migrated.audit.targetPolicyVersion, engine.emailPolicy.version);

    const row = (await pool!.query(
      `SELECT canonical_email, policy_version, revision::pg_catalog.text AS revision,
         pg_catalog.to_char(claimed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') AS claimed_at
       FROM "${schema}".irondome_gate_identity WHERE tenant_id=$1 AND user_id=$2`,
      ['custom-success', 'owner'])).rows[0];
    assert.deepEqual(row, {
      canonical_email: 'originalname@company.com',
      policy_version: engine.emailPolicy.version,
      revision: '3',
      claimed_at: '2024-03-04 05:06:07.123456',
    });
    assert.equal((await pool!.query(
      `SELECT count(*)::int AS n FROM "${schema}".irondome_gate_revoked WHERE tenant_id=$1 AND user_id=$2`,
      ['custom-success', 'deleted-user'])).rows[0]?.n, 1);
    assert.equal((await pool!.query(
      'SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['custom-success'])).rows[0]?.policy_version,
      engine.emailPolicy.version);

    const active = await engine.assertActive({ tenantId: 'custom-success', userId: 'owner', email: 'Original.Name+tag@company.com' });
    assert.equal(active.canonical, 'originalname@company.com');
    const claimed = await engine.claimVerified({ tenantId: 'custom-success', userId: 'new-owner', email: 'New.Name+tag@company.com' });
    assert.equal(claimed.canonical, 'newname@company.com');
    assert.equal(await registry.claim({ tenantId: 'custom-success', userId: 'old-writer',
      canonical: 'old@company.com', policyVersion: POLICY_VERSION }), 'policy-mismatch');

    assert.equal((await migrator.migrateTenant({ tenantId: 'custom-success', expectedDigest: audit.digest })).status, 'already-current');
    const afterRetry = (await pool!.query(
      `SELECT revision::pg_catalog.text AS revision, pg_catalog.to_char(claimed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') AS claimed_at
       FROM "${schema}".irondome_gate_identity WHERE tenant_id=$1 AND user_id=$2`,
      ['custom-success', 'owner'])).rows[0];
    assert.deepEqual(afterRetry, { revision: '3', claimed_at: '2024-03-04 05:06:07.123456' });
  });

  await t.test('unknown previous custom policy is blocked without guessing lossy source keys', async () => {
    const priorCustom = 'gate-domain-rules-v1-unavailable-old-config';
    await pool!.query('INSERT INTO irondome_gate_tenant_policy (tenant_id, policy_version) VALUES ($1,$2)', ['custom-unknown', priorCustom]);
    await pool!.query(
      `INSERT INTO "${schema}".irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version,revision)
       VALUES ($1,$2,$3,$4,7)`,
      ['custom-unknown', 'prior-owner', 'oldcanonical@company.com', priorCustom]);
    const before = await pool!.query(
      `SELECT user_id, canonical_email, policy_version, revision::pg_catalog.text AS revision
       FROM "${schema}".irondome_gate_identity WHERE tenant_id=$1`, ['custom-unknown']);
    const audit = await migrator.auditTenant({ tenantId: 'custom-unknown' });
    assert.equal(audit.status, 'blocked');
    assert.equal(audit.unsupportedPolicy, true);
    assert.equal((await migrator.migrateTenant({ tenantId: 'custom-unknown', expectedDigest: audit.digest })).status, 'blocked');
    const after = await pool!.query(
      `SELECT user_id, canonical_email, policy_version, revision::pg_catalog.text AS revision
       FROM "${schema}".irondome_gate_identity WHERE tenant_id=$1`, ['custom-unknown']);
    assert.deepEqual(after.rows, before.rows);
    assert.deepEqual((await pool!.query('SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['custom-unknown'])).rows[0], { policy_version: priorCustom });
  });

  await t.test('audit digest binds target rule fingerprint; malformed config or derived key cannot create ownership', async () => {
    await registry.claim({ tenantId: 'custom-digest', userId: 'digest-owner', canonical: 'A.B+tag@company.com', policyVersion: POLICY_VERSION });
    const auditA = await migrator.auditTenant({ tenantId: 'custom-digest' });
    const differentPolicy = createLifecycleGate({ registry, screening: allow,
      canonicalRules: { 'company.com': { lowercase: true } } });
    const otherMigrator = createPostgresPolicyMigrator(pool!, { schema, emailPolicy: differentPolicy.emailPolicy });
    const auditB = await otherMigrator.auditTenant({ tenantId: 'custom-digest' });
    assert.notEqual(auditA.targetPolicyVersion, auditB.targetPolicyVersion);
    assert.notEqual(auditA.digest, auditB.digest);
    assert.equal((await migrator.migrateTenant({ tenantId: 'custom-digest', expectedDigest: auditB.digest })).status, 'stale-audit');

    assert.throws(() => createLifecycleGate({ registry, screening: allow,
      canonicalRules: { '*.company.com': { lowercase: true } } as never }), TypeError);
    let screeningCalls = 0;
    const guardedEngine = createLifecycleGate({ registry,
      screening: { async screen() { screeningCalls++; return { allowed: true, reason: 'not_listed' }; } },
      canonicalRules: { 'company.com': { stripPlusTag: true } } });
    await assert.rejects(guardedEngine.claimVerified({ tenantId: 'invalid-derived-key', userId: 'nobody', email: '+tag@company.com' }),
      error => (error as { code?: string }).code === 'invalid_email');
    assert.equal(screeningCalls, 0, 'invalid derived keys fail before screening');
    assert.equal((await pool!.query('SELECT count(*)::int AS n FROM irondome_gate_identity WHERE tenant_id=$1', ['invalid-derived-key'])).rows[0]?.n, 0);
  });
});
