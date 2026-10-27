import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createPostgresPolicyMigrator } from '../src/storage/postgres/policy-migration.js';
import { createPostgresIdentityRegistry, type PgClient, type PgPool, type PgQueryResult } from '../src/storage/postgres/identity.js';
import { createEmailPolicy, POLICY_VERSION } from '../src/core/policy.js';

const targetPolicy = createEmailPolicy({
  'company.example': { stripPlusTag: true },
  'dots.example': { lowercase: true, stripDots: true, stripPlusTag: true },
  'other.example': { stripPlusTag: true },
});
const TARGET_POLICY_VERSION = targetPolicy.version;

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;

test('real PostgreSQL: canonical policy audit, fencing, atomic rekey, and rollback', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL unset; policy migration not verified against PostgreSQL',
  timeout: 60_000,
}, async t => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only an explicitly supplied loopback PostgreSQL URL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  const driverName = 'pg';
  const { Pool } = await import(driverName) as { Pool: new (options: Record<string, unknown>) => PgPool & { end(): Promise<void> } };
  const schema = `gate_policy_${process.pid}_${Date.now()}`;
  const mixedSchema = `${schema}_mixed`;
  const config = { connectionString: databaseUrl, max: 12, connectionTimeoutMillis: 2_000,
    statement_timeout: 5_000, query_timeout: 6_000, lock_timeout: 3_000 };
  const admin = new Pool(config);
  const pool = new Pool({ ...config, options: `-c search_path=${schema}` });
  let created = false;
  let mixedCreated = false;
  t.after(async () => {
    await pool.end();
    try {
      if (mixedCreated) await admin.query(`DROP SCHEMA ${mixedSchema} CASCADE`);
      if (created) await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    } finally { await admin.end(); }
  });

  await admin.query(`CREATE SCHEMA ${mixedSchema}`);
  mixedCreated = true;
  const mixedPool = new Pool({ ...config, options: `-c search_path=${mixedSchema}` });
  try {
    await mixedPool.query(await readFile('migrations/001_identity.sql', 'utf8'));
    await mixedPool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('t','a','a@example.com','v1'),('t','b','b@example.com','v2')");
    await mixedPool.query(await readFile('migrations/002_lifecycle.sql', 'utf8'));
    await assert.rejects(mixedPool.query(await readFile('migrations/005_tenant_policy.sql', 'utf8')), /mixed policy versions/);
    const untouched = await mixedPool.query("SELECT count(*)::int AS n FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname='irondome_gate_tenant_policy'", [mixedSchema]);
    assert.equal(untouched.rows[0]?.n, 0, 'mixed-version upgrade creates no partial policy objects');
  } finally { await mixedPool.end(); }

  await admin.query(`CREATE SCHEMA ${schema}`);
  created = true;
  await pool.query(await readFile('migrations/001_identity.sql', 'utf8'));
  await pool.query(await readFile('migrations/002_lifecycle.sql', 'utf8'));
  await t.test('new writes fail closed before the required policy migration is installed', async () => {
    const outdated = createPostgresIdentityRegistry(pool, { schema });
    await assert.rejects(outdated.claim({ tenantId: 'before-upgrade', userId: 'u',
      canonical: 'person@company.example', policyVersion: TARGET_POLICY_VERSION }), { code: '42P01' });
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM irondome_gate_identity')).rows[0]?.count, 0);
  });
  const sourceClaims = [
    ['t', 'preserve', 'original.name+tag@company.example', POLICY_VERSION, 7, '2024-03-04 05:06:07.123456+00'],
    ['collision-plus', 'one', 'person+tag@company.example', POLICY_VERSION, 4, '2024-03-04 05:06:07.000001+00'],
    ['collision-plus', 'two', 'person@company.example', POLICY_VERSION, 4, '2024-03-04 05:06:08.000002+00'],
    ['collision-dots', 'one', 'a.b@dots.example', POLICY_VERSION, 3, '2024-03-04 05:06:09.000003+00'],
    ['collision-dots', 'two', 'ab@dots.example', POLICY_VERSION, 3, '2024-03-04 05:06:10.000004+00'],
    ['collision-other', 'one', 'alice+tag@other.example', POLICY_VERSION, 2, '2024-03-04 05:06:11.000005+00'],
    ['collision-other', 'two', 'alice@other.example', POLICY_VERSION, 2, '2024-03-04 05:06:12.000006+00'],
    ['invalid', 'u', 'not-an-email', POLICY_VERSION, 1, '2024-03-04 05:06:13.000007+00'],
    ['future', 'u', 'future@example.com', 'future-policy-v9', 1, '2024-03-04 05:06:14.000008+00'],
  ];
  for (const claim of sourceClaims) {
    await pool.query('INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version,revision,claimed_at) VALUES ($1,$2,$3,$4,$5,$6)', claim);
  }
  await pool.query(await readFile('migrations/005_tenant_policy.sql', 'utf8'));
  const migrator = createPostgresPolicyMigrator(pool, { schema, emailPolicy: targetPolicy });
  const registry = createPostgresIdentityRegistry(pool, { schema });
  await registry.revokeUser({ tenantId: 't', userId: 'already-revoked' });

  await t.test('tenant parent fence prevents mixed policy keys, including old writer inserts', async () => {
    await assert.rejects(pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('t','wrong','wrong@example.com','old-policy')"));
    await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('new-tenant','new-user','new@example.com',$1)", [TARGET_POLICY_VERSION]);
    assert.deepEqual((await pool.query('SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['new-tenant'])).rows[0], { policy_version: TARGET_POLICY_VERSION });
  });

  await t.test('audit identifies custom-domain plus-tag and dot collisions without returning identity data', async () => {
    for (const tenantId of ['collision-plus', 'collision-dots', 'collision-other']) {
      const audit = await migrator.auditTenant({ tenantId });
      assert.equal(audit.status, 'blocked');
      assert.equal(audit.collisionRows.length, 2);
      assert.deepEqual(Object.keys(audit).sort(), ['collisionRows', 'currentPolicyVersion', 'digest', 'invalidRows', 'limitExceeded', 'ready', 'revisionOverflowRows', 'rowCount', 'status', 'targetPolicyVersion', 'unsupportedPolicy'].sort());
      assert.equal(JSON.stringify(audit).includes('@'), false);
      assert.equal(JSON.stringify(audit).includes(tenantId), false);
    }
  });

  await t.test('audit blocks malformed stored keys and unknown policy versions', async () => {
    const invalid = await migrator.auditTenant({ tenantId: 'invalid' });
    assert.equal(invalid.status, 'blocked');
    assert.deepEqual(invalid.invalidRows, [1]);
    const unsupported = await migrator.auditTenant({ tenantId: 'future' });
    assert.equal(unsupported.status, 'blocked');
    assert.equal(unsupported.unsupportedPolicy, true);
  });

  await t.test('digest mismatch performs no writes; verified digest rekeys atomically and advances revision by two', async () => {
    const before = await pool.query('SELECT tenant_id,user_id,canonical_email,policy_version,revision::text AS revision,pg_catalog.to_char(claimed_at AT TIME ZONE \'UTC\', \'YYYY-MM-DD HH24:MI:SS.US\') AS claimed FROM irondome_gate_identity WHERE tenant_id=$1', ['t']);
    const audit = await migrator.auditTenant({ tenantId: 't' });
    assert.equal(audit.status, 'ready');
    await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('t','concurrent','other@example.com',$1)", [POLICY_VERSION]);
    assert.equal((await migrator.migrateTenant({ tenantId: 't', expectedDigest: audit.digest })).status, 'stale-audit');
    const afterStale = await pool.query('SELECT canonical_email,policy_version,revision::text AS revision FROM irondome_gate_identity WHERE tenant_id=$1 ORDER BY user_id COLLATE "C"', ['t']);
    assert.equal(afterStale.rows.some(row => row.canonical_email === 'original.name+tag@company.example'), true);

    const fresh = await migrator.auditTenant({ tenantId: 't' });
    assert.equal(fresh.status, 'ready');
    assert.equal((await migrator.migrateTenant({ tenantId: 't', expectedDigest: fresh.digest })).status, 'migrated');
    assert.equal((await migrator.migrateTenant({ tenantId: 't', expectedDigest: fresh.digest })).status, 'already-current');
    const after = await pool.query('SELECT tenant_id,user_id,canonical_email,policy_version,revision::text AS revision,pg_catalog.to_char(claimed_at AT TIME ZONE \'UTC\', \'YYYY-MM-DD HH24:MI:SS.US\') AS claimed FROM irondome_gate_identity WHERE tenant_id=$1 ORDER BY user_id COLLATE "C"', ['t']);
    assert.equal(after.rows.length, before.rows.length + 1);
    const preserved = after.rows.find(row => row.user_id === 'preserve');
    assert.deepEqual(preserved, { tenant_id: 't', user_id: 'preserve', canonical_email: 'original.name@company.example', policy_version: TARGET_POLICY_VERSION, revision: '9', claimed: '2024-03-04 05:06:07.123456' });
    assert.equal((await pool.query('SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['t'])).rows[0]?.policy_version, TARGET_POLICY_VERSION);
    const again = await migrator.auditTenant({ tenantId: 't' });
    assert.equal(again.status, 'already-current');
    assert.equal((await migrator.migrateTenant({ tenantId: 't', expectedDigest: again.digest })).status, 'already-current');

    assert.equal(await registry.replaceVerified({ tenantId: 't', userId: 'preserve', canonical: 'new@company.example', policyVersion: TARGET_POLICY_VERSION, expectedRevision: '8' }), 'stale');
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM irondome_gate_revoked WHERE tenant_id=$1 AND user_id=$2', ['t', 'already-revoked'])).rows[0]?.n, 1);
  });

  await t.test('constraint failure rolls back all rekey and parent changes', async () => {
    await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version,revision) VALUES ('rollback','u','old.name+tag@dots.example',$1,11)", [POLICY_VERSION]);
    const audit = await migrator.auditTenant({ tenantId: 'rollback' });
    await pool.query(`CREATE FUNCTION ${schema}.reject_policy_rekey() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN RAISE EXCEPTION 'injected policy rekey failure'; END $fn$`);
    await pool.query(`CREATE TRIGGER reject_policy_rekey BEFORE INSERT ON ${schema}.irondome_gate_identity FOR EACH ROW WHEN (NEW.tenant_id = 'rollback') EXECUTE FUNCTION ${schema}.reject_policy_rekey()`);
    try {
      await assert.rejects(migrator.migrateTenant({ tenantId: 'rollback', expectedDigest: audit.digest }), error => {
        assert.equal((error as { code?: string }).code, 'storage_unavailable');
        assert.equal(String(error).includes('injected'), false);
        return true;
      });
    } finally {
      await pool.query(`DROP TRIGGER reject_policy_rekey ON ${schema}.irondome_gate_identity`);
      await pool.query(`DROP FUNCTION ${schema}.reject_policy_rekey()`);
    }
    const row = (await pool.query('SELECT canonical_email,policy_version,revision::text AS revision FROM irondome_gate_identity WHERE tenant_id=$1', ['rollback'])).rows[0];
    assert.deepEqual(row, { canonical_email: 'old.name+tag@dots.example', policy_version: POLICY_VERSION, revision: '11' });
    assert.deepEqual((await pool.query('SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['rollback'])).rows[0], { policy_version: POLICY_VERSION });
  });

  await t.test('audit blocks oversized tenants and revision overflow', async () => {
    const limited = createPostgresPolicyMigrator(pool, { schema, maxRows: 1, emailPolicy: targetPolicy });
    const overLimit = await limited.auditTenant({ tenantId: 't' });
    assert.equal(overLimit.status, 'blocked');
    assert.equal(overLimit.limitExceeded, true);
    assert.equal(overLimit.rowCount, 2);
    await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version,revision) VALUES ('overflow','u','overflow@example.com',$1,9223372036854775805)", [POLICY_VERSION]);
    const overflow = await migrator.auditTenant({ tenantId: 'overflow' });
    assert.equal(overflow.status, 'blocked');
    assert.deepEqual(overflow.revisionOverflowRows, [1]);
  });

  await t.test('audit digest is tenant-bound, and mutable request objects are snapshotted before connect', async () => {
    const emptyA = await migrator.auditTenant({ tenantId: 'empty-a' });
    assert.equal((await migrator.migrateTenant({ tenantId: 'empty-b', expectedDigest: emptyA.digest })).status, 'stale-audit');
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['empty-b'])).rows[0]?.n, 0);

    const mutableAuditPool = delayedPool(pool);
    const mutableAuditMigrator = createPostgresPolicyMigrator(mutableAuditPool.pool, { schema, emailPolicy: targetPolicy });
    const auditInput = { tenantId: 't' };
    const expectedAuditDigest = (await migrator.auditTenant({ tenantId: 't' })).digest;
    const pendingAudit = mutableAuditMigrator.auditTenant(auditInput);
    await mutableAuditPool.started;
    auditInput.tenantId = 'empty-b';
    mutableAuditPool.resume();
    assert.equal((await pendingAudit).digest, expectedAuditDigest);

    await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('captured-before-connect','u','captured+tag@example.com',$1)", [POLICY_VERSION]);
    const migrationAudit = await migrator.auditTenant({ tenantId: 'captured-before-connect' });
    const mutableMigrationPool = delayedPool(pool);
    const mutableMigrationMigrator = createPostgresPolicyMigrator(mutableMigrationPool.pool, { schema, emailPolicy: targetPolicy });
    const migrationInput = { tenantId: 'captured-before-connect', expectedDigest: migrationAudit.digest };
    const pendingMigration = mutableMigrationMigrator.migrateTenant(migrationInput);
    await mutableMigrationPool.started;
    migrationInput.tenantId = 'empty-b';
    mutableMigrationPool.resume();
    assert.equal((await pendingMigration).status, 'migrated');
    assert.equal((await pool.query('SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['captured-before-connect'])).rows[0]?.policy_version, TARGET_POLICY_VERSION);
  });

  await t.test('connection failures are sanitized to storage_unavailable', async () => {
    const failingPool: PgPool = {
      async connect(): Promise<PgClient> { throw new Error('secret connection details'); },
      async query() { throw new Error('secret query details'); },
    };
    const failed = createPostgresPolicyMigrator(failingPool, { schema, emailPolicy: targetPolicy });
    await assert.rejects(failed.auditTenant({ tenantId: 'no-pii' }), error => {
      assert.equal((error as { code?: string }).code, 'storage_unavailable');
      assert.equal((error as Error).message, 'storage_unavailable');
      assert.equal(String(error).includes('secret'), false);
      return true;
    });
    await assert.rejects(failed.migrateTenant({ tenantId: 'no-pii', expectedDigest: '0'.repeat(64) }), error => {
      assert.equal((error as { code?: string }).code, 'storage_unavailable');
      return true;
    });
  });

  await t.test('explicit schema works with default public search_path', async () => {
    await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('explicit-schema','u','explicit+tag@dots.example',$1)", [POLICY_VERSION]);
    const publicPathMigrator = createPostgresPolicyMigrator(admin, { schema, emailPolicy: targetPolicy });
    const audit = await publicPathMigrator.auditTenant({ tenantId: 'explicit-schema' });
    assert.equal(audit.status, 'ready');
    assert.equal((await publicPathMigrator.migrateTenant({ tenantId: 'explicit-schema', expectedDigest: audit.digest })).status, 'migrated');
    assert.equal((await pool.query('SELECT canonical_email FROM irondome_gate_identity WHERE tenant_id=$1', ['explicit-schema'])).rows[0]?.canonical_email, 'explicit@dots.example');
  });

  await t.test('concurrent first claims for one tenant select exactly one policy', async () => {
    const identityInsert = `INSERT INTO "${schema}".irondome_gate_identity`;
    const arrivals = createArrivalBarrier(2);
    const racingPool = interceptPool(pool, async (sql, values, client) => {
      if (sql.startsWith(identityInsert)) {
        const pending = client.query(sql, values);
        await arrivals.arrive();
        return pending;
      }
      return client.query(sql, values);
    });
    const racingRegistry = createPostgresIdentityRegistry(racingPool, { schema });
    const inputs = [
      { tenantId: 'policy-race-new', userId: 'old-writer', canonical: 'old@race.example', policyVersion: POLICY_VERSION },
      { tenantId: 'policy-race-new', userId: 'new-writer', canonical: 'new@race.example', policyVersion: TARGET_POLICY_VERSION },
    ];
    const outcomes = await Promise.allSettled(inputs.map(input => racingRegistry.claim(input)));
    assert.equal(outcomes.filter(result => result.status === 'fulfilled' && result.value === 'claimed').length, 1);
    assert.equal(outcomes.filter(result => result.status === 'fulfilled' && result.value === 'policy-mismatch').length, 1);
    const rows = await pool.query('SELECT policy_version FROM irondome_gate_identity WHERE tenant_id=$1', ['policy-race-new']);
    const policies = await pool.query('SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['policy-race-new']);
    assert.equal(rows.rows.length, 1);
    assert.equal(policies.rows.length, 1);
    assert.equal(rows.rows[0]?.policy_version, policies.rows[0]?.policy_version);
  });

  await t.test('exclusive policy migration lock fences queued old and new writers', async () => {
    await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('queued-writers','existing','existing+tag@dots.example',$1)", [POLICY_VERSION]);
    const audit = await migrator.auditTenant({ tenantId: 'queued-writers' });
    assert.equal(audit.status, 'ready');

    const lockSql = `LOCK TABLE "${schema}".irondome_gate_identity IN EXCLUSIVE MODE`;
    const lockHeld = deferred<void>();
    const releaseMigration = deferred<void>();
    const migrationPool = interceptPool(pool, async (sql, values, client) => {
      const result = await client.query(sql, values);
      if (sql === lockSql) {
        lockHeld.resolve();
        await releaseMigration.promise;
      }
      return result;
    });
    const insertAttemptBarrier = createArrivalBarrier(2);
    const identityInsert = `INSERT INTO "${schema}".irondome_gate_identity`;
    const queuedWriterPool = interceptPool(pool, async (sql, values, client) => {
      if (sql.startsWith(identityInsert)) {
        const pending = client.query(sql, values);
        insertAttemptBarrier.arrive().catch(() => {});
        return pending;
      }
      return client.query(sql, values);
    });
    const migration = createPostgresPolicyMigrator(migrationPool, { schema, emailPolicy: targetPolicy });
    const writerRegistry = createPostgresIdentityRegistry(queuedWriterPool, { schema });
    const migrationPromise = migration.migrateTenant({ tenantId: 'queued-writers', expectedDigest: audit.digest });
    const claims: Promise<unknown>[] = [];
    try {
      await within(lockHeld.promise, 5_000, 'exclusive identity lock');
      claims.push(writerRegistry.claim({ tenantId: 'queued-writers', userId: 'queued-old', canonical: 'old+tag@dots.example', policyVersion: POLICY_VERSION }));
      claims.push(writerRegistry.claim({ tenantId: 'queued-writers', userId: 'queued-new', canonical: 'new@dots.example', policyVersion: TARGET_POLICY_VERSION }));
      await within(insertAttemptBarrier.arrivals, 5_000, 'both writer inserts queued');
      releaseMigration.resolve();
      assert.equal((await migrationPromise).status, 'migrated');
      const results = await Promise.allSettled(claims);
      assert.equal(results.filter(result => result.status === 'fulfilled' && result.value === 'claimed').length, 1);
      assert.equal(results.filter(result => result.status === 'fulfilled' && result.value === 'policy-mismatch').length, 1);
      const rows = await pool.query('SELECT policy_version FROM irondome_gate_identity WHERE tenant_id=$1', ['queued-writers']);
      assert.equal(rows.rows.length, 2);
      assert.ok(rows.rows.every(row => row.policy_version === TARGET_POLICY_VERSION));
      assert.equal((await pool.query('SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['queued-writers'])).rows[0]?.policy_version, TARGET_POLICY_VERSION);
    } finally {
      releaseMigration.resolve();
      await Promise.allSettled([migrationPromise, ...claims]);
    }
  });

  await t.test('tenant policy fence remains after last revocation and rejects mismatched-policy reinsert', async () => {
    await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('terminal','u','terminal@other.example',$1)", [TARGET_POLICY_VERSION]);
    await registry.revokeUser({ tenantId: 'terminal', userId: 'u' });
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM irondome_gate_identity WHERE tenant_id=$1', ['terminal'])).rows[0]?.n, 0);
    assert.deepEqual((await pool.query('SELECT policy_version FROM irondome_gate_tenant_policy WHERE tenant_id=$1', ['terminal'])).rows[0], { policy_version: TARGET_POLICY_VERSION });
    await assert.rejects(pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('terminal','old-writer','different@other.example',$1)", [POLICY_VERSION]));
  });

  await t.test('current policy metadata cannot conceal an unnormalized key', async () => {
    await pool.query("INSERT INTO irondome_gate_identity (tenant_id,user_id,canonical_email,policy_version) VALUES ('corrupt-current','u','Unnormalized+tag@dots.example',$1)", [TARGET_POLICY_VERSION]);
    const audit = await migrator.auditTenant({ tenantId: 'corrupt-current' });
    assert.equal(audit.status, 'blocked');
    assert.deepEqual(audit.invalidRows, [1]);
    assert.equal((await migrator.migrateTenant({ tenantId: 'corrupt-current', expectedDigest: audit.digest })).status, 'blocked');
  });
});

function delayedPool(pool: PgPool): { pool: PgPool; started: Promise<void>; resume(): void } {
  let start!: () => void;
  let release!: () => void;
  const started = new Promise<void>(resolve => { start = resolve; });
  const waiting = new Promise<void>(resolve => { release = resolve; });
  const wrapped: PgPool = {
    query: (sql, values) => pool.query(sql, values),
    async connect() {
      start();
      await waiting;
      return pool.connect();
    },
  };
  return { pool: wrapped, started, resume: release };
}

function deferred<T>(): { promise: Promise<T>; resolve(value?: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve: value => resolve(value as T) };
}

function createArrivalBarrier(expected: number): { arrivals: Promise<void>; arrive(): Promise<void> } {
  let resolveReached!: () => void;
  let rejectReached!: (error: Error) => void;
  const arrivals = new Promise<void>((resolve, reject) => { resolveReached = resolve; rejectReached = reject; });
  let count = 0;
  const timeout = setTimeout(() => rejectReached(new Error('Timed out waiting for query barrier')), 5_000);
  return {
    arrivals,
    async arrive() {
      count++;
      if (count >= expected) {
        clearTimeout(timeout);
        resolveReached();
      }
      await arrivals;
    },
  };
}

async function within<T>(promise: Promise<T>, milliseconds: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([promise, new Promise<T>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}`)), milliseconds);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}

function interceptPool(
  pool: PgPool,
  intercept: (sql: string, values: unknown[] | undefined, client: PgClient) => Promise<PgQueryResult>,
): PgPool {
  return {
    query: (sql, values) => pool.query(sql, values),
    async connect() {
      const client = await pool.connect();
      return {
        query: (sql, values) => intercept(sql, values, client),
        release: error => client.release(error),
      };
    },
  };
}
