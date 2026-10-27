import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createOnlinePostgresGate } from '../src/storage/postgres/online.js';
import { createEmailPolicy, DEFAULT_EMAIL_POLICY, POLICY_VERSION } from '../src/core/policy.js';
import { createPostgresIdentityRegistry, type PgPool } from '../src/storage/postgres/identity.js';
import { createLifecycleGate } from '../src/core/lifecycle.js';

const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
const screening = { async screen() { return { allowed: true, reason: 'not_listed' }; } };
const targetPolicy = createEmailPolicy({ 'company.test': { lowercase: true, stripPlusTag: true, stripDots: true } });

test('real PostgreSQL: online dual-epoch policy cutover, concurrent writes, and legacy adoption', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL unset; online policy migration not verified against PostgreSQL',
  timeout: 90_000,
}, async t => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(url.hostname), 'Only an explicitly supplied loopback PostgreSQL URL is permitted');
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  const driverName = 'pg';
  const { Pool } = await import(driverName) as { Pool: new (options: Record<string, unknown>) => PgPool & { end(): Promise<void> } };
  const schema = `gate_online_${process.pid}_${Date.now()}`;
  const config = { connectionString: databaseUrl, max: 10, connectionTimeoutMillis: 2_000,
    statement_timeout: 8_000, query_timeout: 9_000, lock_timeout: 3_000 };
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
  for (const migration of ['001_identity.sql', '002_lifecycle.sql', '005_tenant_policy.sql', '006_online_policy.sql']) {
    await pool.query(await readFile(`migrations/${migration}`, 'utf8'));
  }

  const legacyRegistry = createPostgresIdentityRegistry(pool, { schema });
  const legacyGate = createLifecycleGate({ registry: legacyRegistry, screening });
  const online = createOnlinePostgresGate(pool, { schema, screening });
  const activeSourcePolicy = DEFAULT_EMAIL_POLICY.version;

  await t.test('modern ownership dual-writes through backfill, then flips epoch without losing delivery proofs', async () => {
    const tenantId = 'online-modern';
    await online.claimVerified({ tenantId, userId: 'a-owner', email: 'A.B+tag@company.test' });
    await online.claimVerified({ tenantId, userId: 'b-owner', email: 'C.D+tag@company.test' });
    await online.claimVerified({ tenantId, userId: 'c-owner', email: 'E.F+tag@company.test' });
    await online.claimVerified({ tenantId, userId: 'proof-owner', email: 'Proof.Owner+tag@company.test' });
    await online.claimVerified({ tenantId, userId: 'retry-owner', email: 'Alias+one@gmail.com' });
    await online.claimVerified({ tenantId, userId: 'retry-owner', email: 'ALIAS+two@googlemail.com' });
    await online.claimVerified({ tenantId, userId: 'z-revoked', email: 'Deleted@company.test' });
    await online.revokeUser({ tenantId, userId: 'z-revoked' });
    await online.claimVerified({ tenantId: 'isolated-tenant', userId: 'same-user', email: 'A.B+tag@company.test' });

    const before = await pool!.query(`SELECT delivery_email, revision::pg_catalog.text AS revision
      FROM "${schema}".irondome_gate_online_owner WHERE tenant_id=$1 AND user_id='a-owner'`, [tenantId]);
    assert.deepEqual(before.rows[0], { delivery_email: 'A.B+tag@company.test', revision: '1' });
    const retrySource = await pool!.query(`SELECT delivery_email, revision::pg_catalog.text AS revision
      FROM "${schema}".irondome_gate_online_owner WHERE tenant_id=$1 AND user_id='retry-owner'`, [tenantId]);
    assert.deepEqual(retrySource.rows[0], { delivery_email: 'Alias+one@gmail.com', revision: '1' },
      'same-canonical proof retries cannot replace the exact tracked delivery address');
    const proofStateBeforeFlip = await online.getOwnership({ tenantId, userId: 'proof-owner' });
    assert.equal(proofStateBeforeFlip.status, 'active');
    const capturedProofRevision = proofStateBeforeFlip.status === 'active' ? proofStateBeforeFlip.revision : '';

    const begun = await online.migration.begin({ tenantId, targetPolicy });
    assert.equal(begun.phase, 'building');
    assert.equal(begun.activePolicyVersion, activeSourcePolicy);
    assert.equal(begun.pendingPolicyVersion, targetPolicy.version);
    assert.ok(begun.pendingEpoch);

    // The legacy registry is fenced as soon as this tenant begins the protocol.
    await assert.rejects(legacyRegistry.claim({ tenantId, userId: 'legacy-writer', canonical: 'legacy@company.test', policyVersion: activeSourcePolicy }));

    // A source-valid address that collapses to an invalid target still keeps active access,
    // while recording a gap that prevents an unsafe activation.
    await online.claimVerified({ tenantId, userId: 'invalid-target', email: '+tag@company.test' });
    assert.equal((await online.assertActive({ tenantId, userId: 'invalid-target', email: '+tag@company.test' })).canonical,
      '+tag@company.test');
    assert.equal((await online.migration.status({ tenantId })).gaps, '1');
    await online.revokeUser({ tenantId, userId: 'invalid-target' });

    let status = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 1, includeCounts: true });
    assert.equal(status.phase, 'building');
    // A new user sorts behind the cursor and must still get its target-epoch key from the dual writer.
    await online.claimVerified({ tenantId, userId: '0-behind-cursor', email: 'Q.R+tag@company.test' });
    // The tenant lock is scoped: another tenant remains writable during this backfill batch.
    await online.claimVerified({ tenantId: 'isolated-tenant', userId: 'during-cutover', email: 'Concurrent@company.test' });
    // Existing-user changes and revocations remain live while batches are being built.
    await online.changeVerifiedEmail({ tenantId, userId: 'b-owner', email: 'New.Name+tag@company.test', expectedRevision: '1' });
    await online.revokeUser({ tenantId, userId: 'c-owner' });

    for (let i = 0; i < 20 && status.phase === 'building'; i++) {
      status = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 1, includeCounts: true });
    }
    assert.equal(status.phase, 'ready');
    assert.equal(status.gaps, '0');
    assert.equal(status.sourceRows, '5');

    // Other tenants keep their own current epoch and policy while this tenant is ready to flip.
    const isolated = await online.getOwnership({ tenantId: 'isolated-tenant', userId: 'same-user' });
    assert.equal(isolated.status, 'active');
    if (isolated.status === 'active') assert.equal(isolated.policyVersion, activeSourcePolicy);

    const activated = await online.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
    assert.equal(activated.phase, 'idle');
    assert.equal(activated.activePolicyVersion, targetPolicy.version);
    assert.equal(activated.pendingEpoch, null);
    const a = await online.getOwnership({ tenantId, userId: 'a-owner' });
    const b = await online.getOwnership({ tenantId, userId: 'b-owner' });
    const behind = await online.getOwnership({ tenantId, userId: '0-behind-cursor' });
    assert.deepEqual(a.status === 'active' ? { canonical: a.canonical, version: a.policyVersion, revision: a.revision } : a,
      { canonical: 'ab@company.test', version: targetPolicy.version, revision: '1' });
    assert.deepEqual(b.status === 'active' ? { canonical: b.canonical, version: b.policyVersion, revision: b.revision } : b,
      { canonical: 'newname@company.test', version: targetPolicy.version, revision: '2' });
    assert.deepEqual(behind.status === 'active' ? behind.canonical : behind, 'qr@company.test');
    assert.deepEqual(await online.getOwnership({ tenantId, userId: 'c-owner' }), { status: 'revoked' });
    assert.deepEqual(await online.getOwnership({ tenantId, userId: 'z-revoked' }), { status: 'revoked' });

    // A valid revision-captured proof begun before the flip remains valid after a key-only rewrite.
    await online.changeVerifiedEmail({ tenantId, userId: 'proof-owner', email: 'Proof.After+tag@company.test', expectedRevision: capturedProofRevision });
    const completedProof = await online.getOwnership({ tenantId, userId: 'proof-owner' });
    assert.deepEqual(completedProof.status === 'active' ? { canonical: completedProof.canonical, revision: completedProof.revision } : completedProof,
      { canonical: 'proofafter@company.test', revision: '2' });
    await assert.rejects(online.changeVerifiedEmail({ tenantId, userId: 'proof-owner', email: 'Proof.Stale@company.test', expectedRevision: capturedProofRevision }),
      error => (error as { code?: string }).code === 'stale_revision');
    const preserved = await pool!.query(`SELECT delivery_email, revision::pg_catalog.text AS revision
      FROM "${schema}".irondome_gate_online_owner WHERE tenant_id=$1 AND user_id='a-owner'`, [tenantId]);
    assert.deepEqual(preserved.rows[0], { delivery_email: 'A.B+tag@company.test', revision: '1' });
    const cleanup = await online.migration.cleanup({ tenantId, batchSize: 100 });
    assert.ok(cleanup.removed > 0);
    assert.equal((await online.migration.status({ tenantId })).activePolicyVersion, targetPolicy.version);

    // A second live cutover can loosen the custom rules because exact provider-verified
    // delivery addresses survived the first rewrite. No inverse is guessed from canonical keys.
    const restoredPolicy = createEmailPolicy({ 'company.test': { lowercase: true } });
    const second = await online.migration.begin({ tenantId, targetPolicy: restoredPolicy });
    assert.equal(second.phase, 'building');
    let secondStatus = second;
    for (let i = 0; i < 20 && secondStatus.phase === 'building'; i++) {
      secondStatus = await online.migration.backfill({ tenantId, epoch: second.pendingEpoch!, batchSize: 1 });
    }
    assert.equal(secondStatus.phase, 'ready');
    const secondActivated = await online.migration.activate({ tenantId, epoch: second.pendingEpoch! });
    assert.equal(secondActivated.activePolicyVersion, restoredPolicy.version);
    assert.equal((await online.getOwnership({ tenantId, userId: 'a-owner' })).status, 'active');
    const restored = await online.getOwnership({ tenantId, userId: 'a-owner' });
    assert.deepEqual(restored.status === 'active' ? { canonical: restored.canonical, revision: restored.revision } : restored,
      { canonical: 'a.b+tag@company.test', revision: '1' });
    assert.deepEqual(await online.migration.cleanup({ tenantId, batchSize: 100 }).then(result => result.removed > 0), true);
    await assert.rejects(online.migration.activate({ tenantId, epoch: begun.pendingEpoch! }),
      error => (error as { code?: string }).code === 'stale_revision');
    assert.equal((await online.claimVerified({ tenantId, userId: 'restored-rules', email: 'Other.Name+tag@company.test' })).canonical,
      'other.name+tag@company.test');
    assert.equal((await online.claimVerified({ tenantId, userId: 'dots-preserved', email: 'othername+tag@company.test' })).canonical,
      'othername+tag@company.test');
  });

  await t.test('legacy change retries require the current exact verified source through a tag-preserving migration', async () => {
    const tenantId = 'online-exact-change-retry';
    const sourcePolicy = createEmailPolicy({ 'company.test': { stripPlusTag: true } });
    const gate = createOnlinePostgresGate(pool!, { schema, screening, emailPolicy: sourcePolicy });
    const userId = 'owner';
    await gate.claimVerified({ tenantId, userId, email: 'alice+original@company.test' });
    const accepted = { tenantId, userId, email: 'alice+one@company.test', expectedRevision: '1' };
    await gate.changeVerifiedEmail(accepted);
    assert.equal((await gate.changeVerifiedEmail(accepted)).deliveryEmail, accepted.email,
      'a retry of the exact completed change is idempotent');
    await assert.rejects(gate.changeVerifiedEmail({ ...accepted, email: 'alice+two@company.test' }),
      error => (error as { code?: string }).code === 'stale_revision',
      'canonical equivalence cannot prove that this exact change completed');
    const stored = await pool!.query(`SELECT delivery_email,revision::pg_catalog.text AS revision
      FROM "${schema}".irondome_gate_online_owner WHERE tenant_id=$1 AND user_id=$2`, [tenantId, userId]);
    assert.deepEqual(stored.rows[0], { delivery_email: accepted.email, revision: '2' });

    const job = await gate.migration.begin({ tenantId, targetPolicy: createEmailPolicy({ 'company.test': { lowercase: true } }) });
    let progress = job;
    while (progress.phase === 'building') progress = await gate.migration.backfill({ tenantId, epoch: job.pendingEpoch! });
    assert.equal(progress.phase, 'ready');
    await gate.migration.activate({ tenantId, epoch: job.pendingEpoch! });
    assert.equal((await gate.assertActive({ tenantId, userId, email: accepted.email })).canonical, accepted.email);
    await assert.rejects(gate.assertActive({ tenantId, userId, email: 'alice+two@company.test' }));
    assert.equal((await gate.changeVerifiedEmail(accepted)).deliveryEmail, accepted.email,
      'the exact completed change remains retryable after migration');

    // A compatible legacy writer can advance the canonical-only row without
    // refreshing the retained source. A prior-revision source proves no retry.
    const legacyTenant = 'online-exact-retry-unknown';
    const old = createLifecycleGate({ registry: legacyRegistry, screening, canonicalRules: { 'company.test': { stripPlusTag: true } } });
    await gate.claimVerified({ tenantId: legacyTenant, userId, email: accepted.email });
    await old.changeVerifiedEmail({ tenantId: legacyTenant, userId, email: 'alice+unknown@company.test', expectedRevision: '1' });
    await assert.rejects(gate.changeVerifiedEmail({ ...accepted, tenantId: legacyTenant }),
      error => (error as { code?: string }).code === 'stale_revision');

    const missingTenant = 'online-exact-retry-missing';
    await old.claimVerified({ tenantId: missingTenant, userId, email: 'alice+original@company.test' });
    await old.changeVerifiedEmail({ tenantId: missingTenant, userId, email: accepted.email, expectedRevision: '1' });
    await assert.rejects(gate.changeVerifiedEmail({ ...accepted, tenantId: missingTenant }),
      error => (error as { code?: string }).code === 'stale_revision',
      'no retained exact source means a completed change cannot be established');
  });

  await t.test('target collisions block activation while source-policy access and dual writes remain available', async () => {
    const tenantId = 'online-collision';
    await online.claimVerified({ tenantId, userId: 'one', email: 'A.B+tag@company.test' });
    await online.claimVerified({ tenantId, userId: 'two', email: 'ab@company.test' });
    const begun = await online.migration.begin({ tenantId, targetPolicy });
    let status = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 20, includeCounts: true });
    assert.equal(status.phase, 'blocked');
    assert.equal(status.gaps, '1');
    assert.equal((await online.assertActive({ tenantId, userId: 'one', email: 'A.B+tag@company.test' })).canonical,
      'A.B+tag@company.test');
    await online.claimVerified({ tenantId, userId: 'new-source-user', email: 'Different@company.test' });
    await assert.rejects(online.migration.activate({ tenantId, epoch: begun.pendingEpoch! }),
      error => (error as { code?: string }).code === 'identity_conflict');
    await online.revokeUser({ tenantId, userId: 'two' });
    status = await online.migration.status({ tenantId });
    assert.equal(status.phase, 'ready');
    const fixed = await online.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
    assert.equal(fixed.phase, 'idle');
    assert.equal(fixed.activePolicyVersion, targetPolicy.version);
    assert.deepEqual(await online.getOwnership({ tenantId, userId: 'two' }), { status: 'revoked' });
  });

  await t.test('revoking the first target-key winner leaves a retryable loser gap until backfill reruns', async () => {
    const tenantId = 'online-collision-winner-revoked';
    await online.claimVerified({ tenantId, userId: 'one', email: 'A.B+tag@company.test' });
    await online.claimVerified({ tenantId, userId: 'two', email: 'ab@company.test' });
    const begun = await online.migration.begin({ tenantId, targetPolicy });
    let status = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 20, includeCounts: true });
    assert.equal(status.phase, 'blocked');
    assert.equal(status.gaps, '1');
    await online.revokeUser({ tenantId, userId: 'one' });
    status = await online.migration.status({ tenantId });
    assert.equal(status.phase, 'blocked', 'removing the winner does not silently promote an unscanned loser');
    status = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 20, includeCounts: true });
    assert.equal(status.phase, 'ready');
    assert.equal(status.gaps, '0');
    const activated = await online.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
    assert.equal(activated.activePolicyVersion, targetPolicy.version);
    const loser = await online.getOwnership({ tenantId, userId: 'two' });
    assert.deepEqual(loser.status === 'active' ? loser.canonical : loser, 'ab@company.test');
    assert.deepEqual(await online.getOwnership({ tenantId, userId: 'one' }), { status: 'revoked' });
  });

  await t.test('legacy adoption requires exact verified provider witnesses and can be repaired safely', async () => {
    const tenantId = 'online-legacy-adoption';
    await legacyGate.claimVerified({ tenantId, userId: 'legacy-good', email: 'Legacy.Good+tag@company.test' });
    await legacyGate.claimVerified({ tenantId, userId: 'legacy-bad', email: 'Legacy.Bad+tag@company.test' });
    await legacyGate.claimVerified({ tenantId, userId: 'legacy-unverified', email: 'Legacy.Unverified+tag@company.test' });
    await legacyGate.claimVerified({ tenantId, userId: 'legacy-missing', email: 'Legacy.Missing+tag@company.test' });
    await legacyGate.claimVerified({ tenantId, userId: 'legacy-revoked', email: 'Legacy.Deleted@company.test' });
    await legacyGate.revokeUser({ tenantId, userId: 'legacy-revoked' });
    const begun = await online.migration.begin({ tenantId, targetPolicy });
    assert.equal(begun.legacyAdoption, true);
    assert.equal(begun.sourceRows, '4', 'legacy claims made after online-engine construction are included in adoption');

    const invalid = async ({ userId: id }: { userId: string }) => {
      if (id === 'legacy-good') return { userId: id, email: 'Legacy.Good+tag@company.test', emailVerified: true };
      if (id === 'legacy-bad') return { userId: 'another-user', email: 'Legacy.Bad+tag@company.test', emailVerified: true };
      if (id === 'legacy-unverified') return { userId: id, email: 'Legacy.Unverified+tag@company.test', emailVerified: false };
      return null;
    };
    let status = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 20, includeCounts: true, resolveLegacyEmail: invalid });
    assert.equal(status.phase, 'blocked');
    assert.equal(status.gaps, '3');
    await assert.rejects(online.migration.activate({ tenantId, epoch: begun.pendingEpoch! }),
      error => (error as { code?: string }).code === 'identity_conflict');

    // Retry of the unresolved row with a correct proof removes its gap; the already mirrored row needs no resolver.
    status = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 20, includeCounts: true,
      async resolveLegacyEmail({ userId: id }) {
        const emails: Record<string, string> = {
          'legacy-bad': 'Legacy.Bad+tag@company.test',
          'legacy-unverified': 'Legacy.Unverified+tag@company.test',
          'legacy-missing': 'Legacy.Missing+tag@company.test',
        };
        if (!emails[id]) return null;
        return { userId: id, email: emails[id]!, emailVerified: true };
      } });
    assert.equal(status.phase, 'ready');
    const activated = await online.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
    assert.equal(activated.legacyAdoption, false);
    const good = await online.getOwnership({ tenantId, userId: 'legacy-good' });
    assert.deepEqual(good.status === 'active' ? { canonical: good.canonical, revision: good.revision, policy: good.policyVersion } : good,
      { canonical: 'legacygood@company.test', revision: '1', policy: targetPolicy.version });
    assert.deepEqual(await online.getOwnership({ tenantId, userId: 'legacy-revoked' }), { status: 'revoked' });
  });

  await t.test('empty legacy tenancy can adopt the same policy without a blocked phase', async () => {
    const tenantId = 'online-empty-adoption';
    await legacyGate.claimVerified({ tenantId, userId: 'seed', email: 'Seed@company.test' });
    await legacyGate.revokeUser({ tenantId, userId: 'seed' });
    const begun = await online.migration.begin({ tenantId, targetPolicy: DEFAULT_EMAIL_POLICY });
    assert.equal(begun.legacyAdoption, true);
    assert.equal(begun.activePolicyVersion, DEFAULT_EMAIL_POLICY.version);
    assert.equal(begun.pendingPolicyVersion, DEFAULT_EMAIL_POLICY.version);
    const ready = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 10, includeCounts: true });
    assert.equal(ready.phase, 'ready');
    assert.equal(ready.sourceRows, '0');
    const activated = await online.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
    assert.equal(activated.phase, 'idle');
    assert.equal(activated.activePolicyVersion, DEFAULT_EMAIL_POLICY.version);
    assert.equal(activated.legacyAdoption, false);
  });

  await t.test('legacy claim racing after empty online initialization is included in pre-cutover adoption', async () => {
    const tenantId = 'online-rollout-race';
    assert.equal((await online.getEmailPolicy(tenantId)).version, activeSourcePolicy);
    await legacyGate.claimVerified({ tenantId, userId: 'late-legacy-owner', email: 'Late.Owner+tag@company.test' });
    const begun = await online.migration.begin({ tenantId, targetPolicy });
    assert.equal(begun.legacyAdoption, true);
    assert.equal(begun.sourceRows, '1');
    let resolverCalls = 0;
    const ready = await online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 10,
      async resolveLegacyEmail({ userId: id }) {
        resolverCalls++;
        return { userId: id, email: 'Late.Owner+tag@company.test', emailVerified: true };
      } });
    assert.equal(resolverCalls, 1, 'the claim raced after this engine initialized without a shadow delivery source');
    assert.equal(ready.phase, 'ready');
    await online.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
    const owner = await online.getOwnership({ tenantId, userId: 'late-legacy-owner' });
    assert.deepEqual(owner.status === 'active' ? owner.canonical : owner, 'lateowner@company.test');
  });

  await t.test('legacy provider lookup completing after a source revision change cannot restore its stale snapshot', async () => {
    const tenantId = 'online-witness-race';
    await legacyGate.claimVerified({ tenantId, userId: 'owner', email: 'Old.Name+tag@company.test' });
    const begun = await online.migration.begin({ tenantId, targetPolicy });
    let entered!: () => void;
    let release!: () => void;
    const callbackEntered = new Promise<void>(resolve => { entered = resolve; });
    const callbackRelease = new Promise<void>(resolve => { release = resolve; });
    const pendingBackfill = online.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 10,
      async resolveLegacyEmail({ userId: id }) {
        entered();
        await callbackRelease;
        return { userId: id, email: 'Old.Name+tag@company.test', emailVerified: true };
      } });
    await callbackEntered;
    await online.changeVerifiedEmail({ tenantId, userId: 'owner', email: 'Fresh.Name+tag@company.test', expectedRevision: '1' });
    release();
    const status = await pendingBackfill;
    assert.equal(status.phase, 'ready');
    const activated = await online.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
    assert.equal(activated.phase, 'idle');
    const owner = await online.getOwnership({ tenantId, userId: 'owner' });
    assert.deepEqual(owner.status === 'active' ? { canonical: owner.canonical, revision: owner.revision } : owner,
      { canonical: 'freshname@company.test', revision: '2' });
    const stored = await pool!.query(`SELECT delivery_email FROM "${schema}".irondome_gate_online_owner
      WHERE tenant_id=$1 AND user_id='owner'`, [tenantId]);
    assert.deepEqual(stored.rows[0], { delivery_email: 'Fresh.Name+tag@company.test' });
  });

  await t.test('late legacy provider proof cannot replace a newer exact source hydrated at the same revision', async () => {
    const tenantId = 'online-witness-source-refresh';
    const sourceGate = createLifecycleGate({ registry: legacyRegistry, screening,
      canonicalRules: { 'company.test': { lowercase: true, stripPlusTag: true } } });
    const sourcePolicy = sourceGate.emailPolicy;
    const sourceOnline = createOnlinePostgresGate(pool!, { schema, screening, emailPolicy: sourcePolicy });
    const original = 'User+Original@company.test';
    const refreshed = 'User+Fresh+Alias@company.test';
    await sourceGate.claimVerified({ tenantId, userId: 'owner', email: original });
    const begun = await sourceOnline.migration.begin({ tenantId, targetPolicy: createEmailPolicy({ 'company.test': { lowercase: true } }) });
    let entered!: () => void;
    let release!: () => void;
    const callbackEntered = new Promise<void>(resolve => { entered = resolve; });
    const callbackRelease = new Promise<void>(resolve => { release = resolve; });
    const pendingBackfill = sourceOnline.migration.backfill({ tenantId, epoch: begun.pendingEpoch!, batchSize: 10,
      async resolveLegacyEmail({ userId: id }) {
        entered();
        await callbackRelease;
        return { userId: id, email: original, emailVerified: true };
      } });
    await callbackEntered;
    await sourceOnline.claimVerified({ tenantId, userId: 'owner', email: refreshed });
    release();
    const status = await pendingBackfill;
    assert.equal(status.phase, 'ready');
    const activated = await sourceOnline.migration.activate({ tenantId, epoch: begun.pendingEpoch! });
    assert.equal(activated.phase, 'idle');
    const owner = await sourceOnline.getOwnership({ tenantId, userId: 'owner' });
    assert.deepEqual(owner.status === 'active' ? { canonical: owner.canonical, revision: owner.revision } : owner,
      { canonical: 'user+fresh+alias@company.test', revision: '1' });
    const stored = await pool!.query(`SELECT delivery_email FROM "${schema}".irondome_gate_online_owner
      WHERE tenant_id=$1 AND user_id='owner'`, [tenantId]);
    assert.deepEqual(stored.rows[0], { delivery_email: refreshed });
  });

  await t.test('a failed native batch rolls back fully and a lost cutover commit acknowledgement is retry-safe', async () => {
    const batchTenant = 'online-native-batch-rollback';
    await online.claimVerified({ tenantId: batchTenant, userId: 'owner-a', email: 'Rollback.A@company.test' });
    await online.claimVerified({ tenantId: batchTenant, userId: 'owner-b', email: 'Rollback.B@company.test' });
    const bridge = await online.migration.begin({ tenantId: batchTenant, targetPolicy: DEFAULT_EMAIL_POLICY });
    await online.migration.backfill({ tenantId: batchTenant, epoch: bridge.pendingEpoch!, batchSize: 10 });
    await online.migration.activate({ tenantId: batchTenant, epoch: bridge.pendingEpoch! });
    const nativeCutover = await online.migration.begin({ tenantId: batchTenant, targetPolicy });

    let failBatch = false;
    let batchFaulted = false;
    const faultPool = new Proxy(pool!, { get(target, property) {
      if (property === 'connect') return async () => {
        const client = await target.connect();
        return new Proxy(client, { get(inner, key) {
          if (key === 'query') return async (...args: Parameters<typeof client.query>) => {
            const sql = args[0];
            if (failBatch && !batchFaulted && /INSERT INTO .*irondome_gate_online_gap/.test(sql)) {
              batchFaulted = true;
              failBatch = false;
              throw new Error('injected batch query failure');
            }
            return client.query(...args);
          };
          const value = Reflect.get(inner, key);
          return typeof value === 'function' ? value.bind(inner) : value;
        } });
      };
      const value = Reflect.get(target, property);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) as PgPool;
    const faultEngine = createOnlinePostgresGate(faultPool, { schema, screening });
    failBatch = true;
    await assert.rejects(faultEngine.migration.backfill({ tenantId: batchTenant, epoch: nativeCutover.pendingEpoch!, batchSize: 10 }),
      error => (error as { code?: string }).code === 'storage_unavailable');
    assert.equal(batchFaulted, true);
    const afterRollback = await pool!.query(`SELECT
      (SELECT count(*)::int FROM "${schema}".irondome_gate_online_key WHERE tenant_id=$1 AND epoch=$2::uuid) AS keys,
      (SELECT count(*)::int FROM "${schema}".irondome_gate_online_gap WHERE tenant_id=$1 AND epoch=$2::uuid) AS gaps,
      (SELECT cursor_user FROM "${schema}".irondome_gate_online_tenant WHERE tenant_id=$1) AS cursor`,
      [batchTenant, nativeCutover.pendingEpoch]);
    assert.deepEqual(afterRollback.rows[0], { keys: 0, gaps: 0, cursor: null }, 'failed transaction leaves no partial batch or cursor advance');
    const resumed = await online.migration.backfill({ tenantId: batchTenant, epoch: nativeCutover.pendingEpoch!, batchSize: 10 });
    assert.equal(resumed.phase, 'ready');

    const ackTenant = 'online-cutover-lost-ack';
    await online.claimVerified({ tenantId: ackTenant, userId: 'owner', email: 'Ack.Owner@company.test' });
    const pending = await online.migration.begin({ tenantId: ackTenant, targetPolicy });
    await online.migration.backfill({ tenantId: ackTenant, epoch: pending.pendingEpoch!, batchSize: 10 });
    let dropCommitAck = false;
    let dropped = false;
    const ackPool = new Proxy(pool!, { get(target, property) {
      if (property === 'connect') return async () => {
        const client = await target.connect();
        return new Proxy(client, { get(inner, key) {
          if (key === 'query') return async (...args: Parameters<typeof client.query>) => {
            const sql = args[0];
            const result = await client.query(...args);
            if (dropCommitAck && !dropped && /^COMMIT\s*$/i.test(sql.trim())) {
              dropped = true;
              dropCommitAck = false;
              throw new Error('injected lost COMMIT acknowledgement');
            }
            return result;
          };
          const value = Reflect.get(inner, key);
          return typeof value === 'function' ? value.bind(inner) : value;
        } });
      };
      const value = Reflect.get(target, property);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) as PgPool;
    const ackEngine = createOnlinePostgresGate(ackPool, { schema, screening });
    dropCommitAck = true;
    await assert.rejects(ackEngine.migration.activate({ tenantId: ackTenant, epoch: pending.pendingEpoch! }),
      error => (error as { code?: string }).code === 'storage_unavailable');
    assert.equal(dropped, true);
    const committed = await online.migration.status({ tenantId: ackTenant });
    assert.equal(committed.activePolicyVersion, targetPolicy.version, 'the lost reply followed a durable pointer flip');
    assert.equal(committed.pendingEpoch, null);
    const retried = await online.migration.activate({ tenantId: ackTenant, epoch: pending.pendingEpoch! });
    assert.equal(retried.activePolicyVersion, targetPolicy.version);
    assert.equal(retried.phase, 'idle');
  });

  await t.test('concurrent backfill batches lock disjoint source rows before reversed-order target keys', async () => {
    const tenantId = 'online-disjoint-backfill-workers';
    await online.claimVerified({ tenantId, userId: 'a-source', email: 'Zulu+tag@company.test' });
    await online.claimVerified({ tenantId, userId: 'b-source', email: 'Alpha+tag@company.test' });
    await online.claimVerified({ tenantId, userId: 'c-source', email: 'Middle+tag@company.test' });
    const bridge = await online.migration.begin({ tenantId, targetPolicy: DEFAULT_EMAIL_POLICY });
    await online.migration.backfill({ tenantId, epoch: bridge.pendingEpoch!, batchSize: 10 });
    await online.migration.activate({ tenantId, epoch: bridge.pendingEpoch! });
    const targetPolicy = createEmailPolicy({ 'company.test': { lowercase: true } });
    const pending = await online.migration.begin({ tenantId, targetPolicy });

    let insertHeld!: () => void;
    let releaseInsert!: () => void;
    const reachedInsert = new Promise<void>(resolve => { insertHeld = resolve; });
    const waitForRelease = new Promise<void>(resolve => { releaseInsert = resolve; });
    let holdFirstKeyInsert = true;
    const concurrentPool = new Proxy(pool!, { get(target, property) {
      if (property === 'connect') return async () => {
        const client = await target.connect();
        return new Proxy(client, { get(inner, key) {
          if (key === 'query') return async (...args: Parameters<typeof client.query>) => {
            const sql = args[0];
            const result = await client.query(...args);
            if (holdFirstKeyInsert && /INSERT INTO .*irondome_gate_online_key/.test(sql)) {
              holdFirstKeyInsert = false;
              insertHeld();
              await waitForRelease;
            }
            return result;
          };
          const value = Reflect.get(inner, key);
          return typeof value === 'function' ? value.bind(inner) : value;
        } });
      };
      const value = Reflect.get(target, property);
      return typeof value === 'function' ? value.bind(target) : value;
    } }) as PgPool;
    const concurrentEngine = createOnlinePostgresGate(concurrentPool, { schema, screening });
    let firstWorker: Promise<Awaited<ReturnType<typeof concurrentEngine.migration.backfill>>> | undefined;
    try {
      firstWorker = concurrentEngine.migration.backfill({ tenantId, epoch: pending.pendingEpoch!, batchSize: 1 });
      await reachedInsert;
      // Emulate the first worker's completed page boundary while its target key is
      // still uncommitted, giving a second worker the next disjoint source row.
      await pool!.query(`UPDATE "${schema}".irondome_gate_online_tenant SET cursor_user='a-source' WHERE tenant_id=$1`, [tenantId]);
      const secondWorker = await concurrentEngine.migration.backfill({ tenantId, epoch: pending.pendingEpoch!, batchSize: 1 });
      assert.equal(secondWorker.phase, 'building');

      // A writer for a later source row proceeds while the earlier batch holds its
      // target-key insertion; the pending key is dual-written and reconciled later.
      await concurrentEngine.changeVerifiedEmail({ tenantId, userId: 'c-source', email: 'Charlie+tag@company.test', expectedRevision: '1' });
    } finally {
      releaseInsert();
    }
    assert.ok(firstWorker);
    await firstWorker;
    let status = await concurrentEngine.migration.backfill({ tenantId, epoch: pending.pendingEpoch!, batchSize: 1, includeCounts: true });
    for (let i = 0; i < 5 && status.phase === 'building'; i++) {
      status = await concurrentEngine.migration.backfill({ tenantId, epoch: pending.pendingEpoch!, batchSize: 1, includeCounts: true });
    }
    assert.equal(status.phase, 'ready');
    assert.equal(status.gaps, '0');
    await concurrentEngine.migration.activate({ tenantId, epoch: pending.pendingEpoch! });
    const first = await concurrentEngine.getOwnership({ tenantId, userId: 'a-source' });
    const second = await concurrentEngine.getOwnership({ tenantId, userId: 'b-source' });
    const live = await concurrentEngine.getOwnership({ tenantId, userId: 'c-source' });
    assert.deepEqual(first.status === 'active' ? first.canonical : first, 'zulu+tag@company.test');
    assert.deepEqual(second.status === 'active' ? second.canonical : second, 'alpha+tag@company.test');
    assert.deepEqual(live.status === 'active' ? { canonical: live.canonical, revision: live.revision } : live,
      { canonical: 'charlie+tag@company.test', revision: '2' });
  });
});
