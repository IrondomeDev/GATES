import { randomUUID } from 'node:crypto';
import { GateError } from '../../core/errors.js';
import { screenPreparedEmail, type ScreeningClient, type SignupInput, type VerifiedInput } from '../../core/engine.js';
import { createEmailPolicy, requireEmailPolicy, serializeEmailPolicy, validateContext, type DomainCanonicalRules, type EmailPolicy, type EmailPreparation, type PreparedEmail } from '../../core/policy.js';
import { validRevision, type OwnershipState, type UserInput } from '../../core/registry.js';
import type { VerifiedChangeInput } from '../../core/lifecycle.js';
import type { PgClient, PgPool } from './identity.js';
import { createOnlinePostgresStore, type OnlinePostgresStoreOptions } from './online-store.js';

const BIGINT_MAX = 9_223_372_036_854_775_807n;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
type Queryable = Pick<PgClient, 'query'>;
interface Tenant {
  active_epoch: string; active_version: string; pending_epoch: string | null; pending_version: string | null;
  cursor_user: string | null; scan_done: boolean; legacy_mode: boolean;
}
interface Owner {
  user_id: string; canonical_email: string; policy_version: string; revision: string;
  delivery_email: string | null; claimed_at: string;
}
export interface OnlinePostgresGateOptions extends OnlinePostgresStoreOptions {
  screening: ScreeningClient;
  canonicalRules?: DomainCanonicalRules;
  emailPolicy?: EmailPolicy;
  /** Bound process memory for immutable policy configuration, never for addresses. Default 64. */
  maxCachedPolicies?: number;
}
export interface LegacyIdentitySource {
  readonly tenantId: string; readonly userId: string; readonly canonical: string;
  readonly policyVersion: string; readonly revision: string;
}
export interface VerifiedLegacyEmail {
  readonly userId: string; readonly email: string; readonly emailVerified: boolean;
}
export interface OnlinePolicyStatus {
  readonly activePolicyVersion: string;
  readonly pendingPolicyVersion: string | null;
  readonly activeEpoch: string;
  readonly pendingEpoch: string | null;
  readonly phase: 'idle' | 'building' | 'blocked' | 'ready';
  readonly scanComplete: boolean;
  /** Exact counts only when requested; batch progress does not repeatedly scan the tenant. */
  readonly sourceRows: string | null;
  readonly gaps: string | null;
  readonly legacyAdoption: boolean;
}

function check(signal?: AbortSignal) { if (signal?.aborted) throw new GateError('cancelled'); }
function safe<T>(work: () => Promise<T>): Promise<T> {
  return work().catch(error => { throw error instanceof GateError ? error : new GateError('storage_unavailable', true); });
}
function epoch(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !UUID.test(value)) throw new TypeError('Invalid policy migration epoch');
}
function batchLimit(value: number | undefined): number {
  const size = value ?? 100;
  if (!Number.isInteger(size) || size < 1 || size > 1000) throw new TypeError('Invalid policy migration batch size');
  return size;
}

/**
 * Live PostgreSQL ownership with stable principals, durable verified delivery
 * sources, dual-written policy epochs and a constant-size atomic pointer flip.
 * Deploy this engine to every reader/writer before beginning a legacy adoption.
 */
export function createOnlinePostgresGate(pool: PgPool, options: OnlinePostgresGateOptions) {
  if (options.emailPolicy && options.canonicalRules !== undefined) throw new TypeError('Choose emailPolicy or canonicalRules');
  const initial = requireEmailPolicy(options.emailPolicy ?? createEmailPolicy(options.canonicalRules));
  const schema = options.schema ?? 'public';
  const store = createOnlinePostgresStore(pool, { schema,
    ...(options.lockTimeoutMs === undefined ? {} : { lockTimeoutMs: options.lockTimeoutMs }),
    ...(options.statementTimeoutMs === undefined ? {} : { statementTimeoutMs: options.statementTimeoutMs }),
    ...(options.exclusiveWaitMs === undefined ? {} : { exclusiveWaitMs: options.exclusiveWaitMs }),
  });
  const table = store.tables;
  const legacy = table.legacyIdentity;
  const legacyPolicy = table.legacyPolicy;
  const screening = options.screening;
  const cacheLimit = options.maxCachedPolicies ?? 64;
  if (!Number.isInteger(cacheLimit) || cacheLimit < 2 || cacheLimit > 1024) throw new TypeError('Invalid policy cache size');
  const policies = new Map<string, EmailPolicy>();
  function remember(policy: EmailPolicy) {
    policies.delete(policy.version); policies.set(policy.version, policy);
    if (policies.size > cacheLimit) policies.delete(policies.keys().next().value!);
    return policy;
  }
  async function loadPolicy(version: string, db: Queryable = pool): Promise<EmailPolicy> {
    const cached = policies.get(version);
    if (cached) return remember(cached);
    const result = await db.query(`SELECT rules FROM ${table.policy} WHERE policy_version=$1`, [version]);
    if (result.rows.length !== 1) throw new GateError('policy_mismatch');
    const policy = createEmailPolicy(result.rows[0]!.rules as DomainCanonicalRules);
    if (policy.version !== version) throw new GateError('policy_mismatch');
    return remember(policy);
  }
  async function persistPolicy(policy: EmailPolicy) {
    await pool.query(`INSERT INTO ${table.policy} (policy_version,rules) VALUES ($1,$2::pg_catalog.jsonb) ON CONFLICT (policy_version) DO NOTHING`,
      [policy.version, JSON.stringify(serializeEmailPolicy(policy))]);
    const result = await pool.query(`SELECT rules FROM ${table.policy} WHERE policy_version=$1`, [policy.version]);
    if (result.rows.length !== 1 || createEmailPolicy(result.rows[0]!.rules as DomainCanonicalRules).version !== policy.version) throw new GateError('policy_mismatch');
    remember(policy);
  }
  let initialized: Promise<void> | undefined;
  async function initialize() {
    initialized ??= persistPolicy(initial).catch(error => { initialized = undefined; throw error; });
    await initialized;
  }
  async function tenant(db: Queryable, tenantId: string): Promise<Tenant> {
    const result = await db.query(`SELECT active_epoch::pg_catalog.text,active_version,pending_epoch::pg_catalog.text,pending_version,
      cursor_user,scan_done,legacy_mode FROM ${table.tenant} WHERE tenant_id=$1`, [tenantId]);
    if (result.rows.length !== 1) throw new GateError('storage_unavailable', true);
    return result.rows[0] as unknown as Tenant;
  }
  async function ensureTenant(tenantId: string) {
    validateContext(tenantId); await initialize();
    const exists = await pool.query(`SELECT 1 FROM ${table.tenant} WHERE tenant_id=$1`, [tenantId]);
    if (exists.rows.length) return;
    await store.exclusiveTenant(tenantId, async db => {
      const exists = await db.query(`SELECT 1 FROM ${table.tenant} WHERE tenant_id=$1`, [tenantId]);
      if (exists.rows.length) return;
      const prior = await db.query(`SELECT policy_version FROM ${legacyPolicy} WHERE tenant_id=$1`, [tenantId]);
      if (prior.rows.length && prior.rows[0]!.policy_version !== initial.version) throw new GateError('policy_mismatch');
      await db.query(`INSERT INTO ${table.tenant} (tenant_id,active_epoch,active_version,legacy_mode) VALUES ($1,$2::pg_catalog.uuid,$3,$4)`,
        // Bridge mode is intentional even for an initially empty tenant: old
        // application instances may still create legacy rows during rollout.
        [tenantId, randomUUID(), initial.version, true]);
    });
  }
  async function revoked(db: Queryable, tenantId: string, userId: string): Promise<boolean> {
    return (await db.query(`SELECT 1 FROM ${table.revoked} WHERE tenant_id=$1 AND user_id=$2`, [tenantId, userId])).rows.length > 0;
  }
  async function owner(db: Queryable, tenantId: string, userId: string, state: Tenant, lock = false): Promise<Owner | null> {
    const result = state.legacy_mode
      ? await db.query(`SELECT user_id,canonical_email,policy_version,revision::pg_catalog.text,NULL AS delivery_email,
          pg_catalog.to_char(claimed_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US') || '+00' AS claimed_at
          FROM ${legacy} WHERE tenant_id=$1 AND user_id=$2${lock ? ' FOR UPDATE' : ''}`, [tenantId, userId])
      : await db.query(`SELECT o.user_id,k.canonical_email,$3::pg_catalog.text AS policy_version,o.revision::pg_catalog.text,o.delivery_email,
          pg_catalog.to_char(o.claimed_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US') || '+00' AS claimed_at
          FROM ${table.owner} o JOIN ${table.key} k ON k.tenant_id=o.tenant_id AND k.user_id=o.user_id AND k.epoch=$4::pg_catalog.uuid
          WHERE o.tenant_id=$1 AND o.user_id=$2${lock ? ' FOR UPDATE OF o' : ''}`, [tenantId, userId, state.active_version, state.active_epoch]);
    if (result.rows.length > 1) throw new GateError('storage_unavailable', true);
    const value = (result.rows[0] as unknown as Owner | undefined) ?? null;
    if (value && value.policy_version !== state.active_version) throw new GateError('policy_mismatch');
    return value;
  }
  async function putKey(db: Queryable, tenantId: string, userId: string, keyEpoch: string, canonical: string): Promise<boolean> {
    await db.query(`DELETE FROM ${table.key} WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid AND user_id=$3 AND canonical_email<>$4`,
      [tenantId, keyEpoch, userId, canonical]);
    await db.query(`INSERT INTO ${table.key} (tenant_id,epoch,canonical_email,user_id) VALUES ($1,$2::pg_catalog.uuid,$3,$4) ON CONFLICT DO NOTHING`,
      [tenantId, keyEpoch, canonical, userId]);
    const actual = await db.query(`SELECT user_id FROM ${table.key} WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid AND canonical_email=$3`,
      [tenantId, keyEpoch, canonical]);
    return actual.rows.length === 1 && actual.rows[0]!.user_id === userId;
  }
  async function gap(db: Queryable, tenantId: string, keyEpoch: string, userId: string, reason: string) {
    await db.query(`INSERT INTO ${table.gap} (tenant_id,epoch,user_id,reason) VALUES ($1,$2::pg_catalog.uuid,$3,$4)
      ON CONFLICT (tenant_id,epoch,user_id) DO UPDATE SET reason=EXCLUDED.reason`, [tenantId, keyEpoch, userId, reason]);
  }
  async function pendingKey(db: Queryable, tenantId: string, userId: string, delivery: string, state: Tenant) {
    if (!state.pending_epoch || !state.pending_version) return;
    let canonical: string;
    try { canonical = (await loadPolicy(state.pending_version, db)).prepareEmail(delivery).canonical; }
    catch (error) {
      if (!(error instanceof GateError) || error.code !== 'invalid_email') throw error;
      await db.query(`DELETE FROM ${table.key} WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid AND user_id=$3`, [tenantId, state.pending_epoch, userId]);
      await gap(db, tenantId, state.pending_epoch, userId, 'invalid-target'); return;
    }
    if (!await putKey(db, tenantId, userId, state.pending_epoch, canonical)) {
      await gap(db, tenantId, state.pending_epoch, userId, 'collision'); return;
    }
    await db.query(`DELETE FROM ${table.gap} WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid AND user_id=$3`, [tenantId, state.pending_epoch, userId]);
  }
  async function mirrorLegacy(db: Queryable, tenantId: string, row: Owner, delivery: string, state: Tenant, stagePending = true) {
    await db.query(`INSERT INTO ${table.owner} (tenant_id,user_id,delivery_email,revision,claimed_at)
      VALUES ($1,$2,$3,$4::pg_catalog.int8,$5::pg_catalog.timestamptz)
      ON CONFLICT (tenant_id,user_id) DO UPDATE SET delivery_email=EXCLUDED.delivery_email,revision=EXCLUDED.revision,claimed_at=EXCLUDED.claimed_at`,
      [tenantId, row.user_id, delivery, row.revision, row.claimed_at]);
    // Legacy rows remain authoritative during the rolling bridge. A source
    // shadow index could be stale after a still-compatible legacy writer, and
    // must never reject a valid source-policy claim. Only target keys are built.
    if (stagePending) await pendingKey(db, tenantId, row.user_id, delivery, state);
  }
  async function rebuildTargetBatch(db: Queryable, tenantId: string, state: Tenant, ids: string[]) {
    if (!ids.length || !state.pending_epoch || !state.pending_version) return;
    // Lock all source rows before any target key is written. Tuple locks avoid
    // retaining one shared-memory advisory lock for every row in a large batch.
    await db.query(`SELECT user_id FROM ${table.owner} WHERE tenant_id=$1 AND user_id=ANY($2::pg_catalog.text[])
      ORDER BY user_id COLLATE "C" FOR UPDATE`, [tenantId, ids]);
    const current = await db.query(`SELECT o.user_id,o.delivery_email,k.canonical_email,r.user_id IS NOT NULL AS revoked
      FROM ${table.owner} o ${state.legacy_mode
        ? `LEFT JOIN ${legacy} k ON k.tenant_id=o.tenant_id AND k.user_id=o.user_id`
        : `LEFT JOIN ${table.key} k ON k.tenant_id=o.tenant_id AND k.user_id=o.user_id AND k.epoch=$3::pg_catalog.uuid`}
      LEFT JOIN ${table.revoked} r ON r.tenant_id=o.tenant_id AND r.user_id=o.user_id
      WHERE o.tenant_id=$1 AND o.user_id=ANY($2::pg_catalog.text[])`, state.legacy_mode ? [tenantId, ids] : [tenantId, ids, state.active_epoch]);
    const sourcePolicy = await loadPolicy(state.active_version, db);
    const targetPolicy = await loadPolicy(state.pending_version, db);
    const candidates: Array<{ userId: string; canonical: string }> = [];
    const invalid: Array<{ userId: string; reason: string }> = [];
    const dead: string[] = [];
    const present = new Set<string>();
    for (const row of current.rows) {
      const id = String(row.user_id); present.add(id);
      if (row.revoked === true) { dead.push(id); continue; }
      try {
        if (sourcePolicy.prepareEmail(row.delivery_email).canonical !== row.canonical_email) {
          invalid.push({ userId: id, reason: 'invalid-source' }); continue;
        }
      } catch { invalid.push({ userId: id, reason: 'invalid-source' }); continue; }
      try { candidates.push({ userId: id, canonical: targetPolicy.prepareEmail(row.delivery_email).canonical }); }
      catch { invalid.push({ userId: id, reason: 'invalid-target' }); }
    }
    await db.query(`DELETE FROM ${table.key} WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid AND user_id=ANY($3::pg_catalog.text[])`, [tenantId, state.pending_epoch, ids]);
    const gone = [...dead, ...ids.filter(id => !present.has(id))];
    if (gone.length) {
      await db.query(`DELETE FROM ${table.owner} WHERE tenant_id=$1 AND user_id=ANY($2::pg_catalog.text[])`, [tenantId, dead]);
      await db.query(`DELETE FROM ${table.gap} WHERE tenant_id=$1 AND user_id=ANY($2::pg_catalog.text[])`, [tenantId, gone]);
    }
    // Matching the unique-index order avoids cross-batch unique-key deadlocks.
    candidates.sort((a, b) => a.canonical < b.canonical ? -1 : a.canonical > b.canonical ? 1 : a.userId < b.userId ? -1 : 1);
    if (candidates.length) {
      await db.query(`INSERT INTO ${table.key} (tenant_id,epoch,canonical_email,user_id)
        SELECT $1,$2::pg_catalog.uuid,input.canonical,input.user_id FROM
        ROWS FROM (pg_catalog.unnest($3::pg_catalog.text[]),pg_catalog.unnest($4::pg_catalog.text[])) AS input(canonical,user_id)
        ORDER BY input.canonical COLLATE "C",input.user_id COLLATE "C" ON CONFLICT DO NOTHING`,
        [tenantId, state.pending_epoch, candidates.map(row => row.canonical), candidates.map(row => row.userId)]);
      await db.query(`INSERT INTO ${table.gap} (tenant_id,epoch,user_id,reason)
        SELECT $1,$2::pg_catalog.uuid,input.user_id,'collision' FROM pg_catalog.unnest($3::pg_catalog.text[]) AS input(user_id)
        WHERE NOT EXISTS(SELECT 1 FROM ${table.key} k WHERE k.tenant_id=$1 AND k.epoch=$2::pg_catalog.uuid AND k.user_id=input.user_id)
        ON CONFLICT (tenant_id,epoch,user_id) DO UPDATE SET reason=EXCLUDED.reason`,
        [tenantId, state.pending_epoch, candidates.map(row => row.userId)]);
      await db.query(`DELETE FROM ${table.gap} g WHERE g.tenant_id=$1 AND g.epoch=$2::pg_catalog.uuid AND g.user_id=ANY($3::pg_catalog.text[])
        AND EXISTS(SELECT 1 FROM ${table.key} k WHERE k.tenant_id=g.tenant_id AND k.epoch=g.epoch AND k.user_id=g.user_id)`,
        [tenantId, state.pending_epoch, candidates.map(row => row.userId)]);
    }
    if (invalid.length) await db.query(`INSERT INTO ${table.gap} (tenant_id,epoch,user_id,reason)
      SELECT $1,$2::pg_catalog.uuid,input.user_id,input.reason FROM
      ROWS FROM (pg_catalog.unnest($3::pg_catalog.text[]),pg_catalog.unnest($4::pg_catalog.text[])) AS input(user_id,reason)
      ON CONFLICT (tenant_id,epoch,user_id) DO UPDATE SET reason=EXCLUDED.reason`,
      [tenantId, state.pending_epoch, invalid.map(row => row.userId), invalid.map(row => row.reason)]);
  }
  async function readOwnership(tenantId: string, userId: string): Promise<{ state: Tenant; row: Owner | null; revoked: boolean }> {
    // One MVCC statement observes the pointer and matching key together. Reads
    // take no advisory locks and remain available during the atomic epoch flip.
    const result = await pool.query(`SELECT t.active_epoch::pg_catalog.text,t.active_version,t.pending_epoch::pg_catalog.text,
      t.pending_version,t.cursor_user,t.scan_done,t.legacy_mode,
      CASE WHEN t.legacy_mode THEN old.user_id ELSE k.user_id END AS user_id,
      CASE WHEN t.legacy_mode THEN old.canonical_email ELSE k.canonical_email END AS canonical_email,
      CASE WHEN t.legacy_mode THEN old.policy_version ELSE t.active_version END AS policy_version,
      CASE WHEN t.legacy_mode THEN old.revision ELSE o.revision END::pg_catalog.text AS revision,
      o.delivery_email, r.user_id IS NOT NULL AS revoked
      FROM ${table.tenant} t
      LEFT JOIN ${legacy} old ON t.legacy_mode AND old.tenant_id=t.tenant_id AND old.user_id=$2
      LEFT JOIN ${table.owner} o ON NOT t.legacy_mode AND o.tenant_id=t.tenant_id AND o.user_id=$2
      LEFT JOIN ${table.key} k ON NOT t.legacy_mode AND k.tenant_id=o.tenant_id AND k.user_id=o.user_id AND k.epoch=t.active_epoch
      LEFT JOIN ${table.revoked} r ON r.tenant_id=t.tenant_id AND r.user_id=$2
      WHERE t.tenant_id=$1`, [tenantId, userId]);
    if (!result.rows.length) { await ensureTenant(tenantId); return readOwnership(tenantId, userId); }
    if (result.rows.length !== 1) throw new GateError('storage_unavailable', true);
    const value = result.rows[0]!;
    if (value.user_id !== null && value.policy_version !== value.active_version) throw new GateError('policy_mismatch');
    return { state: value as unknown as Tenant, row: value.user_id === null ? null : value as unknown as Owner, revoked: value.revoked === true };
  }
  const prepare: EmailPreparation = input => {
    const tenantId = input.tenantId, email = input.email, version = input.policyVersion, signal = input.signal;
    validateContext(tenantId); check(signal);
    return safe(async () => {
      await initialize();
      let selected = version;
      if (selected === undefined) {
        const current = await pool.query(`SELECT active_version FROM ${table.tenant} WHERE tenant_id=$1`, [tenantId]);
        if (!current.rows.length) { await ensureTenant(tenantId); selected = (await tenant(pool, tenantId)).active_version; }
        else selected = String(current.rows[0]!.active_version);
      }
      const policy = await loadPolicy(selected); check(signal); return policy.prepareEmail(email);
    });
  };
  async function screenSignup(raw: SignupInput): Promise<PreparedEmail> {
    const input = { ...raw };
    const prepared = await prepare(input);
    return screenPreparedEmail(screening, prepared, input.signal);
  }
  async function getOwnership(raw: UserInput & { signal?: AbortSignal }): Promise<OwnershipState> {
    const input = { ...raw }; validateContext(input.tenantId, input.userId); check(input.signal);
    return safe(async () => {
      const current = await readOwnership(input.tenantId, input.userId); check(input.signal);
      if (current.revoked) return Object.freeze({ status: 'revoked' });
      if (!current.row) return Object.freeze({ status: 'unclaimed' });
      return Object.freeze({ status: 'active', canonical: current.row.canonical_email, policyVersion: current.state.active_version,
        revision: current.row.revision });
    });
  }
  async function assertActive(raw: VerifiedInput): Promise<PreparedEmail> {
    const input = { ...raw }; validateContext(input.tenantId, input.userId); check(input.signal);
    return safe(async () => {
      const current = await readOwnership(input.tenantId, input.userId);
      if (current.revoked || !current.row) throw new GateError('ownership_required');
      const prepared = (await loadPolicy(current.state.active_version)).prepareEmail(input.email);
      if (prepared.canonical !== current.row.canonical_email) throw new GateError('ownership_required');
      check(input.signal); return prepared;
    });
  }
  async function claimVerified(raw: VerifiedInput): Promise<PreparedEmail> {
    const input = { ...raw }; validateContext(input.tenantId, input.userId);
    const screened = await screenSignup(input); check(input.signal);
    return safe(async () => {
      const result = await store.transaction({ tenantId: input.tenantId, userId: input.userId }, async db => {
        check(input.signal);
        const state = await tenant(db, input.tenantId);
        const prepared = (await loadPolicy(state.active_version, db)).prepareEmail(screened.deliveryEmail);
        if (await revoked(db, input.tenantId, input.userId)) throw new GateError('identity_revoked');
        const prior = await owner(db, input.tenantId, input.userId, state, true);
        if (prior) {
          if (prior.canonical_email !== prepared.canonical) throw new GateError('identity_conflict');
          // Retries hydrate a missing source, never overwrite an established
          // exact source at the same user revision. Exact changes use the CAS.
          if (state.legacy_mode) {
            const tracked = await db.query(`SELECT delivery_email,revision::pg_catalog.text FROM ${table.owner} WHERE tenant_id=$1 AND user_id=$2`,
              [input.tenantId, input.userId]);
            const delivery = tracked.rows[0]?.revision === prior.revision && typeof tracked.rows[0]?.delivery_email === 'string'
              ? tracked.rows[0].delivery_email : prepared.deliveryEmail;
            await mirrorLegacy(db, input.tenantId, prior, delivery, state);
          }
          return prepared;
        }
        if (state.legacy_mode) {
          const inserted = await db.query(`INSERT INTO ${legacy} (tenant_id,user_id,canonical_email,policy_version)
            VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id,canonical_email) DO NOTHING RETURNING user_id`,
            [input.tenantId, input.userId, prepared.canonical, state.active_version]);
          if (!inserted.rows.length) throw new GateError('identity_conflict');
          await mirrorLegacy(db, input.tenantId, (await owner(db, input.tenantId, input.userId, state))!, prepared.deliveryEmail, state);
        } else {
          await db.query(`INSERT INTO ${table.owner} (tenant_id,user_id,delivery_email) VALUES ($1,$2,$3)`,
            [input.tenantId, input.userId, prepared.deliveryEmail]);
          if (!await putKey(db, input.tenantId, input.userId, state.active_epoch, prepared.canonical)) throw new GateError('identity_conflict');
          await pendingKey(db, input.tenantId, input.userId, prepared.deliveryEmail, state);
        }
        return prepared;
      });
      check(input.signal); return result;
    });
  }
  async function changeVerifiedEmail(raw: VerifiedChangeInput): Promise<PreparedEmail> {
    const input = { ...raw }; validateContext(input.tenantId, input.userId);
    if (!validRevision(input.expectedRevision)) throw new GateError('invalid_context');
    const screened = await screenSignup(input); check(input.signal);
    return safe(async () => {
      const result = await store.transaction({ tenantId: input.tenantId, userId: input.userId }, async db => {
        check(input.signal);
        const state = await tenant(db, input.tenantId);
        const prepared = (await loadPolicy(state.active_version, db)).prepareEmail(screened.deliveryEmail);
        if (await revoked(db, input.tenantId, input.userId)) throw new GateError('identity_revoked');
        const prior = await owner(db, input.tenantId, input.userId, state, true);
        if (!prior) throw new GateError('stale_revision');
        const revision = BigInt(prior.revision);
        if (revision === BigInt(input.expectedRevision) + 1n && prior.canonical_email === prepared.canonical) {
          // A canonical-only bridge row cannot prove which exact change won.
          // Accept a lost-acknowledgement retry only with a source recorded at
          // this revision; older mirrors may belong to a legacy writer's past.
          let delivery = prior.delivery_email;
          if (state.legacy_mode) {
            const tracked = await db.query(`SELECT delivery_email,revision::pg_catalog.text AS revision
              FROM ${table.owner} WHERE tenant_id=$1 AND user_id=$2`, [input.tenantId, input.userId]);
            delivery = tracked.rows[0]?.revision === prior.revision && typeof tracked.rows[0]?.delivery_email === 'string'
              ? tracked.rows[0].delivery_email : null;
          }
          if (delivery === prepared.deliveryEmail) return prepared;
        }
        if (revision.toString() !== input.expectedRevision) throw new GateError('stale_revision');
        if (revision >= BIGINT_MAX - 1n) throw new GateError('stale_revision');
        if (state.legacy_mode) {
          await db.query(`UPDATE ${legacy} SET canonical_email=$3,revision=revision+1,claimed_at=CURRENT_TIMESTAMP WHERE tenant_id=$1 AND user_id=$2`,
            [input.tenantId, input.userId, prepared.canonical]);
          await mirrorLegacy(db, input.tenantId, (await owner(db, input.tenantId, input.userId, state))!, prepared.deliveryEmail, state);
        } else {
          await db.query(`UPDATE ${table.owner} SET delivery_email=$3,revision=revision+1,claimed_at=CURRENT_TIMESTAMP WHERE tenant_id=$1 AND user_id=$2`,
            [input.tenantId, input.userId, prepared.deliveryEmail]);
          if (!await putKey(db, input.tenantId, input.userId, state.active_epoch, prepared.canonical)) throw new GateError('identity_conflict');
          await pendingKey(db, input.tenantId, input.userId, prepared.deliveryEmail, state);
        }
        return prepared;
      });
      check(input.signal); return result;
    });
  }
  async function revokeUser(raw: UserInput & { signal?: AbortSignal }): Promise<void> {
    const input = { ...raw }; validateContext(input.tenantId, input.userId); check(input.signal);
    return safe(async () => {
      await ensureTenant(input.tenantId);
      await store.transaction({ tenantId: input.tenantId, userId: input.userId }, async db => {
        check(input.signal);
        await db.query(`INSERT INTO ${table.revoked} (tenant_id,user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, [input.tenantId, input.userId]);
        // Erase any retained bridge copy too, even after epoch activation.
        await db.query(`DELETE FROM ${legacy} WHERE tenant_id=$1 AND user_id=$2`, [input.tenantId, input.userId]);
        await db.query(`DELETE FROM ${table.owner} WHERE tenant_id=$1 AND user_id=$2`, [input.tenantId, input.userId]);
        await db.query(`DELETE FROM ${table.gap} WHERE tenant_id=$1 AND user_id=$2`, [input.tenantId, input.userId]);
      });
      check(input.signal);
    });
  }

  async function status(tenantId: string, includeCounts = true): Promise<OnlinePolicyStatus> {
    validateContext(tenantId); await ensureTenant(tenantId);
    if (typeof includeCounts !== 'boolean') throw new TypeError('Invalid policy progress option');
    const state = await tenant(pool, tenantId);
    const sources = state.legacy_mode ? legacy : table.owner;
    const counts = includeCounts ? await pool.query(`SELECT
      (SELECT pg_catalog.count(*)::pg_catalog.text FROM ${sources} WHERE tenant_id=$1) AS owners,
      (SELECT pg_catalog.count(*)::pg_catalog.text FROM ${table.gap} WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid) AS gaps`,
      [tenantId, state.pending_epoch]) : null;
    const hasGap = counts ? counts.rows[0]!.gaps !== '0' : (await pool.query(
      `SELECT 1 FROM ${table.gap} WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid LIMIT 1`, [tenantId, state.pending_epoch])).rows.length > 0;
    return Object.freeze({ activePolicyVersion: state.active_version, pendingPolicyVersion: state.pending_version,
      activeEpoch: state.active_epoch, pendingEpoch: state.pending_epoch, scanComplete: state.scan_done,
      phase: !state.pending_epoch ? 'idle' : !state.scan_done ? 'building' : hasGap ? 'blocked' : 'ready',
      sourceRows: counts ? String(counts.rows[0]!.owners) : null,
      gaps: counts ? String(counts.rows[0]!.gaps) : hasGap ? null : '0', legacyAdoption: state.legacy_mode });
  }
  async function begin(raw: { tenantId: string; targetPolicy: EmailPolicy }): Promise<OnlinePolicyStatus> {
    const tenantId = raw.tenantId, target = requireEmailPolicy(raw.targetPolicy); validateContext(tenantId);
    return safe(async () => {
      await ensureTenant(tenantId); await persistPolicy(target);
      await store.cutoverTenant(tenantId, async db => {
        const state = await tenant(db, tenantId);
        if (state.pending_version === target.version) return;
        if (state.pending_epoch) throw new GateError('policy_mismatch', true);
        if (state.active_version === target.version && !state.legacy_mode) return;
        await db.query(`UPDATE ${table.tenant} SET pending_epoch=$2::pg_catalog.uuid,pending_version=$3,
          cursor_user=NULL,scan_done=false,protocol_enforced=true WHERE tenant_id=$1`, [tenantId, randomUUID(), target.version]);
      });
      return status(tenantId);
    });
  }
  async function backfill(raw: { tenantId: string; epoch: string; batchSize?: number; includeCounts?: boolean;
    resolveLegacyEmail?: (row: Readonly<LegacyIdentitySource>) => Promise<VerifiedLegacyEmail | null> }): Promise<OnlinePolicyStatus> {
    const tenantId = raw.tenantId, expectedEpoch = raw.epoch, size = batchLimit(raw.batchSize), resolveLegacy = raw.resolveLegacyEmail,
      includeCounts = raw.includeCounts ?? false;
    validateContext(tenantId); epoch(expectedEpoch);
    if (typeof includeCounts !== 'boolean') throw new TypeError('Invalid policy progress option');
    return safe(async () => {
      await ensureTenant(tenantId);
      const start = await tenant(pool, tenantId);
      if (start.pending_epoch !== expectedEpoch) throw new GateError('stale_revision');
      const sources = start.legacy_mode ? legacy : table.owner;
      const batch = await pool.query(`SELECT s.user_id FROM ${sources} s WHERE s.tenant_id=$1 AND
        ($2::pg_catalog.bool AND EXISTS (SELECT 1 FROM ${table.gap} g WHERE g.tenant_id=s.tenant_id AND g.user_id=s.user_id AND g.epoch=$3::pg_catalog.uuid)
          OR NOT $2::pg_catalog.bool AND ($4::pg_catalog.text IS NULL OR s.user_id>$4 COLLATE "C"))
        ORDER BY s.user_id COLLATE "C" LIMIT $5`, [tenantId, start.scan_done, expectedEpoch, start.cursor_user, size]);
      // Provider HTTP reads happen outside every database/advisory transaction.
      const witnesses = new Map<string, { row: Owner; proof: VerifiedLegacyEmail | null }>();
      if (start.legacy_mode) for (const value of batch.rows) {
        const id = String(value.user_id), row = await owner(pool, tenantId, id, start);
        if (!row) continue;
        const mirrored = await pool.query(`SELECT delivery_email,revision::pg_catalog.text FROM ${table.owner} WHERE tenant_id=$1 AND user_id=$2`, [tenantId, id]);
        let proof: VerifiedLegacyEmail | null = null;
        if (mirrored.rows[0]?.revision === row.revision && typeof mirrored.rows[0]?.delivery_email === 'string') {
          proof = { userId: id, email: mirrored.rows[0].delivery_email, emailVerified: true };
        } else if (resolveLegacy) {
          try {
            const result = await resolveLegacy(Object.freeze({ tenantId, userId: id, canonical: row.canonical_email,
              policyVersion: row.policy_version, revision: row.revision }));
            proof = result ? Object.freeze({ userId: result.userId, email: result.email, emailVerified: result.emailVerified }) : null;
          } catch { proof = null; }
        }
        witnesses.set(id, { row, proof });
      }
      await store.transaction({ tenantId }, async db => {
        const state = await tenant(db, tenantId);
        if (state.pending_epoch !== expectedEpoch) throw new GateError('stale_revision');
        if (!state.legacy_mode) {
          await rebuildTargetBatch(db, tenantId, state, batch.rows.map(value => String(value.user_id)));
        } else {
          const ids = batch.rows.map(value => String(value.user_id));
          await db.query(`SELECT user_id FROM ${legacy} WHERE tenant_id=$1 AND user_id=ANY($2::pg_catalog.text[])
            ORDER BY user_id COLLATE "C" FOR UPDATE`, [tenantId, ids]);
          const hydrated: string[] = [];
          for (const value of batch.rows) {
            const id = String(value.user_id);
            const row = await owner(db, tenantId, id, state);
            if (!row || await revoked(db, tenantId, id)) {
              await db.query(`DELETE FROM ${table.owner} WHERE tenant_id=$1 AND user_id=$2`, [tenantId, id]);
              await db.query(`DELETE FROM ${table.gap} WHERE tenant_id=$1 AND user_id=$2`, [tenantId, id]);
              continue;
            }
            const tracked = await db.query(`SELECT delivery_email,revision::pg_catalog.text FROM ${table.owner} WHERE tenant_id=$1 AND user_id=$2`, [tenantId, id]);
            if (tracked.rows[0]?.revision === row.revision && typeof tracked.rows[0]?.delivery_email === 'string') {
              let valid = false;
              try { valid = (await loadPolicy(state.active_version, db)).prepareEmail(tracked.rows[0].delivery_email).canonical === row.canonical_email; }
              catch { /* Corrupt established sources require operator recovery. */ }
              if (valid) {
                await mirrorLegacy(db, tenantId, row, tracked.rows[0].delivery_email, state, false);
                hydrated.push(id); continue;
              }
              await gap(db, tenantId, expectedEpoch, id, 'invalid-source'); continue;
            }
            const witness = witnesses.get(id);
            if (!witness || witness.row.revision !== row.revision || witness.row.canonical_email !== row.canonical_email) {
              await gap(db, tenantId, expectedEpoch, id, 'source-required'); continue;
            }
            const proof = witness.proof;
            let delivery: string | undefined;
            if (proof?.emailVerified === true && proof.userId === id) {
              try {
                const source = (await loadPolicy(state.active_version, db)).prepareEmail(proof.email);
                if (source.canonical === row.canonical_email) delivery = source.deliveryEmail;
              } catch { /* Invalid provider snapshots remain a gap. */ }
            }
            if (!delivery) { await gap(db, tenantId, expectedEpoch, id, proof ? 'invalid-source' : 'source-required'); continue; }
            await mirrorLegacy(db, tenantId, row, delivery, state, false); hydrated.push(id);
          }
          await rebuildTargetBatch(db, tenantId, state, hydrated);
        }
        if (!start.scan_done) await db.query(`UPDATE ${table.tenant} SET
          cursor_user=CASE WHEN $2::pg_catalog.text IS NULL THEN cursor_user ELSE GREATEST(cursor_user,$2 COLLATE "C") END,
          scan_done=scan_done OR $3 WHERE tenant_id=$1 AND pending_epoch=$4::pg_catalog.uuid`,
          [tenantId, batch.rows.at(-1)?.user_id ?? null, batch.rows.length < size, expectedEpoch]);
      });
      return status(tenantId, includeCounts);
    });
  }
  async function activate(raw: { tenantId: string; epoch: string }): Promise<OnlinePolicyStatus> {
    const tenantId = raw.tenantId, expectedEpoch = raw.epoch; validateContext(tenantId); epoch(expectedEpoch);
    return safe(async () => {
      await ensureTenant(tenantId);
      await store.cutoverTenant(tenantId, async db => {
        const state = await tenant(db, tenantId);
        if (state.active_epoch === expectedEpoch) return;
        if (state.pending_epoch !== expectedEpoch) throw new GateError('stale_revision');
        if (!state.scan_done || (await db.query(`SELECT 1 FROM ${table.gap} WHERE tenant_id=$1 AND epoch=$2::pg_catalog.uuid LIMIT 1`, [tenantId, expectedEpoch])).rows.length) {
          throw new GateError('identity_conflict');
        }
        // Policy representation changes no principal or delivery address. User
        // revisions remain stable, preserving legitimate in-flight native proofs.
        // Only an actual verified email change increments the per-user CAS.
        await db.query(`UPDATE ${table.tenant} SET active_epoch=pending_epoch,active_version=pending_version,
          pending_epoch=NULL,pending_version=NULL,cursor_user=NULL,scan_done=false,legacy_mode=false
          WHERE tenant_id=$1`, [tenantId]);
      });
      return status(tenantId);
    });
  }
  async function abort(raw: { tenantId: string; epoch: string }): Promise<OnlinePolicyStatus> {
    const tenantId = raw.tenantId, expectedEpoch = raw.epoch; validateContext(tenantId); epoch(expectedEpoch);
    return safe(async () => {
      await ensureTenant(tenantId);
      await store.cutoverTenant(tenantId, async db => {
        const state = await tenant(db, tenantId);
        if (!state.pending_epoch) return;
        if (state.pending_epoch !== expectedEpoch) throw new GateError('stale_revision');
        await db.query(`UPDATE ${table.tenant} SET pending_epoch=NULL,pending_version=NULL,cursor_user=NULL,scan_done=false WHERE tenant_id=$1`, [tenantId]);
      });
      return status(tenantId);
    });
  }
  async function cleanup(raw: { tenantId: string; batchSize?: number }): Promise<{ removed: number }> {
    const tenantId = raw.tenantId, size = batchLimit(raw.batchSize); validateContext(tenantId);
    return safe(async () => {
      await ensureTenant(tenantId);
      const removed = await store.transaction({ tenantId }, async db => {
        const state = await tenant(db, tenantId);
        const result = await db.query(`DELETE FROM ${table.key} WHERE ctid IN
          (SELECT ctid FROM ${table.key} WHERE tenant_id=$1 AND epoch<>$2::pg_catalog.uuid AND ($3::pg_catalog.uuid IS NULL OR epoch<>$3::pg_catalog.uuid) LIMIT $4)`,
          [tenantId, state.active_epoch, state.pending_epoch, size]);
        const gaps = await db.query(`DELETE FROM ${table.gap} WHERE ctid IN
          (SELECT ctid FROM ${table.gap} WHERE tenant_id=$1 AND ($2::pg_catalog.uuid IS NULL OR epoch<>$2::pg_catalog.uuid) LIMIT $3)`, [tenantId, state.pending_epoch, size]);
        const old = state.legacy_mode ? null : await db.query(`DELETE FROM ${legacy} WHERE ctid IN
          (SELECT ctid FROM ${legacy} WHERE tenant_id=$1 LIMIT $2)`, [tenantId, size]);
        return (result.rowCount ?? 0) + (gaps.rowCount ?? 0) + (old?.rowCount ?? 0);
      });
      return Object.freeze({ removed });
    });
  }
  return Object.freeze({ screenSignup, claimVerified, assertActive, getOwnership, changeVerifiedEmail, revokeUser,
    prepareEmail: prepare,
    async getEmailPolicy(tenantId: string) { validateContext(tenantId); return safe(async () => { await ensureTenant(tenantId); return loadPolicy((await tenant(pool, tenantId)).active_version); }); },
    migration: Object.freeze({ begin, backfill, activate, abort,
      status: (input: { tenantId: string; includeCounts?: boolean }) => safe(() => status(input.tenantId, input.includeCounts)), cleanup }),
  });
}
export type OnlinePostgresGate = ReturnType<typeof createOnlinePostgresGate>;
