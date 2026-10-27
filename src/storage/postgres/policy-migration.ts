import { createHash } from 'node:crypto';
import { GateError } from '../../core/errors.js';
import { POLICY_VERSION, DEFAULT_EMAIL_POLICY, requireEmailPolicy, type EmailPolicy } from '../../core/policy.js';
import type { PgClient, PgPool } from './identity.js';

const PG_BIGINT_MAX = 9_223_372_036_854_775_807n;
const MAX_CONFIGURED_ROWS = 100_000;
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;

export interface PostgresPolicyMigratorOptions {
  /** Trusted schema holding migrations 001, 002, and 005. Never request-derived. */
  schema?: string;
  /** Maximum identities a single audited tenant migration may inspect. Default 10,000; hard maximum 100,000. */
  maxRows?: number;
  /** Use engine.emailPolicy so the audit and writer share the same compiled domain rules. */
  emailPolicy?: EmailPolicy;
}

export interface PolicyAudit {
  readonly status: 'ready' | 'already-current' | 'blocked';
  readonly ready: boolean;
  readonly currentPolicyVersion: string | null;
  readonly targetPolicyVersion: string;
  /** Number of rows inspected, capped at maxRows + 1 when limitExceeded is true. */
  readonly rowCount: number;
  /** One-based positions in the deterministic user_id ordering. No identifiers or addresses are returned. */
  readonly invalidRows: readonly number[];
  readonly collisionRows: readonly number[];
  readonly revisionOverflowRows: readonly number[];
  readonly unsupportedPolicy: boolean;
  readonly limitExceeded: boolean;
  readonly digest: string;
}

export type PolicyMigrationResult =
  | { readonly status: 'migrated'; readonly audit: PolicyAudit }
  | { readonly status: 'already-current'; readonly audit: PolicyAudit }
  | { readonly status: 'stale-audit'; readonly audit: PolicyAudit }
  | { readonly status: 'blocked'; readonly audit: PolicyAudit };

interface IdentityRow {
  user_id: unknown;
  canonical_email: unknown;
  policy_version: unknown;
  revision: unknown;
  claimed_at: unknown;
}

interface Snapshot {
  audit: PolicyAudit;
  rows: Array<{ userId: string; canonical: string; revision: string; claimedAt: string; target: string }>;
}

function validateSchema(schema: unknown): asserts schema is string {
  if (typeof schema !== 'string' || !/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(schema)) {
    throw new TypeError('Invalid policy migrator schema');
  }
}

function validateTenantId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > 512 ||
      value.includes('\0') || LONE_SURROGATE.test(value)) {
    throw new TypeError('Invalid policy migrator tenant');
  }
}

function safeText(value: unknown, maxBytes: number): value is string {
  return typeof value === 'string' && value.length > 0 && Buffer.byteLength(value, 'utf8') <= maxBytes &&
    !value.includes('\0') && !LONE_SURROGATE.test(value);
}

function publicAudit(
  status: PolicyAudit['status'], current: string | null, rowCount: number,
  invalid: number[], collisions: number[], overflow: number[], unsupported: boolean,
  limitExceeded: boolean, digest: string, targetPolicyVersion: string,
): PolicyAudit {
  const ready = status !== 'blocked';
  return Object.freeze({ status, ready, currentPolicyVersion: current, targetPolicyVersion,
    rowCount, invalidRows: Object.freeze(invalid), collisionRows: Object.freeze(collisions),
    revisionOverflowRows: Object.freeze(overflow), unsupportedPolicy: unsupported,
    limitExceeded, digest });
}

function transactionError(error: unknown): Error {
  if (error instanceof GateError) return error;
  return new GateError('storage_unavailable', true);
}

/**
 * Admin-only, offline canonical policy upgrade. Freeze all Gate writers while
 * migrating. This helper does not screen identities, authenticate users, or
 * participate in request paths.
 */
export function createPostgresPolicyMigrator(pool: PgPool, options: PostgresPolicyMigratorOptions = {}) {
  const emailPolicy = requireEmailPolicy(options.emailPolicy ?? DEFAULT_EMAIL_POLICY);
  const targetPolicyVersion = emailPolicy.version;
  const prepareEmail = emailPolicy.prepareEmail;
  // Stored canonical keys are lossy. Only the current built-in policy can be
  // extended automatically; unknown prior custom policies require original data.
  const supportedPolicies = new Set([POLICY_VERSION, targetPolicyVersion]);
  const schema = options.schema ?? 'public';
  validateSchema(schema);
  const maxRows = options.maxRows ?? 10_000;
  if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > MAX_CONFIGURED_ROWS) {
    throw new TypeError('Invalid policy migrator row limit');
  }
  const identity = `"${schema}".irondome_gate_identity`;
  const tenantPolicy = `"${schema}".irondome_gate_tenant_policy`;

  async function snapshot(client: PgClient, tenantId: string, includeRows = false): Promise<Snapshot> {
    const policyResult = await client.query(
      `SELECT policy_version FROM ${tenantPolicy} WHERE tenant_id = $1`, [tenantId]);
    if (policyResult.rows.length > 1) throw new Error('invalid tenant policy state');
    const currentValue = policyResult.rows[0]?.policy_version;
    const currentInvalid = currentValue !== undefined && !safeText(currentValue, 128);
    const current = currentValue === undefined || currentInvalid ? null : currentValue as string;
    const rowResult = await client.query(
      `SELECT user_id, canonical_email, policy_version, revision::pg_catalog.text AS revision,
        pg_catalog.to_char(claimed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') || '+00' AS claimed_at
       FROM ${identity} WHERE tenant_id = $1 ORDER BY user_id COLLATE "C" LIMIT $2`,
      [tenantId, maxRows + 1]);
    const limitExceeded = rowResult.rows.length > maxRows;
    const rawRows = rowResult.rows.slice(0, maxRows) as unknown as IdentityRow[];
    const invalidRows: number[] = [];
    const overflowRows: number[] = [];
    const unsupportedPolicies = new Set<string>();
    const targetByIndex: Array<string | null> = [];
    const validRows: Snapshot['rows'] = [];

    if (currentInvalid || (current !== null && !supportedPolicies.has(current))) unsupportedPolicies.add('unsupported');
    for (let index = 0; index < rawRows.length; index++) {
      const row = rawRows[index]!;
      const rowIndex = index + 1;
      const userId = row.user_id;
      const canonical = row.canonical_email;
      const rowPolicy = row.policy_version;
      const revision = row.revision;
      const claimedAt = row.claimed_at;
      if (!safeText(userId, 512) || !safeText(canonical, 254) || !safeText(rowPolicy, 128) ||
          !safeText(revision, 19) || !/^[1-9][0-9]{0,18}$/.test(revision) || !safeText(claimedAt, 64)) {
        invalidRows.push(rowIndex);
        targetByIndex.push(null);
        continue;
      }
      let target: string | null = null;
      try { target = prepareEmail(canonical).canonical; }
      catch { /* Recorded as a row index below; input data is never exposed. */ }
      if (target === null) {
        invalidRows.push(rowIndex);
        targetByIndex.push(null);
      } else {
        if ((rowPolicy === targetPolicyVersion && canonical !== target) ||
            (rowPolicy === POLICY_VERSION && canonical !== DEFAULT_EMAIL_POLICY.prepareEmail(canonical).canonical)) {
          invalidRows.push(rowIndex);
        }
        targetByIndex.push(target);
        if (includeRows) validRows.push({ userId, canonical, revision, claimedAt, target });
        const rev = BigInt(revision);
        if (rev > PG_BIGINT_MAX - 3n) overflowRows.push(rowIndex);
        if (!supportedPolicies.has(rowPolicy)) unsupportedPolicies.add(rowPolicy);
        if (current !== null && rowPolicy !== current) unsupportedPolicies.add(rowPolicy);
      }
    }

    const targetIndexes = new Map<string, number>();
    const collidingIndexes = new Set<number>();
    targetByIndex.forEach((target, index) => {
      if (target === null) return;
      const first = targetIndexes.get(target);
      if (first === undefined) targetIndexes.set(target, index + 1);
      else { collidingIndexes.add(first); collidingIndexes.add(index + 1); }
    });
    const collisionRows = [...collidingIndexes].sort((a, b) => a - b);
    const unsupportedPolicy = unsupportedPolicies.size > 0;
    const blocked = invalidRows.length > 0 || collisionRows.length > 0 || overflowRows.length > 0 ||
      unsupportedPolicy || limitExceeded;

    const digestHash = createHash('sha256');
    digestHash.update(JSON.stringify([tenantId, current, targetPolicyVersion, limitExceeded]));
    for (let index = 0; index < rawRows.length; index++) {
      const row = rawRows[index]!;
      digestHash.update('\n');
      digestHash.update(JSON.stringify([row.user_id, row.canonical_email, row.policy_version,
        row.revision, row.claimed_at, targetByIndex[index] ?? null]));
    }
    const digest = digestHash.digest('hex');
    const status: PolicyAudit['status'] = blocked ? 'blocked' : current === targetPolicyVersion ? 'already-current' : 'ready';
    const audit = publicAudit(status, current, rowResult.rows.length, invalidRows, collisionRows,
      overflowRows, unsupportedPolicy, limitExceeded, digest, targetPolicyVersion);

    return { audit, rows: validRows };
  }

  async function auditTenant(input: { tenantId: string }): Promise<PolicyAudit> {
    const tenantId = input?.tenantId;
    validateTenantId(tenantId);
    let client: PgClient;
    try { client = await pool.connect(); }
    catch { throw new GateError('storage_unavailable', true); }
    let discard: Error | undefined;
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const result = await snapshot(client, tenantId);
      await client.query('COMMIT');
      return result.audit;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch (rollbackError) { discard = transactionError(rollbackError); }
      throw transactionError(error);
    } finally { client.release(discard); }
  }

  async function migrateTenant(input: { tenantId: string; expectedDigest: string }): Promise<PolicyMigrationResult> {
    const tenantId = input?.tenantId;
    const expectedDigest = input?.expectedDigest;
    validateTenantId(tenantId);
    if (typeof expectedDigest !== 'string' || !/^[0-9a-f]{64}$/.test(expectedDigest)) {
      throw new TypeError('Invalid policy audit digest');
    }
    let client: PgClient;
    try { client = await pool.connect(); }
    catch { throw new GateError('storage_unavailable', true); }
    let discard: Error | undefined;
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      // Identity-first lock order matches Gate writers' first table access and
      // blocks new inserts while policy metadata and all keys are transitioned.
      await client.query(`LOCK TABLE ${identity} IN EXCLUSIVE MODE`);
      await client.query(`LOCK TABLE ${tenantPolicy} IN EXCLUSIVE MODE`);
      const state = await snapshot(client, tenantId, true);
      // A retry after a lost success acknowledgment is a no-op success, even
      // though the original audit digest necessarily changed during migration.
      if (state.audit.status === 'already-current' && state.audit.ready) {
        await client.query('COMMIT');
        return { status: 'already-current', audit: state.audit };
      }
      if (state.audit.digest !== expectedDigest) {
        await client.query('COMMIT');
        return { status: 'stale-audit', audit: state.audit };
      }
      if (!state.audit.ready) {
        await client.query('COMMIT');
        return { status: 'blocked', audit: state.audit };
      }
      await client.query('SET CONSTRAINTS ALL DEFERRED');
      await client.query(
        `INSERT INTO ${tenantPolicy} (tenant_id, policy_version) VALUES ($1, $2)
         ON CONFLICT (tenant_id) DO UPDATE SET policy_version = EXCLUDED.policy_version`,
        [tenantId, targetPolicyVersion]);
      await client.query(`DELETE FROM ${identity} WHERE tenant_id = $1`, [tenantId]);
      const batchSize = 5_000;
      for (let start = 0; start < state.rows.length; start += batchSize) {
        const batch = state.rows.slice(start, start + batchSize);
        const values: unknown[] = [];
        const tuples = batch.map((row, index) => {
          const base = index * 6;
          values.push(tenantId, row.userId, row.target, targetPolicyVersion,
            (BigInt(row.revision) + 2n).toString(), row.claimedAt);
          return `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}::pg_catalog.int8, $${base + 6}::pg_catalog.timestamptz)`;
        });
        await client.query(
          `INSERT INTO ${identity} (tenant_id, user_id, canonical_email, policy_version, revision, claimed_at)
           VALUES ${tuples.join(', ')}`, values);
      }
      await client.query('COMMIT');
      return { status: 'migrated', audit: state.audit };
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch (rollbackError) { discard = transactionError(rollbackError); }
      throw transactionError(error);
    } finally { client.release(discard); }
  }

  return Object.freeze({ auditTenant, migrateTenant });
}
