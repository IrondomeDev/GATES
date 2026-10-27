import { validRevision, type ClaimResult, type LifecycleIdentityRegistry, type OwnershipState } from '../../core/registry.js';
export type { ClaimInput, ClaimResult, IdentityRegistry, OwnershipInput, LifecycleIdentityRegistry, OwnershipState, ReplaceInput, ReplaceResult, RevokeResult } from '../../core/registry.js';

export interface PgQueryResult {
  rows: Record<string, unknown>[];
  rowCount: number | null;
}
/** Structural subset of pg.PoolClient; the application owns the pool lifecycle. */
export interface PgClient {
  query(text: string, values?: unknown[]): Promise<PgQueryResult>;
  release(error?: Error | boolean): void;
}
export interface PgPool {
  connect(): Promise<PgClient>;
  query(text: string, values?: unknown[]): Promise<PgQueryResult>;
}
export interface PostgresRegistryOptions {
  /** Trusted schema containing ownership/lifecycle/policy migrations. Never request-derived. */
  schema?: string;
}
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;
function validString(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    Buffer.byteLength(value, 'utf8') <= max && !value.includes('\0') && !LONE_SURROGATE.test(value);
}
function validate(input: { tenantId: string; userId: string; canonical?: string; policyVersion?: string }): void {
  if (!validString(input.tenantId, 512) || !validString(input.userId, 512) ||
      ('canonical' in input && !validString(input.canonical, 254)) ||
      ('policyVersion' in input && !validString(input.policyVersion, 128))) {
    throw new TypeError('Invalid identity registry input');
  }
}
function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error('Identity registry transaction failure');
}
function decodeState(rows: Record<string, unknown>[]): OwnershipState {
  if (rows.length === 0) return Object.freeze({ status: 'unclaimed' });
  if (rows.length !== 1) throw new Error('Invalid identity registry state');
  const row = rows[0]!;
  if (row.revoked === true) return Object.freeze({ status: 'revoked' });
  if (row.revoked !== false || !validString(row.canonical_email, 254) || !validString(row.policy_version, 128) ||
      typeof row.revision !== 'string' || !/^[1-9][0-9]{0,18}$/.test(row.revision) || BigInt(row.revision) > 9223372036854775807n) {
    throw new Error('Invalid identity registry state');
  }
  return Object.freeze({ status: 'active', canonical: row.canonical_email, policyVersion: row.policy_version, revision: row.revision });
}

/** PostgreSQL 12+. All lifecycle writers share the same user lock and unique constraints. */
export function createPostgresIdentityRegistry(pool: PgPool, options: PostgresRegistryOptions = {}): LifecycleIdentityRegistry {
  const schema = options.schema ?? 'public';
  // PostgreSQL identifiers truncate at 63 bytes. Reject instead of selecting another schema.
  if (typeof schema !== 'string' || !/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(schema)) {
    throw new TypeError('Invalid identity registry schema');
  }
  const identity = `"${schema}".irondome_gate_identity`;
  const revoked = `"${schema}".irondome_gate_revoked`;
  const tenantPolicy = `"${schema}".irondome_gate_tenant_policy`;
  const onlineTenant = `"${schema}".irondome_gate_online_tenant`;
  // Requiring the policy relation here also fails writes closed on an old schema.
  // The verified hot-path owns() query remains a single identity-index lookup.
  let onlineTenantProbe: Promise<boolean> | undefined;
  async function hasOnlineTenant(db: Pick<PgClient, 'query'> | PgPool): Promise<boolean> {
    onlineTenantProbe ??= db.query('SELECT pg_catalog.to_regclass($1::pg_catalog.text) IS NOT NULL AS enabled', [onlineTenant])
      .then(result => result.rows[0]?.enabled === true)
      .catch(error => { onlineTenantProbe = undefined; throw error; });
    return onlineTenantProbe;
  }
  function stateSql(fenced: boolean): string {
    const onlineFence = fenced
      ? ` AND NOT EXISTS (SELECT 1 FROM ${onlineTenant} AS online WHERE online.tenant_id = owner.tenant_id AND NOT online.legacy_mode)`
      : '';
    return `SELECT canonical_email, owner.policy_version, revision::pg_catalog.text AS revision, false AS revoked FROM ${identity} AS owner JOIN ${tenantPolicy} AS policy ON owner.tenant_id = policy.tenant_id AND owner.policy_version = policy.policy_version WHERE owner.tenant_id = $1 AND owner.user_id = $2${onlineFence} UNION ALL SELECT NULL, NULL, NULL, true FROM ${revoked} WHERE tenant_id = $1 AND user_id = $2`;
  }
  function policyMismatch(error: unknown): boolean {
    return !!error && typeof error === 'object' && 'code' in error && error.code === '23503' &&
      'constraint' in error && error.constraint === 'irondome_gate_identity_policy_fkey' &&
      'schema' in error && error.schema === schema && 'table' in error && error.table === 'irondome_gate_identity';
  }

  async function transaction<T>(input: { tenantId: string; userId: string }, work: (client: PgClient) => Promise<T>): Promise<T> {
    const client = await pool.connect();
    let discard: Error | undefined;
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      const onlineFence = await hasOnlineTenant(client);
      // Compatible legacy callers take the tenant lock before the historical
      // per-user lock, matching the online registry. This ordering prevents a
      // queued tenant cutover from wedging a user-locked legacy writer behind
      // an online same-user transaction. Old binaries are drained before the
      // protocol flag is enabled.
      if (onlineFence) {
        await client.query('SELECT pg_catalog.pg_advisory_xact_lock_shared(pg_catalog.hashtextextended($1::pg_catalog.text, 0))',
          [`irondome-gate-online-v1|${schema}|tenant|${input.tenantId}`]);
      }
      await client.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1::pg_catalog.text, 0))',
        [JSON.stringify(['irondome-gate', input.tenantId, input.userId])]);
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try { await client.query('ROLLBACK'); }
      catch (rollbackError) { discard = asError(rollbackError); }
      throw error;
    } finally { client.release(discard); }
  }

  async function revokeUser(rawInput: { tenantId: string; userId: string }) {
    const input = { tenantId: rawInput.tenantId, userId: rawInput.userId };
    validate(input);
    return transaction(input, async client => {
      // One statement atomically erases the address and retains a non-email revocation fence.
      const result = await client.query(`WITH marked AS (INSERT INTO ${revoked} (tenant_id, user_id) VALUES ($1, $2) ON CONFLICT (tenant_id, user_id) DO NOTHING RETURNING user_id), removed AS (DELETE FROM ${identity} WHERE tenant_id = $1 AND user_id = $2) SELECT EXISTS (SELECT 1 FROM marked) AS inserted`,
        [input.tenantId, input.userId]);
      if (result.rows.length !== 1 || typeof result.rows[0]?.inserted !== 'boolean') throw new Error('Invalid identity registry result');
      return result.rows[0].inserted ? 'revoked' as const : 'already-revoked' as const;
    });
  }

  return Object.freeze({
    async claim(rawInput) {
      const input = { tenantId: rawInput.tenantId, userId: rawInput.userId, canonical: rawInput.canonical, policyVersion: rawInput.policyVersion };
      validate(input);
      try {
        return await transaction<ClaimResult>(input, async client => {
          const existing = await client.query(stateSql(await hasOnlineTenant(client)), [input.tenantId, input.userId]);
          if (existing.rows.length > 1) throw new Error('Invalid identity registry state');
          if (existing.rows[0]?.revoked === true) return 'revoked';
          if (existing.rows.length === 1) return existing.rows[0]?.canonical_email === input.canonical ? 'already-owned' : 'conflict';
          const inserted = await client.query(`INSERT INTO ${identity} (tenant_id, user_id, canonical_email, policy_version) VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, canonical_email) DO NOTHING RETURNING user_id`,
            [input.tenantId, input.userId, input.canonical, input.policyVersion]);
          return inserted.rows.length === 1 ? 'claimed' : 'conflict';
        });
      } catch (error) {
        if (policyMismatch(error)) return 'policy-mismatch';
        throw error;
      }
    },
    async owns(rawInput) {
      const input = { tenantId: rawInput.tenantId, userId: rawInput.userId, canonical: rawInput.canonical };
      validate(input);
      const onlineFence = await hasOnlineTenant(pool)
        ? ` AND NOT EXISTS (SELECT 1 FROM ${onlineTenant} AS online WHERE online.tenant_id = owner.tenant_id AND NOT online.legacy_mode)`
        : '';
      const result = await pool.query(`SELECT 1 AS owned FROM ${identity} AS owner WHERE owner.tenant_id = $1 AND owner.user_id = $2 AND owner.canonical_email = $3${onlineFence}`,
        [input.tenantId, input.userId, input.canonical]);
      return result.rows.length === 1;
    },
    async getOwnership(rawInput) {
      const input = { tenantId: rawInput.tenantId, userId: rawInput.userId };
      validate(input);
      const fenced = await hasOnlineTenant(pool);
      return decodeState((await pool.query(stateSql(fenced), [input.tenantId, input.userId])).rows);
    },
    async replaceVerified(rawInput) {
      const input = { tenantId: rawInput.tenantId, userId: rawInput.userId, canonical: rawInput.canonical,
        policyVersion: rawInput.policyVersion, expectedRevision: rawInput.expectedRevision };
      validate(input);
      if (!validRevision(input.expectedRevision)) throw new TypeError('Invalid identity revision');
      try {
        return await transaction(input, async client => {
          const state = decodeState((await client.query(stateSql(await hasOnlineTenant(client)), [input.tenantId, input.userId])).rows);
          if (state.status === 'revoked') return 'revoked' as const;
          if (state.status !== 'active') return 'stale' as const;
          // Reconcile a lost acknowledgement without repeating the update or incrementing revision.
          if (BigInt(state.revision) === BigInt(input.expectedRevision) + 1n && state.canonical === input.canonical &&
              state.policyVersion === input.policyVersion) return 'already-replaced' as const;
          if (state.revision !== input.expectedRevision) return 'stale' as const;
          const changed = await client.query(`UPDATE ${identity} SET canonical_email = $3, policy_version = $4, revision = revision + 1, claimed_at = CURRENT_TIMESTAMP WHERE tenant_id = $1 AND user_id = $2 AND revision = $5::pg_catalog.int8 RETURNING revision`,
            [input.tenantId, input.userId, input.canonical, input.policyVersion, input.expectedRevision]);
          if (changed.rows.length !== 1) throw new Error('Invalid identity registry result');
          return 'replaced' as const;
        });
      } catch (error) {
        if (policyMismatch(error)) return 'policy-mismatch';
        // The whole transaction has rolled back, preserving the old identity. Other errors propagate.
        if (error && typeof error === 'object' && 'code' in error && error.code === '23505' &&
            'constraint' in error && error.constraint === 'irondome_gate_identity_pkey' &&
            'schema' in error && error.schema === schema && 'table' in error && error.table === 'irondome_gate_identity') return 'conflict';
        throw error;
      }
    },
    revokeUser,
    async releaseUser(input) { await revokeUser(input); },
  } satisfies LifecycleIdentityRegistry);
}
