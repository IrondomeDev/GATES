import { prepareEmail, validateContext } from '../../core/policy.js';
import { validRevision } from '../../core/registry.js';
import type { PgPool, PostgresRegistryOptions } from './identity.js';
import type { BetterAuthChange, BetterAuthChangeStore } from '../../connectors/better-auth/store.js';
export type { BetterAuthChange, BetterAuthChangeStore } from '../../connectors/better-auth/store.js';

function validHash(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
/** Uses the host pool. No Better Auth import or additional database driver at runtime. */
export function createPostgresBetterAuthChangeStore(pool: PgPool, options: PostgresRegistryOptions = {}): BetterAuthChangeStore {
  const schema = options.schema ?? 'public';
  if (typeof schema !== 'string' || !/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(schema)) throw new TypeError('Invalid change store schema');
  const table = `"${schema}".irondome_gate_better_auth_change`;
  return Object.freeze({
    async save(raw: BetterAuthChange) {
      const input = { ...raw, expiresAt: new Date(raw.expiresAt) };
      validateContext(input.tenantId, input.userId);
      if (!validHash(input.tokenHash) || !['verify-email', 'change-email'].includes(input.purpose) || !validRevision(input.expectedRevision) ||
          !Number.isFinite(input.expiresAt.getTime()) || input.expiresAt.getTime() <= Date.now()) throw new TypeError('Invalid change binding');
      prepareEmail(input.previousDeliveryEmail); prepareEmail(input.nextDeliveryEmail);
      const result = await pool.query(`INSERT INTO ${table} (tenant_id,user_id,token_hash,purpose,previous_delivery_email,next_delivery_email,expected_revision,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7::pg_catalog.int8,$8) ON CONFLICT (tenant_id,token_hash) DO NOTHING RETURNING token_hash`,
        [input.tenantId, input.userId, input.tokenHash, input.purpose, input.previousDeliveryEmail, input.nextDeliveryEmail, input.expectedRevision, input.expiresAt]);
      if (result.rows.length !== 1) throw new Error('Change binding already exists');
    },
    async find(raw: { tenantId: string; tokenHash: string }) {
      const input = { ...raw };
      validateContext(input.tenantId);
      if (!validHash(input.tokenHash)) throw new TypeError('Invalid change binding');
      const result = await pool.query(`SELECT user_id,purpose,previous_delivery_email,next_delivery_email,expected_revision::pg_catalog.text AS expected_revision,expires_at FROM ${table} WHERE tenant_id=$1 AND token_hash=$2 AND expires_at > CURRENT_TIMESTAMP`, [input.tenantId, input.tokenHash]);
      if (result.rows.length === 0) return null;
      if (result.rows.length !== 1) throw new Error('Invalid change binding');
      const row = result.rows[0]!;
      validateContext(input.tenantId, row.user_id);
      const previous = prepareEmail(row.previous_delivery_email).deliveryEmail;
      const next = prepareEmail(row.next_delivery_email).deliveryEmail;
      const expiresAt = row.expires_at instanceof Date ? new Date(row.expires_at) : new Date(NaN);
      if ((row.purpose !== 'verify-email' && row.purpose !== 'change-email') || !validRevision(row.expected_revision) || !Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) return null;
      return Object.freeze({ ...input, purpose: row.purpose as BetterAuthChange['purpose'], userId: row.user_id as string, previousDeliveryEmail: previous,
        nextDeliveryEmail: next, expectedRevision: row.expected_revision, expiresAt });
    },
    async deleteUser(raw: { tenantId: string; userId: string }) {
      const input = { ...raw }; validateContext(input.tenantId, input.userId);
      await pool.query(`DELETE FROM ${table} WHERE tenant_id=$1 AND user_id=$2`, [input.tenantId, input.userId]);
    },
    async deleteExpired() { await pool.query(`DELETE FROM ${table} WHERE expires_at <= CURRENT_TIMESTAMP`); },
  });
}
