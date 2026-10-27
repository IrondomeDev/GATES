import { validateContext, prepareEmail } from '../../core/policy.js';
import type { PgPool, PostgresRegistryOptions } from './identity.js';
import { validRevision } from '../../core/registry.js';
import type { ProviderOperation, ProviderOperationStore } from '../../core/provider-lifecycle.js';
export type { ProviderOperationStore } from '../../core/provider-lifecycle.js';
export interface PostgresProviderOperationStore extends ProviderOperationStore {
  /** Remove expired email-change PII only; never purge recoverable/terminal deletion intents. */
  deleteExpiredChanges(): Promise<void>;
}
export function createPostgresProviderOperationStore(pool: PgPool, options: PostgresRegistryOptions = {}): PostgresProviderOperationStore {
  const schema = options.schema ?? 'public';
  if (typeof schema !== 'string' || !/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(schema)) throw new TypeError('Invalid provider operation schema');
  const table = `"${schema}".irondome_gate_provider_operation`;
  return Object.freeze<PostgresProviderOperationStore>({
    async deleteExpiredChanges() { await pool.query(`DELETE FROM ${table} WHERE kind='email-change' AND expires_at <= CURRENT_TIMESTAMP`); },
    async withUserLock(scope, work) {
    const input = { ...scope };
    validateContext(input.tenantId, input.namespace, input.userId);
    const client = await pool.connect();
    let discard: Error | undefined;
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await client.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1::pg_catalog.text,0))',
        [JSON.stringify(['irondome-gate-provider',input.namespace,input.tenantId,input.userId])]);
      const result = await work({
        async read() {
          const result = await client.query(`SELECT operation_id,kind,generation,previous_email,next_email,expected_revision::pg_catalog.text AS expected_revision,status,expires_at FROM ${table} WHERE namespace=$1 AND tenant_id=$2 AND user_id=$3`, [input.namespace,input.tenantId,input.userId]);
          if (result.rows.length === 0) return null;
          const row = result.rows[0]!;
          if (result.rows.length !== 1 || typeof row.operation_id !== 'string' || typeof row.generation !== 'string' ||
              !(row.expires_at instanceof Date) || !['email-change','delete'].includes(String(row.kind)) ||
              !['pending','complete','deleting','deleted'].includes(String(row.status))) throw new Error('Invalid provider operation');
          if (row.kind === 'email-change') {
            prepareEmail(row.previous_email); prepareEmail(row.next_email);
            if (!validRevision(row.expected_revision)) throw new Error('Invalid provider operation');
          }
          return Object.freeze({ id: row.operation_id, kind: row.kind as ProviderOperation['kind'], generation: row.generation,
            previousEmail: row.previous_email as string | null, nextEmail: row.next_email as string | null,
            expectedRevision: row.expected_revision as string | null, status: row.status as ProviderOperation['status'], expiresAt: new Date(row.expires_at) });
        },
        async write(raw) {
          const operation = { ...raw, expiresAt: new Date(raw.expiresAt) };
          if (!/^[a-f0-9-]{36}$/i.test(operation.id) || !/^[\x21-\x7e]{1,256}$/.test(operation.generation) || !Number.isFinite(operation.expiresAt.getTime())) throw new TypeError('Invalid provider operation');
          if (operation.kind === 'email-change') {
            prepareEmail(operation.previousEmail); prepareEmail(operation.nextEmail);
            if (!validRevision(operation.expectedRevision)) throw new TypeError('Invalid provider operation');
          }
          await client.query(`INSERT INTO ${table} (namespace,tenant_id,user_id,operation_id,kind,generation,previous_email,next_email,expected_revision,status,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (namespace,tenant_id,user_id) DO UPDATE SET operation_id=EXCLUDED.operation_id,kind=EXCLUDED.kind,generation=EXCLUDED.generation,previous_email=EXCLUDED.previous_email,next_email=EXCLUDED.next_email,expected_revision=EXCLUDED.expected_revision,status=EXCLUDED.status,expires_at=EXCLUDED.expires_at`,
            [input.namespace,input.tenantId,input.userId,operation.id,operation.kind,operation.generation,operation.previousEmail,operation.nextEmail,operation.expectedRevision,operation.status,operation.expiresAt]);
        },
      });
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch { discard = new Error('Provider transaction rollback failed'); }
      throw error;
    } finally { client.release(discard); }
  } });
}
