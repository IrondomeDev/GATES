import { validateContext } from '../../core/policy.js';
import type { PgClient, PgPool } from './identity.js';

export interface OnlinePostgresStoreOptions {
  /** Trusted schema containing migrations 001, 002, and 006. */
  schema?: string;
  /** Maximum time a database lock may block, 50..10000 ms. Defaults to 2000. */
  lockTimeoutMs?: number;
  /** Maximum execution time for each statement, 100..60000 ms. Defaults to 5000. */
  statementTimeoutMs?: number;
  /** Maximum time to wait for a non-queued exclusive tenant lock, 1..5000 ms. Defaults to 5000. */
  exclusiveWaitMs?: number;
}

export interface OnlinePostgresScope {
  tenantId: string;
  /** When supplied, acquire the per-user exclusive lock after the tenant-shared lock. */
  userId?: string;
}

export interface OnlinePostgresTables {
  readonly policy: string;
  readonly tenant: string;
  readonly owner: string;
  readonly key: string;
  readonly gap: string;
  readonly legacyIdentity: string;
  readonly legacyPolicy: string;
  readonly revoked: string;
}

function validateSchema(schema: unknown): asserts schema is string {
  if (typeof schema !== 'string' || !/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(schema)) {
    throw new TypeError('Invalid online identity registry schema');
  }
}

function boundedInteger(name: string, value: unknown, fallback: number, min: number, max: number): number {
  const resolved = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(resolved) || (resolved as number) < min || (resolved as number) > max) {
    throw new TypeError(`Invalid ${name}`);
  }
  return resolved as number;
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error('Online identity transaction failure');
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Low-level PostgreSQL transaction and advisory-lock layer for the online
 * dual-epoch registry. All ordinary tenant writers use a shared transaction
 * lock before any optional per-user lock. Epoch cutovers acquire an exclusive
 * lock with a bounded queue for a short metadata transaction. Bootstrap uses
 * try-lock polling while legacy writers may still coexist. Every writer to online and legacy identity tables must use
 * this store after protocol enforcement is enabled.
 */
export function createOnlinePostgresStore(pool: PgPool, options: OnlinePostgresStoreOptions = {}) {
  const schema = options.schema ?? 'public';
  validateSchema(schema);
  const lockTimeoutMs = boundedInteger('lock timeout', options.lockTimeoutMs, 2000, 50, 10000);
  const statementTimeoutMs = boundedInteger('statement timeout', options.statementTimeoutMs, 5000, 100, 60000);
  const exclusiveWaitMs = boundedInteger('exclusive wait', options.exclusiveWaitMs, 5000, 1, 5000);
  const prefix = `"${schema}".irondome_gate_online_`;
  const legacyPrefix = `"${schema}".irondome_gate_`;
  const tables: OnlinePostgresTables = Object.freeze({
    policy: `${prefix}policy`,
    tenant: `${prefix}tenant`,
    owner: `${prefix}owner`,
    key: `${prefix}key`,
    gap: `${prefix}gap`,
    legacyIdentity: `${legacyPrefix}identity`,
    legacyPolicy: `${legacyPrefix}tenant_policy`,
    revoked: `${legacyPrefix}revoked`,
  });

  function tenantLockKey(tenantId: string): string {
    return `irondome-gate-online-v1|${schema}|tenant|${tenantId}`;
  }
  function userLockKey(tenantId: string, userId: string): string {
    // Match the fixed registry during the compatible rolling bridge. Exclusive
    // tenant operations never queue behind these user-first legacy writers.
    return JSON.stringify(['irondome-gate', tenantId, userId]);
  }

  async function begin(client: PgClient): Promise<void> {
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    await client.query(
      `SELECT pg_catalog.set_config('lock_timeout', $1::pg_catalog.text, true),
              pg_catalog.set_config('statement_timeout', $2::pg_catalog.text, true)`,
      [`${lockTimeoutMs}ms`, `${statementTimeoutMs}ms`]);
  }

  async function withTransaction<T>(
    tenantId: string,
    lockTenant: 'shared' | 'exclusive',
    userId: string | undefined,
    work: (client: PgClient) => Promise<T>,
  ): Promise<T> {
    let client: PgClient;
    try { client = await pool.connect(); }
    catch { throw new Error('Online identity database unavailable'); }
    let discard: Error | undefined;
    try {
      await begin(client);
      if (lockTenant === 'shared') {
        await client.query(
          'SELECT pg_catalog.pg_advisory_xact_lock_shared(pg_catalog.hashtextextended($1::pg_catalog.text, 0))',
          [tenantLockKey(tenantId)]);
      } else {
        await client.query(
          'SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1::pg_catalog.text, 0))',
          [tenantLockKey(tenantId)]);
      }
      if (userId !== undefined) {
        await client.query(
          'SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1::pg_catalog.text, 0))',
          [userLockKey(tenantId, userId)]);
      }
      await client.query("SELECT pg_catalog.set_config('irondome_gate.online_write', 'on', true)");
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      try { await client.query('ROLLBACK'); }
      catch (rollbackError) { discard = asError(rollbackError); }
      throw error;
    } finally {
      client.release(discard);
    }
  }

  async function tryExclusiveOnce<T>(tenantId: string, work: (client: PgClient) => Promise<T>): Promise<{ acquired: false } | { acquired: true; value: T }> {
    let client: PgClient;
    try { client = await pool.connect(); }
    catch { throw new Error('Online identity database unavailable'); }
    let discard: Error | undefined;
    let transactionOpen = false;
    try {
      await begin(client);
      transactionOpen = true;
      const lock = await client.query(
        'SELECT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended($1::pg_catalog.text, 0)) AS acquired',
        [tenantLockKey(tenantId)]);
      if (lock.rows[0]?.acquired !== true) {
        await client.query('ROLLBACK');
        transactionOpen = false;
        return { acquired: false };
      }
      await client.query("SELECT pg_catalog.set_config('irondome_gate.online_write', 'on', true)");
      const value = await work(client);
      await client.query('COMMIT');
      transactionOpen = false;
      return { acquired: true, value };
    } catch (error) {
      if (transactionOpen) {
        try { await client.query('ROLLBACK'); }
        catch (rollbackError) { discard = asError(rollbackError); }
      }
      throw error;
    } finally {
      client.release(discard);
    }
  }

  async function transaction<T>(scope: OnlinePostgresScope, work: (client: PgClient) => Promise<T>): Promise<T> {
    const tenantId = scope?.tenantId;
    const userId = scope?.userId;
    validateContext(tenantId, ...(userId === undefined ? [] : [userId]));
    return withTransaction(tenantId, 'shared', userId, work);
  }

  async function exclusiveTenant<T>(tenantId: string, work: (client: PgClient) => Promise<T>): Promise<T> {
    validateContext(tenantId);
    const end = Date.now() + exclusiveWaitMs;
    let pauseMs = 5;
    do {
      const attempt = await tryExclusiveOnce(tenantId, work);
      if (attempt.acquired) return attempt.value;
      const remaining = end - Date.now();
      if (remaining <= 0) break;
      await delay(Math.min(pauseMs, remaining));
      pauseMs = Math.min(pauseMs * 2, 100);
    } while (Date.now() < end);
    throw new Error('Online identity tenant is busy');
  }

  /**
   * Fair, bounded metadata cutover after every writer uses the tenant-first
   * protocol. Queueing drains existing short transactions instead of starving
   * behind continuous new writers. Never run a backfill or provider I/O here.
   */
  async function cutoverTenant<T>(tenantId: string, work: (client: PgClient) => Promise<T>): Promise<T> {
    validateContext(tenantId);
    return withTransaction(tenantId, 'exclusive', undefined, work);
  }

  return Object.freeze({ tables, transaction, exclusiveTenant, cutoverTenant });
}
