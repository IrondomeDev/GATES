import { DEFAULT_EMAIL_POLICY, requireEmailPolicy, validateContext, type EmailPolicy } from '../core/policy.js';
import type { Gate } from '../core/engine.js';

export interface BackfillRow { tenantId: string; userId: string; email: unknown; emailVerified: boolean }
export interface BackfillReport {
  policyVersion: string;
  total: number;
  verifiedEligible: number;
  pendingSkipped: number;
  invalidRows: number[];
  duplicateUserRows: number[][];
  collisionRows: number[][];
  ready: boolean;
}
/** Read-only audit. Row indexes are zero-based; no addresses/IDs in report, no network/writes. */
export function dryRunBackfill(rows: readonly BackfillRow[], options: { emailPolicy?: EmailPolicy } = {}): BackfillReport {
  const emailPolicy = requireEmailPolicy(options.emailPolicy ?? DEFAULT_EMAIL_POLICY);
  const prepareEmail = emailPolicy.prepareEmail;
  const report: BackfillReport = {policyVersion: emailPolicy.version, total: rows.length,
    verifiedEligible: 0, pendingSkipped: 0, invalidRows: [], duplicateUserRows: [], collisionRows: [], ready: false};
  const identities = new Map<string, number[]>();
  const users = new Map<string, number[]>();
  rows.forEach((row, index) => {
    try {
      if (!row || typeof row.emailVerified !== 'boolean') throw new Error();
      validateContext(row.tenantId, row.userId);
      const email = prepareEmail(row.email);
      if (!row.emailVerified) { report.pendingSkipped++; return; }
      report.verifiedEligible++;
      const identityKey = JSON.stringify([row.tenantId, email.canonical]);
      const userKey = JSON.stringify([row.tenantId, row.userId]);
      const identityRows = identities.get(identityKey);
      if (identityRows) identityRows.push(index); else identities.set(identityKey, [index]);
      const userRows = users.get(userKey);
      if (userRows) userRows.push(index); else users.set(userKey, [index]);
    } catch { report.invalidRows.push(index); }
  });
  report.collisionRows = [...identities.values()].filter(group => group.length > 1);
  report.duplicateUserRows = [...users.values()].filter(group => group.length > 1);
  report.ready = !report.invalidRows.length && !report.collisionRows.length && !report.duplicateUserRows.length;
  return report;
}

export interface BackfillApplyFailure { readonly index: number; readonly code: string }
export interface BackfillApplyReport {
  readonly audit: BackfillReport;
  readonly limitExceeded: boolean;
  readonly attempted: number;
  readonly completedRowIndexes: readonly number[];
  readonly failures: readonly BackfillApplyFailure[];
  /** True only when every verified eligible row was applied and rechecked. */
  readonly complete: boolean;
}
export interface ApplyBackfillOptions {
  /** Must read the current auth provider state under a coordinated cutover. */
  revalidate(row: Readonly<BackfillRow>, index: number): Promise<boolean>;
  concurrency?: number;
  signal?: AbortSignal;
}

const SAFE_GATE_CODES = new Set([
  'cancelled', 'invalid_email', 'invalid_context', 'screening_blocked',
  'screening_unavailable', 'identity_conflict', 'identity_revoked', 'stale_revision',
  'ownership_required', 'storage_unavailable',
  'policy_mismatch',
]);
const MAX_BACKFILL_ROWS = 100_000;

function gateFailureCode(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error &&
      typeof error.code === 'string' && SAFE_GATE_CODES.has(error.code)) return error.code;
  return 'apply_failed';
}

/**
 * Supervised, resumable application of a previously audited snapshot. This is
 * intentionally not a bulk transaction: completed rows remain owned if a later
 * row fails, and the returned indexes identify safe same-owner retry candidates.
 */
export async function applyBackfill(
  gate: Pick<Gate, 'claimVerified' | 'assertActive'> & Partial<Pick<Gate, 'emailPolicy'>>,
  inputRows: readonly BackfillRow[],
  options: ApplyBackfillOptions,
): Promise<BackfillApplyReport> {
  const emailPolicy = requireEmailPolicy(gate.emailPolicy ?? DEFAULT_EMAIL_POLICY);
  if (inputRows.length > MAX_BACKFILL_ROWS) {
    return Object.freeze({ audit: Object.freeze({ policyVersion: emailPolicy.version, total: inputRows.length,
      verifiedEligible: 0, pendingSkipped: 0, invalidRows: [], duplicateUserRows: [], collisionRows: [], ready: false }),
      limitExceeded: true, attempted: 0, completedRowIndexes: Object.freeze([]), failures: Object.freeze([]), complete: false });
  }
  // Copy every input field before awaiting, so caller mutation cannot change the
  // audited identity. Invalid/getter-backed rows become report-only blockers.
  const rows: BackfillRow[] = Array.from(inputRows, (row) => {
    try {
      if (!row || typeof row !== 'object') throw new Error();
      const tenantId = row.tenantId;
      const userId = row.userId;
      const email = row.email;
      const emailVerified = row.emailVerified;
      if (typeof tenantId !== 'string' || typeof userId !== 'string' ||
          typeof email !== 'string' || typeof emailVerified !== 'boolean') throw new Error();
      return Object.freeze({ tenantId, userId, email, emailVerified });
    } catch {
      return Object.freeze({ tenantId: '', userId: '', email: null, emailVerified: false });
    }
  });
  const audit = dryRunBackfill(rows, { emailPolicy });
  // Copy all options and method references before the first await. A caller
  // cannot swap the authority check, signal, or target operations mid-run.
  const revalidate = options.revalidate;
  const signal = options.signal;
  const requestedConcurrency = options.concurrency ?? 4;
  const claimVerified = gate.claimVerified;
  const assertActive = gate.assertActive;
  if (rows.length > MAX_BACKFILL_ROWS || !Number.isInteger(requestedConcurrency) ||
      requestedConcurrency < 1 || requestedConcurrency > 32 || typeof revalidate !== 'function') {
    return Object.freeze({ audit: Object.freeze({ ...audit, ready: false }), limitExceeded: false, attempted: 0,
      completedRowIndexes: Object.freeze([]), failures: Object.freeze([]), complete: false });
  }
  if (!audit.ready) return Object.freeze({ audit, limitExceeded: false, attempted: 0,
    completedRowIndexes: Object.freeze([]), failures: Object.freeze([]), complete: false });

  const eligible = rows.flatMap((row, index) => row.emailVerified ? [index] : []);
  const completed: number[] = [];
  const failures: BackfillApplyFailure[] = [];
  let cursor = 0;
  let attempted = 0;
  let stopped = false;
  const recordFailure = (index: number, code: string): void => {
    failures.push(Object.freeze({ index, code }));
    stopped = true;
  };

  const worker = async (): Promise<void> => {
    while (!stopped) {
      if (signal?.aborted) {
        const index = eligible[cursor];
        if (index !== undefined) { cursor++; recordFailure(index, 'cancelled'); }
        else stopped = true;
        return;
      }
      const index = eligible[cursor++];
      if (index === undefined) return;
      const row = rows[index]!;
      attempted++;
      try {
        let current: boolean;
        try { current = await revalidate(row, index); }
        catch { recordFailure(index, 'revalidation_failed'); return; }
        if (current !== true) { recordFailure(index, 'revalidation_mismatch'); return; }
        if (signal?.aborted) { recordFailure(index, 'cancelled'); return; }
        const claim = { tenantId: row.tenantId, userId: row.userId, email: row.email as string,
        ...(signal ? { signal } : {}) };
        await claimVerified(claim);
        await assertActive(claim);
        completed.push(index);
      } catch (error) {
        recordFailure(index, gateFailureCode(error));
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(requestedConcurrency, eligible.length) }, () => worker()));
  completed.sort((a, b) => a - b);
  failures.sort((a, b) => a.index - b.index);
  return Object.freeze({ audit, limitExceeded: false, attempted, completedRowIndexes: Object.freeze(completed),
    failures: Object.freeze(failures), complete: signal?.aborted !== true && failures.length === 0 && completed.length === eligible.length });
}
