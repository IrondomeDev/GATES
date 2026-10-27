export type GateErrorCode = 'cancelled' | 'invalid_email' | 'invalid_context' | 'screening_blocked' |
  'screening_unavailable' | 'identity_conflict' | 'identity_revoked' | 'stale_revision' | 'ownership_required' | 'storage_unavailable' | 'policy_mismatch';
/** Deliberately contains no input address, user ID, tenant ID, upstream body, or cause. */
export class GateError extends Error {
  readonly code: GateErrorCode;
  readonly retryable: boolean;
  constructor(code: GateErrorCode, retryable = false) {
    super(code);
    this.name = 'GateError';
    this.code = code;
    this.retryable = retryable;
  }
}
