/** A durable registry implements these operations atomically, never with read-then-write. */
export interface OwnershipInput {
  tenantId: string;
  userId: string;
  canonical: string;
}
export interface ClaimInput extends OwnershipInput { policyVersion: string }
export type ClaimResult = 'claimed' | 'already-owned' | 'conflict' | 'revoked' | 'policy-mismatch';
export interface IdentityRegistry {
  /** Verified proof must be checked by trusted auth before calling. Conflict preserves old ownership. */
  claim(input: ClaimInput): Promise<ClaimResult>;
  owns(input: OwnershipInput): Promise<boolean>;
  /** Terminal revocation: user IDs must never be reused. Never use for an email change. */
  releaseUser(input: Pick<OwnershipInput, 'tenantId' | 'userId'>): Promise<void>;
}

export type UserInput = Pick<OwnershipInput, 'tenantId' | 'userId'>;
/** Decimal PostgreSQL bigint, kept as a string to avoid JavaScript precision loss. */
export type OwnershipState =
  | { readonly status: 'active'; readonly canonical: string; readonly policyVersion: string; readonly revision: string }
  | { readonly status: 'unclaimed' | 'revoked' };
export interface ReplaceInput extends ClaimInput { expectedRevision: string }
export type ReplaceResult = 'replaced' | 'already-replaced' | 'conflict' | 'stale' | 'revoked' | 'policy-mismatch';
export type RevokeResult = 'revoked' | 'already-revoked';
export interface LifecycleIdentityRegistry extends IdentityRegistry {
  getOwnership(input: UserInput): Promise<OwnershipState>;
  /** Trusted current provider proof required. Compare revision, never canonical alone (ABA). */
  replaceVerified(input: ReplaceInput): Promise<ReplaceResult>;
  /** Persist a tombstone even for an absent user; serialize against every claim/swap. */
  revokeUser(input: UserInput): Promise<RevokeResult>;
}

export function validRevision(value: unknown): value is string {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) < 9223372036854775807n;
}
