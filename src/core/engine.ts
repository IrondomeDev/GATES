import { GateError } from './errors.js';
import { IronDomeClientError } from './irondome.js';
import { createEmailPolicy, validateContext, type DomainCanonicalRules, type PreparedEmail } from './policy.js';
import type { IdentityRegistry } from './registry.js';

export interface ScreeningClient {
  screen(email: string, signal?: AbortSignal): Promise<{ allowed: boolean; reason: string }>;
}
export interface SignupInput { tenantId: string; email: unknown; signal?: AbortSignal }
export interface VerifiedInput extends SignupInput { userId: string }
export interface GateOptions {
  registry: IdentityRegistry;
  screening: ScreeningClient;
  /** Compiled once; automatically inherited by adapters using this engine. */
  canonicalRules?: DomainCanonicalRules;
}

/** Shared screening boundary for fixed-policy and online-policy engines. */
export async function screenPreparedEmail(screening: ScreeningClient, prepared: PreparedEmail, signal?: AbortSignal): Promise<PreparedEmail> {
  if (signal?.aborted) throw new GateError('cancelled');
  let decision: { allowed: boolean; reason: string };
  try { decision = await screening.screen(prepared.deliveryEmail, signal); }
  catch (error) {
    if (signal?.aborted || (error instanceof IronDomeClientError && error.code === 'cancelled')) throw new GateError('cancelled');
    if (error instanceof IronDomeClientError && error.code === 'invalid_email') throw new GateError('invalid_email');
    throw new GateError('screening_unavailable', error instanceof IronDomeClientError ? error.retryable : true);
  }
  if (signal?.aborted) throw new GateError('cancelled');
  if (decision?.allowed !== true) throw new GateError('screening_blocked');
  return prepared;
}

/** Auth-independent engine. No sessions, passwords, OTPs, global PII cache, or background jobs. */
export function createGate({ registry, screening, canonicalRules }: GateOptions) {
  const emailPolicy = createEmailPolicy(canonicalRules);
  const prepareEmail = emailPolicy.prepareEmail;
  function checkCancellation(signal?: AbortSignal): void {
    if (signal?.aborted) throw new GateError('cancelled');
  }
  async function screenSignup(input: SignupInput): Promise<PreparedEmail> {
    input = { ...input }; // Bind context before the first await; callers may reuse mutable objects.
    validateContext(input.tenantId);
    checkCancellation(input.signal);
    const prepared = prepareEmail(input.email); // Invalid input never reaches a billable API.
    return screenPreparedEmail(screening, prepared, input.signal);
  }

  async function claimVerified(input: VerifiedInput): Promise<PreparedEmail> {
    input = { ...input };
    validateContext(input.tenantId, input.userId);
    // TRUST BOUNDARY: call only after auth validates its verification proof tied to this current user AND
    // exact submitted delivery address. Never expose this method as a client endpoint.
    // Re-screen at activation: no persistent allow-cache or stale allow proof.
    const prepared = await screenSignup(input);
    checkCancellation(input.signal);
    let outcome;
    try {
      outcome = await registry.claim({ tenantId: input.tenantId, userId: input.userId,
        canonical: prepared.canonical, policyVersion: prepared.policyVersion });
    } catch {
      throw new GateError('storage_unavailable', true);
    }
    // Cancellation after a write begins cannot roll it back; retrying the same claim is safe.
    checkCancellation(input.signal);
    if (outcome === 'revoked') throw new GateError('identity_revoked');
    if (outcome === 'policy-mismatch') throw new GateError('policy_mismatch');
    if (outcome === 'conflict') throw new GateError('identity_conflict');
    if (outcome !== 'claimed' && outcome !== 'already-owned') throw new GateError('storage_unavailable', true);
    return prepared;
  }

  async function assertActive(input: VerifiedInput): Promise<PreparedEmail> {
    input = { ...input };
    validateContext(input.tenantId, input.userId);
    checkCancellation(input.signal);
    const prepared = prepareEmail(input.email);
    let owns: boolean;
    try {
      owns = await registry.owns({ tenantId: input.tenantId, userId: input.userId, canonical: prepared.canonical });
    } catch {
      throw new GateError('storage_unavailable', true);
    }
    checkCancellation(input.signal);
    if (owns !== true) throw new GateError('ownership_required');
    return prepared;
  }
  return Object.freeze({ emailPolicy, screenSignup, claimVerified, assertActive });
}
export type Gate = ReturnType<typeof createGate>;
