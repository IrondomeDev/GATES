import { createGate, type GateOptions, type VerifiedInput } from './engine.js';
import { GateError } from './errors.js';
import { validateContext, type PreparedEmail } from './policy.js';
import { validRevision, type LifecycleIdentityRegistry, type OwnershipState } from './registry.js';

export interface LifecycleGateOptions extends GateOptions { registry: LifecycleIdentityRegistry }
export interface LifecycleUserInput { tenantId: string; userId: string; signal?: AbortSignal }
export interface VerifiedChangeInput extends VerifiedInput { expectedRevision: string }

function check(signal?: AbortSignal): void {
  if (signal?.aborted) throw new GateError('cancelled');
}

/** Trusted server capabilities; provider proof and provider writes remain the adapter's responsibility. */
export function createLifecycleGate(options: LifecycleGateOptions) {
  const gate = createGate(options);
  const registry = options.registry;
  async function getOwnership(rawInput: LifecycleUserInput): Promise<OwnershipState> {
    const input = { ...rawInput };
    validateContext(input.tenantId, input.userId);
    check(input.signal);
    let state: OwnershipState;
    try { state = await registry.getOwnership({ tenantId: input.tenantId, userId: input.userId }); }
    catch { check(input.signal); throw new GateError('storage_unavailable', true); }
    check(input.signal);
    return state;
  }

  async function changeVerifiedEmail(rawInput: VerifiedChangeInput): Promise<PreparedEmail> {
    const input = { ...rawInput };
    validateContext(input.tenantId, input.userId);
    check(input.signal);
    if (!validRevision(input.expectedRevision)) throw new GateError('invalid_context');
    // Capture the revision when starting the provider change flow. The adapter must bind
    // final proof to the exact new address/current provider state, including on retries.
    const prepared = await gate.screenSignup(input);
    check(input.signal);
    let result;
    try {
      result = await registry.replaceVerified({ tenantId: input.tenantId, userId: input.userId,
        canonical: prepared.canonical, policyVersion: prepared.policyVersion, expectedRevision: input.expectedRevision });
    } catch { check(input.signal); throw new GateError('storage_unavailable', true); }
    check(input.signal);
    if (result === 'conflict') throw new GateError('identity_conflict');
    if (result === 'stale') throw new GateError('stale_revision');
    if (result === 'revoked') throw new GateError('identity_revoked');
    if (result === 'policy-mismatch') throw new GateError('policy_mismatch');
    if (result !== 'replaced' && result !== 'already-replaced') throw new GateError('storage_unavailable', true);
    return prepared;
  }

  async function revokeUser(rawInput: LifecycleUserInput): Promise<void> {
    const input = { ...rawInput };
    validateContext(input.tenantId, input.userId);
    check(input.signal);
    let result;
    try { result = await registry.revokeUser({ tenantId: input.tenantId, userId: input.userId }); }
    catch { check(input.signal); throw new GateError('storage_unavailable', true); }
    check(input.signal);
    if (result !== 'revoked' && result !== 'already-revoked') throw new GateError('storage_unavailable', true);
  }
  return Object.freeze({ ...gate, getOwnership, changeVerifiedEmail, revokeUser });
}
export type LifecycleGate = ReturnType<typeof createLifecycleGate>;
