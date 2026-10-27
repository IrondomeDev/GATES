export { createGate } from './core/engine.js';
export type { Gate, GateOptions, ScreeningClient, SignupInput, VerifiedInput } from './core/engine.js';
export { prepareEmail, createEmailPolicy, DEFAULT_EMAIL_POLICY, POLICY_VERSION } from './core/policy.js';
export type { PreparedEmail, EmailPolicy, EmailPreparation, DomainCanonicalRule, DomainCanonicalRules } from './core/policy.js';
export { GateError } from './core/errors.js';
export type { GateErrorCode } from './core/errors.js';
export type { IdentityRegistry, ClaimInput, ClaimResult, OwnershipInput, LifecycleIdentityRegistry,
  OwnershipState, UserInput, ReplaceInput, ReplaceResult, RevokeResult } from './core/registry.js';
export { createLifecycleGate } from './core/lifecycle.js';
export type { LifecycleGate, LifecycleGateOptions, LifecycleUserInput, VerifiedChangeInput } from './core/lifecycle.js';
export { createIronDomeClient, IronDomeClientError } from './core/irondome.js';
export type { IronDomeClientOptions, IronDomeDecision } from './core/irondome.js';
export { dryRunBackfill, applyBackfill } from './migration/backfill.js';
export type { BackfillRow, BackfillReport, ApplyBackfillOptions, BackfillApplyReport, BackfillApplyFailure } from './migration/backfill.js';
