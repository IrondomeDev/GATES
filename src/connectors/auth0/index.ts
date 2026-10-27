import { GateError } from '../../core/errors.js';
import type { LifecycleGate } from '../../core/lifecycle.js';
import type { ProviderLifecycle } from '../../core/provider-lifecycle.js';
import { prepareEmail, validateContext, type EmailPolicy, type PreparedEmail } from '../../core/policy.js';

type ContextualEmailPreparation = (input: { tenantId: string; email: unknown; policyVersion?: string; signal?: AbortSignal }) => Promise<PreparedEmail>;
type Auth0LifecycleEngine = Omit<LifecycleGate, 'emailPolicy'> & { readonly emailPolicy?: EmailPolicy; readonly prepareEmail?: ContextualEmailPreparation };

/** Minimal event fields consumed from the Auth0 Pre User Registration v2 event. */
export interface Auth0PreUserRegistrationEvent {
  user?: { email?: unknown };
}

/** Minimal API surface consumed from the Auth0 Pre User Registration v2 API. */
export interface Auth0PreUserRegistrationApi {
  access: { deny(reason: string, userMessage: string): unknown };
}

/** Minimal event fields consumed from the Auth0 Post Login v3 event. */
export interface Auth0PostLoginEvent {
  user?: { user_id?: unknown; email?: unknown; email_verified?: unknown; created_at?: unknown };
  connection?: { id?: unknown };
}

/** Minimal API surface consumed from the Auth0 Post Login v3 API. */
export interface Auth0PostLoginApi {
  access: { deny(reason: string): unknown };
}

/** Claims obtained from a host-validated Auth0 token. This module does not validate JWTs. */
export interface Auth0VerifiedPrincipal {
  sub: string;
  /** Claims are supplied for context only; live provider data is authoritative. */
  email?: string;
  email_verified?: boolean;
}

/** Current Auth0 Management API user profile returned by the host's trusted reader. */
export interface Auth0CurrentUser {
  user_id: string;
  email?: unknown;
  email_verified?: unknown;
  created_at?: unknown;
}

export interface Auth0GateOptions {
  /** Gate namespace, independent of the Auth0 tenant domain. */
  tenantId: string;
  engine: Auth0LifecycleEngine;
  /** Auth0 connection IDs whose `email_verified` profile field is trusted as current proof. */
  trustedConnections: readonly string[];
  /** Optional authoritative Auth0 Management API reader. Required for resource-server checks. */
  getUserById?: (userId: string, signal?: AbortSignal) => Promise<Auth0CurrentUser | null>;
  /** Completes only a previously authorized, revision-captured provider change. */
  lifecycle?: Pick<ProviderLifecycle, 'completePendingEmailChange'>;
  /** Bound all Action work and protected profile reads to this deadline (default 10s, max 15s). */
  actionTimeoutMs?: number;
}

export interface Auth0Gate {
  /** Attach to the Auth0 pre-user-registration trigger (v2). */
  onExecutePreUserRegistration(event: Auth0PreUserRegistrationEvent, api: Auth0PreUserRegistrationApi): Promise<void>;
  /** Attach to the Auth0 post-login trigger (v3). */
  onExecutePostLogin(event: Auth0PostLoginEvent, api: Auth0PostLoginApi): Promise<void>;
  /** Check a principal after the host validates Auth0 JWT signature, issuer, audience, and expiry. */
  assertActive(principal: Auth0VerifiedPrincipal): Promise<void>;
}

const deniedMessage = 'Unable to complete this request.';
const DEFAULT_ACTION_TIMEOUT_MS = 10_000;
const MAX_ACTION_TIMEOUT_MS = 15_000;

function validRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function validConnectionIds(value: readonly string[]): Set<string> {
  if (!Array.isArray(value) || value.length === 0) throw new TypeError('At least one trusted Auth0 connection ID is required');
  const ids = new Set<string>();
  for (const id of value) {
    if (typeof id !== 'string' || id.length < 1 || id.length > 128 || !/^[A-Za-z0-9_-]+$/.test(id) || ids.has(id)) {
      throw new TypeError('Invalid trusted Auth0 connection ID');
    }
    ids.add(id);
  }
  return ids;
}

function denialReason(error: unknown): string {
  if (error instanceof GateError && error.retryable) return 'gate_unavailable';
  if (error instanceof GateError && error.code === 'screening_blocked') return 'screening_denied';
  if (!(error instanceof GateError)) return 'gate_unavailable';
  return 'gate_access_denied';
}

/**
 * Adapts Auth0's blocking Action triggers to the lifecycle gate.
 * Pre-registration only screens: Auth0 does not include verified-email proof in that event.
 * Post-login claims an unclaimed verified profile and only asserts already-owned addresses;
 * profile changes must use a separate revision-captured verification workflow.
 */
export function createAuth0Gate(config: Auth0GateOptions): Auth0Gate {
  validateContext(config.tenantId);
  const trustedConnections = validConnectionIds(config.trustedConnections);
  const timeoutMs = config.actionTimeoutMs ?? DEFAULT_ACTION_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_ACTION_TIMEOUT_MS) throw new TypeError('Invalid Auth0 Action deadline');
  if (config.getUserById !== undefined && typeof config.getUserById !== 'function') throw new TypeError('Invalid Auth0 user reader');
  if (config.lifecycle && !config.getUserById) throw new TypeError('Auth0 user reader required for lifecycle completion');
  const { engine, tenantId } = config;
  const emailPolicy = engine.emailPolicy;
  const prepare = emailPolicy ? emailPolicy.prepareEmail.bind(emailPolicy) : prepareEmail;
  const prepareForOwnership = engine.prepareEmail?.bind(engine);
  const getUserById = config.getUserById;
  const completePendingEmailChange = config.lifecycle?.completePendingEmailChange.bind(config.lifecycle);

  async function withDeadline<T>(work: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new GateError('screening_unavailable', true));
      }, timeoutMs);
    });
    try {
      return await Promise.race([Promise.resolve().then(() => work(controller.signal)), timeout]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      controller.abort();
    }
  }

  async function currentUser(userId: string, signal: AbortSignal): Promise<Auth0CurrentUser> {
    if (!getUserById) throw new GateError('ownership_required');
    if (signal.aborted) throw new GateError('cancelled');
    let result: Auth0CurrentUser | null;
    try { result = await getUserById(userId, signal); }
    catch { throw new GateError('storage_unavailable', true); }
    if (signal.aborted) throw new GateError('cancelled');
    if (!result || typeof result !== 'object') throw new GateError('ownership_required');
    // Snapshot mutable provider SDK objects before any later operation can observe changed fields.
    const profile: Auth0CurrentUser = {
      user_id: result.user_id,
      email: result.email,
      email_verified: result.email_verified,
      created_at: result.created_at,
    };
    if (profile.user_id !== userId || typeof profile.email !== 'string' || profile.email_verified !== true ||
        typeof profile.created_at !== 'string') {
      throw new GateError('ownership_required');
    }
    return Object.freeze(profile);
  }

  async function assertActive(principal: Auth0VerifiedPrincipal): Promise<void> {
    if (!principal || typeof principal !== 'object' || typeof principal.sub !== 'string') {
      throw new GateError('ownership_required');
    }
    const userId = principal.sub;
    await withDeadline(async signal => {
      const profile = await currentUser(userId, signal);
      const state = await engine.getOwnership({ tenantId, userId, signal });
      const prepared = prepareForOwnership
        ? await prepareForOwnership({ tenantId, email: profile.email, ...(state.status === 'active' ? { policyVersion: state.policyVersion } : {}), signal })
        : prepare(profile.email);
      if (state.status !== 'active' || state.canonical !== prepared.canonical) throw new GateError('ownership_required');
      await engine.assertActive({ tenantId, userId, email: profile.email as string, signal });
    });
  }

  return Object.freeze({
    async onExecutePreUserRegistration(event: Auth0PreUserRegistrationEvent, api: Auth0PreUserRegistrationApi): Promise<void> {
      const eventUser = validRecord(event) && validRecord(event.user) ? event.user : undefined;
      const email = eventUser?.email;
      try {
        await withDeadline(signal => engine.screenSignup({ tenantId, email, signal }));
      } catch (error) {
        const reason = denialReason(error);
        api.access.deny(reason, deniedMessage);
      }
    },

    async onExecutePostLogin(event: Auth0PostLoginEvent, api: Auth0PostLoginApi): Promise<void> {
      // These values are Auth0 Action inputs: copy primitives before the first await so a reused
      // or mutable event object cannot retarget a proof while a Management API read is pending.
      const eventUser = validRecord(event) && validRecord(event.user) ? event.user : undefined;
      const eventConnection = validRecord(event) && validRecord(event.connection) ? event.connection : undefined;
      const userId = eventUser?.user_id;
      const email = eventUser?.email;
      const emailVerified = eventUser?.email_verified;
      const createdAt = eventUser?.created_at;
      const connectionId = eventConnection?.id;
      try {
        await withDeadline(async signal => {
          if (typeof userId !== 'string' || emailVerified !== true ||
              typeof connectionId !== 'string' || !trustedConnections.has(connectionId)) {
            throw new GateError('ownership_required');
          }
          let freshProfile: Auth0CurrentUser | undefined;
          if (getUserById) {
            const current = await currentUser(userId, signal);
            if (current.email !== email ||
                (typeof createdAt === 'string' && current.created_at !== createdAt)) {
              throw new GateError('ownership_required');
            }
            freshProfile = current;
          }
          const state = await engine.getOwnership({ tenantId, userId, signal });
          const prepared = prepareForOwnership
            ? await prepareForOwnership({ tenantId, email, ...(state.status === 'active' ? { policyVersion: state.policyVersion } : {}), signal })
            : prepare(email);
          if (state.status === 'active') {
            // Even a same-canonical delivery change must advance its captured revision.
            const completed = completePendingEmailChange && freshProfile ? await completePendingEmailChange({
                userId: freshProfile.user_id, email: freshProfile.email as string, signal,
              }) : false;
            if (state.canonical !== prepared.canonical && !completed) throw new GateError('identity_conflict');
            await engine.assertActive({ tenantId, userId, email: prepared.deliveryEmail, signal });
            return;
          }
          if (state.status === 'unclaimed') {
            await engine.claimVerified({ tenantId, userId, email: prepared.deliveryEmail, signal });
            return;
          }
          throw new GateError('identity_revoked');
        });
      } catch (error) {
        api.access.deny(denialReason(error));
      }
    },

    assertActive,
  });
}
