import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Gate } from '../../core/engine.js';
import { GateError } from '../../core/errors.js';
import { prepareEmail, validateContext, type PreparedEmail } from '../../core/policy.js';
import type { LifecycleGate } from '../../core/lifecycle.js';
import type { ProviderLifecycle } from '../../core/provider-lifecycle.js';
import type { EmailPolicy } from '../../core/policy.js';

const MAX_BODY_BYTES = 64 * 1024;
const MAX_EMPTY_READS = 32;
const MAX_SIGNATURE_AGE_SECONDS = 300;
const DEFAULT_REPLAY_IDS = 100_000;
type ContextualEmailPreparation = (input: { tenantId: string; email: unknown; policyVersion?: string; signal?: AbortSignal }) => Promise<PreparedEmail>;
// GoTrue v2.197.0's pre-signing hook may omit an empty issuer; its own output schema
// does not require `iss`. Preserve it when present, but do not invent it here.
const REQUIRED_CLAIMS = ['aud', 'exp', 'iat', 'sub', 'role', 'aal', 'session_id', 'email', 'phone', 'is_anonymous'] as const;

export interface SupabaseProviderUser {
  id: string;
  email: string | null;
  email_confirmed_at: string | null;
  phone_confirmed_at?: string | null;
  email_change?: string;
  [key: string]: unknown;
}
export interface SupabaseAccessTokenEvent {
  user_id: string;
  claims: Record<string, unknown>;
  authentication_method: string;
  [key: string]: unknown;
}
export interface SupabaseGateOptions {
  /** Server-configured tenant; never read from the hook request or user metadata. */
  tenantId: string;
  gate: Pick<Gate, 'screenSignup' | 'claimVerified' | 'assertActive'> & Pick<LifecycleGate, 'getOwnership'> & { emailPolicy?: EmailPolicy; prepareEmail?: ContextualEmailPreparation };
  /** Service-role-backed fresh lookup. Must return GoTrue's current admin user record. */
  getUserById(userId: string, signal?: AbortSignal): Promise<SupabaseProviderUser | null>;
  /** Standard Webhooks secret in whsec_<base64> form. */
  webhookSecret: string;
  /** Optional live auth lookup for protected requests, e.g. Supabase auth.getUser(token). */
  getUserForAccessToken?(accessToken: string, signal?: AbortSignal): Promise<SupabaseProviderUser | null>;
  /** Completes only a previously staged, revision-captured change after provider proof. */
  lifecycle?: Pick<ProviderLifecycle, 'completePendingEmailChange'>;
  now?: () => number;
  maxBodyBytes?: number;
  maxSignatureAgeSeconds?: number;
  /** Per-factory bounded replay window. Size for peak hook rate; replicas do not share it. */
  maxReplayIds?: number;
  hookTimeoutMs?: number;
}

function fixedError(status: number, message = 'Unable to complete this request.'): Response {
  return Response.json({ error: { message, http_code: status } }, { status: 200, headers: { 'cache-control': 'no-store' } });
}
function isRecord(v: unknown): v is Record<string, unknown> { return !!v && typeof v === 'object' && !Array.isArray(v); }
function awaitWithSignal<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new GateError('cancelled'));
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(new GateError('cancelled'));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  return Promise.race([work, aborted]).finally(() => { if (onAbort) signal.removeEventListener('abort', onAbort); });
}
function asProviderUser(v: unknown): SupabaseProviderUser | null {
  if (!isRecord(v) || typeof v.id !== 'string' || !(typeof v.email === 'string' || v.email === null) ||
      !(typeof v.email_confirmed_at === 'string' || v.email_confirmed_at === null) ||
      (v.email_change !== undefined && typeof v.email_change !== 'string')) return null;
  return v as SupabaseProviderUser;
}

function signatureKey(secret: string): Buffer {
  if (secret.startsWith('v1,')) secret = secret.slice(3);
  if (!secret.startsWith('whsec_')) throw new TypeError('Invalid Standard Webhooks secret');
  const key = Buffer.from(secret.slice(6), 'base64');
  if (!key.length) throw new TypeError('Invalid Standard Webhooks secret');
  return key;
}
function signaturesMatch(key: Buffer, id: string, timestamp: string, body: string, header: string): boolean {
  const expected = createHmac('sha256', key).update(`${id}.${timestamp}.${body}`).digest();
  for (const item of header.split(/\s+/)) {
    const match = /^v1,([A-Za-z0-9+/]+={0,2})$/.exec(item);
    if (!match) continue;
    const candidate = Buffer.from(match[1]!, 'base64');
    if (candidate.length === expected.length && timingSafeEqual(candidate, expected)) return true;
  }
  return false;
}

async function readBounded(request: Request, maxBytes: number, signal: AbortSignal): Promise<string> {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maxBytes)) throw new GateError('invalid_context');
  if (!request.body) throw new GateError('invalid_context');
  const reader = request.body.getReader();
  const buffer = new Uint8Array(maxBytes);
  let size = 0;
  let emptyReads = 0;
  let pending: Promise<ReadableStreamReadResult<Uint8Array>> | undefined;
  try {
    for (;;) {
      pending = reader.read();
      const { done, value } = await awaitWithSignal(pending, signal);
      pending = undefined;
      if (done) break;
      if (value.byteLength === 0) {
        if (++emptyReads > MAX_EMPTY_READS) throw new GateError('invalid_context');
        continue;
      }
      emptyReads = 0;
      if (value.byteLength > maxBytes - size) throw new GateError('invalid_context');
      buffer.set(value, size);
      size += value.byteLength;
    }
  } catch (error) {
    // Don't wait for a hostile or broken stream to honor cancellation. Keep the reader lock
    // until its pending read settles, then release it asynchronously.
    if (pending) {
      const outstanding = pending;
      void reader.cancel().catch(() => undefined).then(async () => {
        await outstanding.catch(() => undefined);
        try { reader.releaseLock(); } catch { /* stream implementation already released it */ }
      });
      pending = undefined;
    } else {
      void reader.cancel().catch(() => undefined);
      try { reader.releaseLock(); } catch { /* stream implementation already released it */ }
    }
    throw error;
  }
  try { reader.releaseLock(); } catch { /* completed stream */ }
  return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size));
}

/** Supabase Auth Hooks adapter. It never trusts hook-supplied identity attributes as proof. */
export function createSupabaseGate(options: SupabaseGateOptions) {
  const { tenantId, gate, getUserById, webhookSecret } = options;
  const emailPolicy = gate.emailPolicy;
  const prepare = emailPolicy ? emailPolicy.prepareEmail.bind(emailPolicy) : prepareEmail;
  const prepareForOwnership = gate.prepareEmail?.bind(gate);
  validateContext(tenantId);
  const maxBodyBytes = options.maxBodyBytes ?? MAX_BODY_BYTES;
  const maxAge = options.maxSignatureAgeSeconds ?? MAX_SIGNATURE_AGE_SECONDS;
  const maxReplayIds = options.maxReplayIds ?? DEFAULT_REPLAY_IDS;
  const timeoutMs = options.hookTimeoutMs ?? 4000;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > MAX_BODY_BYTES ||
      !Number.isSafeInteger(maxAge) || maxAge < 1 || maxAge > 900 || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 4500 ||
      !Number.isSafeInteger(maxReplayIds) || maxReplayIds < 1 || maxReplayIds > 1_000_000) throw new TypeError('Invalid Supabase hook bounds');
  const key = signatureKey(webhookSecret);
  const getUserForAccessToken = options.getUserForAccessToken;
  const lifecycle = options.lifecycle;
  const replayIds = new Map<string, number>();
  const now = options.now ?? Date.now;

  async function readHook(request: Request, signal: AbortSignal): Promise<unknown> {
    const id = request.headers.get('webhook-id');
    const timestamp = request.headers.get('webhook-timestamp');
    const signature = request.headers.get('webhook-signature');
    if (!id || id.length > 128 || !/^[\x21-\x7e]+$/.test(id) || !timestamp || !/^\d{1,12}$/.test(timestamp) || !signature || signature.length > 4096) {
      throw new GateError('invalid_context');
    }
    const seconds = Number(timestamp);
    if (!Number.isSafeInteger(seconds) || Math.abs(Math.floor(now() / 1000) - seconds) > maxAge) throw new GateError('invalid_context');
    const body = await readBounded(request, maxBodyBytes, signal);
    if (!signaturesMatch(key, id, timestamp, body, signature)) throw new GateError('invalid_context');
    const current = now();
    // Insertion order gives amortized O(1) expiry, rather than rescanning the entire
    // valid window for every login. Clock regressions conservatively retain IDs.
    for (const [key, seenAt] of replayIds) {
      // A signature accepted maxAge seconds into the future remains valid for
      // another maxAge seconds. Keep IDs for that entire possible interval.
      if (seenAt >= current - maxAge * 2 * 1000) break;
      replayIds.delete(key);
    }
    if (replayIds.has(id)) throw new GateError('invalid_context');
    if (replayIds.size >= maxReplayIds) throw new GateError('storage_unavailable', true);
    replayIds.set(id, current);
    try { return JSON.parse(body) as unknown; } catch { throw new GateError('invalid_context'); }
  }

  async function beforeUserCreated(request: Request): Promise<Response> {
    const controller = new AbortController();
    const signal = AbortSignal.any([request.signal, controller.signal]);
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const event = await readHook(request, signal);
      if (!isRecord(event) || !isRecord(event.user) || typeof event.user.email !== 'string') throw new GateError('invalid_context');
      await awaitWithSignal(gate.screenSignup({ tenantId, email: event.user.email, signal }), signal);
      return Response.json({}, { headers: { 'cache-control': 'no-store' } });
    } catch (e) {
      const code = e instanceof GateError ? e.code : 'storage_unavailable';
      return fixedError(code === 'screening_blocked' ? 403 : code === 'invalid_context' || code === 'invalid_email' ? 400 : 503);
    } finally { clearTimeout(timeout); }
  }

  async function customAccessToken(request: Request): Promise<Response> {
    const controller = new AbortController();
    const signal = AbortSignal.any([request.signal, controller.signal]);
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const event = await readHook(request, signal);
      if (!isRecord(event) || typeof event.user_id !== 'string' || !isRecord(event.claims) ||
          typeof event.authentication_method !== 'string') throw new GateError('invalid_context');
      const sourceClaims = event.claims;
      if (!REQUIRED_CLAIMS.every(k => k in sourceClaims)) throw new GateError('invalid_context');
      const userId = event.user_id;
      validateContext(tenantId, userId);
      if (sourceClaims.sub !== userId) throw new GateError('invalid_context');
      const user = asProviderUser(await awaitWithSignal(getUserById(userId, signal), signal));
      if (!user || user.id !== userId || !user.email || !user.email_confirmed_at || sourceClaims.email !== user.email) throw new GateError('ownership_required');
      // Bind stable provider subject to its existing identity. A changed current email is
      // not an implicit change protocol, even when GoTrue currently reports it verified.
      const ownership = await awaitWithSignal(gate.getOwnership({ tenantId, userId, signal }), signal);
      const prepared = prepareForOwnership
        ? await awaitWithSignal(prepareForOwnership({ tenantId, email: user.email, ...(ownership.status === 'active' ? { policyVersion: ownership.policyVersion } : {}), signal }), signal)
        : prepare(user.email);
      if (ownership.status === 'revoked') throw new GateError('identity_revoked');
      if (ownership.status === 'active') {
        const completed = lifecycle ? await awaitWithSignal(lifecycle.completePendingEmailChange({ userId, email: user.email, signal }), signal) : false;
        if (ownership.canonical !== prepared.canonical) {
          if (!completed) {
            throw new GateError('ownership_required');
          }
          const updated = await awaitWithSignal(gate.getOwnership({ tenantId, userId, signal }), signal);
          const updatedPrepared = prepareForOwnership
            ? await awaitWithSignal(prepareForOwnership({ tenantId, email: user.email, ...(updated.status === 'active' ? { policyVersion: updated.policyVersion } : {}), signal }), signal)
            : prepare(user.email);
          if (updated.status !== 'active' || updated.canonical !== updatedPrepared.canonical) throw new GateError('ownership_required');
        }
        await awaitWithSignal(gate.assertActive({ tenantId, userId, email: prepared.deliveryEmail, signal }), signal);
      } else {
        await awaitWithSignal(gate.claimVerified({ tenantId, userId, email: user.email, signal }), signal);
        await awaitWithSignal(gate.assertActive({ tenantId, userId, email: prepared.deliveryEmail, signal }), signal);
      }
      const claims = { ...sourceClaims };
      return Response.json({ claims }, { headers: { 'cache-control': 'no-store' } });
    } catch (e) {
      const code = e instanceof GateError ? e.code : 'storage_unavailable';
      return fixedError(code === 'screening_blocked' || code === 'identity_conflict' || code === 'identity_revoked' || code === 'ownership_required' ? 403 :
        code === 'invalid_context' || code === 'invalid_email' ? 400 : 503);
    } finally { clearTimeout(timeout); }
  }

  async function assertActive(accessToken: string, signal?: AbortSignal): Promise<SupabaseProviderUser> {
    if (!getUserForAccessToken || typeof accessToken !== 'string' || accessToken.length > 16_384) throw new GateError('ownership_required');
    const controller = new AbortController();
    const effectiveSignal = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const user = asProviderUser(await awaitWithSignal(getUserForAccessToken(accessToken, effectiveSignal), effectiveSignal));
      if (!user || !user.email || !user.email_confirmed_at) throw new GateError('ownership_required');
      validateContext(tenantId, user.id);
      // The engine's single live check selects the active epoch itself. This
      // preparer only preserves/validates delivery; no extra ownership read.
      const prepared = prepare(user.email);
      await awaitWithSignal(gate.assertActive({ tenantId, userId: user.id, email: prepared.deliveryEmail, signal: effectiveSignal }), effectiveSignal);
      return user;
    } catch (error) {
      if (error instanceof GateError) throw error;
      throw new GateError('storage_unavailable', true);
    } finally { clearTimeout(timeout); }
  }

  return Object.freeze({ beforeUserCreated, customAccessToken, assertActive });
}
