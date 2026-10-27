import { randomUUID } from 'node:crypto';
import { GateError } from './errors.js';
import type { LifecycleGate } from './lifecycle.js';
import { prepareEmail, validateContext, type EmailPolicy, type PreparedEmail } from './policy.js';

type ContextualEmailPreparation = (input: { tenantId: string; email: unknown; policyVersion?: string; signal?: AbortSignal }) => Promise<PreparedEmail>;
type ProviderLifecycleEngine = Omit<LifecycleGate, 'emailPolicy'> & { readonly emailPolicy?: EmailPolicy; readonly prepareEmail?: ContextualEmailPreparation };

/** Fresh server-side provider state, never taken from client metadata or an unverified JWT. */
export interface ProviderUser {
  id: string;
  email: string;
  emailVerified: boolean;
  /** Immutable provider creation timestamp or a host-owned principal generation. */
  generation: string;
}
export interface ProviderOperation {
  id: string;
  kind: 'email-change' | 'delete';
  generation: string;
  previousEmail: string | null;
  nextEmail: string | null;
  expectedRevision: string | null;
  status: 'pending' | 'complete' | 'deleting' | 'deleted';
  expiresAt: Date;
}
export interface ProviderScope { namespace: string; tenantId: string; userId: string }
export interface ProviderTransaction {
  read(): Promise<ProviderOperation | null>;
  write(operation: ProviderOperation): Promise<void>;
}
export interface ProviderOperationStore {
  /** Must serialize across processes; callback errors roll back metadata, not an already committed Gate write. */
  withUserLock<T>(scope: ProviderScope, work: (transaction: ProviderTransaction) => Promise<T>): Promise<T>;
}
export interface ProviderLifecycleOptions {
  tenantId: string;
  /** Fixed issuer/project identifier, never supplied by the request. */
  namespace: string;
  engine: ProviderLifecycleEngine;
  operations: ProviderOperationStore;
  getUserById(id: string, signal?: AbortSignal): Promise<ProviderUser | null>;
  /** Host-owned admin capability. Verify the generation and coordinate all deletes/ID reuse. */
  deleteUser(id: string, generation: string, signal?: AbortSignal): Promise<void>;
  operationTtlMs?: number;
}
export interface ProviderUserInput { userId: string; signal?: AbortSignal }

/** Trusted server lifecycle capabilities. Call only after authenticating/authorizing the provider user. */
export function createProviderLifecycle(options: ProviderLifecycleOptions) {
  const { tenantId, namespace, engine, operations, getUserById, deleteUser } = options;
  const emailPolicy = engine.emailPolicy;
  const prepare = emailPolicy ? emailPolicy.prepareEmail.bind(emailPolicy) : prepareEmail;
  const prepareForOwnership = engine.prepareEmail?.bind(engine);
  validateContext(tenantId, namespace);
  const ttl = options.operationTtlMs ?? 3_600_000;
  if (!Number.isSafeInteger(ttl) || ttl < 1000 || ttl > 86_400_000) throw new TypeError('Invalid provider operation expiry');
  function check(signal?: AbortSignal) { if (signal?.aborted) throw new GateError('cancelled'); }
  function scope(input: ProviderUserInput): ProviderScope { validateContext(tenantId, input.userId); check(input.signal); return { namespace, tenantId, userId: input.userId }; }
  async function safe<T>(work: () => Promise<T>): Promise<T> {
    try { return await work(); } catch (error) { if (error instanceof GateError) throw error; throw new GateError('storage_unavailable', true); }
  }
  async function current(input: ProviderUserInput): Promise<ProviderUser | null> {
    check(input.signal);
    const value = await safe(() => getUserById(input.userId, input.signal));
    check(input.signal);
    if (value === null) return null;
    if (!value || value.id !== input.userId || typeof value.emailVerified !== 'boolean' ||
        typeof value.generation !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(value.generation)) throw new GateError('ownership_required');
    const prepared = prepareForOwnership
      ? await prepareForOwnership({ tenantId, email: value.email, ...(input.signal ? { signal: input.signal } : {}) })
      : prepare(value.email);
    return Object.freeze({ id: value.id, email: prepared.deliveryEmail, emailVerified: value.emailVerified, generation: value.generation });
  }
  async function verified(input: ProviderUserInput): Promise<ProviderUser> {
    const user = await current(input);
    if (!user?.emailVerified) throw new GateError('ownership_required');
    return user;
  }
  async function assertActive(raw: ProviderUserInput): Promise<ProviderUser> {
    const input = { ...raw }; scope(input);
    const user = await verified(input);
    await engine.assertActive({ tenantId, userId: user.id, email: user.email, ...(input.signal ? { signal: input.signal } : {}) });
    return user;
  }
  async function beginEmailChange(raw: ProviderUserInput & { email: unknown }): Promise<{ operationId: string; expiresAt: string }> {
    const input = { ...raw }; const key = scope(input);
    const next = prepare(input.email);
    return safe(() => operations.withUserLock(key, async tx => {
      const previous = await tx.read();
      if (previous?.kind === 'delete') throw new GateError('identity_revoked');
      const user = await assertActive(input);
      const state = await engine.getOwnership({ tenantId, userId: user.id });
      if (state.status !== 'active') throw new GateError('ownership_required');
      const previousEmail = prepareForOwnership
        ? await prepareForOwnership({ tenantId, email: user.email, policyVersion: state.policyVersion, ...(input.signal ? { signal: input.signal } : {}) })
        : prepare(user.email);
      if (state.canonical !== previousEmail.canonical) throw new GateError('ownership_required');
      if (user.email === next.deliveryEmail) throw new GateError('invalid_email');
      await engine.screenSignup({ tenantId, email: next.deliveryEmail, ...(input.signal ? { signal: input.signal } : {}) });
      check(input.signal);
      const operation: ProviderOperation = { id: randomUUID(), kind: 'email-change', generation: user.generation,
        previousEmail: user.email, nextEmail: next.deliveryEmail, expectedRevision: state.revision,
        status: 'pending', expiresAt: new Date(Date.now() + ttl) };
      await tx.write(operation);
      return Object.freeze({ operationId: operation.id, expiresAt: operation.expiresAt.toISOString() });
    }));
  }
  async function complete(input: ProviderUserInput, tx: ProviderTransaction, operation: ProviderOperation): Promise<void> {
    if (operation.kind !== 'email-change' || !operation.nextEmail || !operation.expectedRevision ||
        !['pending','complete'].includes(operation.status) || operation.expiresAt.getTime() <= Date.now()) throw new GateError('stale_revision');
    const user = await verified(input);
    if (user.generation !== operation.generation || user.email !== operation.nextEmail) throw new GateError('ownership_required');
    if (operation.status === 'complete') {
      await engine.assertActive({ tenantId, userId: user.id, email: user.email, ...(input.signal ? { signal: input.signal } : {}) });
      return;
    }
    await engine.changeVerifiedEmail({ tenantId, userId: user.id, email: user.email, expectedRevision: operation.expectedRevision,
      ...(input.signal ? { signal: input.signal } : {}) });
    check(input.signal);
    await tx.write({ ...operation, status: 'complete' });
  }
  async function completeEmailChange(raw: ProviderUserInput & { operationId: string }): Promise<void> {
    const input = { ...raw }; const key = scope(input);
    await safe(() => operations.withUserLock(key, async tx => {
      const operation = await tx.read();
      if (!operation || operation.id !== input.operationId) throw new GateError('stale_revision');
      await complete(input, tx, operation);
    }));
  }
  async function completePendingEmailChange(raw: ProviderUserInput & { email: string }): Promise<boolean> {
    const input = { ...raw }; const key = scope(input);
    return safe(() => operations.withUserLock(key, async tx => {
      const operation = await tx.read();
      if (!operation || operation.kind !== 'email-change' || operation.status !== 'pending' || operation.nextEmail !== input.email) return false;
      await complete(input, tx, operation);
      return true;
    }));
  }
  async function resumeDeletion(raw: ProviderUserInput): Promise<void> {
    const input = { ...raw }; const key = scope(input);
    await safe(() => operations.withUserLock(key, async tx => {
      const operation = await tx.read();
      if (!operation || operation.kind !== 'delete') throw new GateError('ownership_required');
      // The durable intent committed in an earlier transaction; failures retain it.
      await engine.revokeUser({ tenantId, userId: input.userId, ...(input.signal ? { signal: input.signal } : {}) });
      const user = await current(input);
      if (user && user.generation !== operation.generation) throw new GateError('identity_revoked');
      if (user) await safe(() => deleteUser(user.id, operation.generation, input.signal));
      check(input.signal);
      if (await current(input)) throw new GateError('storage_unavailable', true);
      await tx.write({ ...operation, status: 'deleted' });
    }));
  }
  async function deleteAccount(raw: ProviderUserInput): Promise<void> {
    const input = { ...raw }; const key = scope(input);
    await safe(() => operations.withUserLock(key, async tx => {
      const previous = await tx.read();
      if (previous?.kind === 'delete') return;
      // Deletion authority comes from the trusted caller, not mailbox ownership.
      // Pending/unverified provider accounts must also be safely deprovisionable.
      const user = await current(input);
      if (!user) throw new GateError('ownership_required');
      await tx.write({ id: randomUUID(), kind: 'delete', generation: user.generation, previousEmail: null, nextEmail: null,
        expectedRevision: null, status: 'deleting', expiresAt: new Date(Date.now() + ttl) });
    }));
    await resumeDeletion(input);
  }
  return Object.freeze({ assertActive, beginEmailChange, completeEmailChange, completePendingEmailChange, deleteAccount, resumeDeletion });
}
export type ProviderLifecycle = ReturnType<typeof createProviderLifecycle>;
