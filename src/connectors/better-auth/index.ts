import { createHash, randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { BetterAuthOptions, StandardSchemaV1 } from 'better-auth';
import { APIError, createAuthEndpoint, createEmailVerificationToken, sensitiveSessionMiddleware, verifyEmail as providerVerifyEmail, type AuthEndpoint } from 'better-auth/api';
import { genericOAuth, type GenericOAuthConfig } from 'better-auth/plugins/generic-oauth';
import { prepareEmail, validateContext, type EmailPolicy, type PreparedEmail } from '../../core/policy.js';
import type { LifecycleGate } from '../../core/lifecycle.js';
import type { BetterAuthChange, BetterAuthChangeStore } from './store.js';
export type { BetterAuthChange, BetterAuthChangeStore } from './store.js';

export const BETTER_AUTH_TESTED_VERSION = '1.7.7';
export interface BetterAuthGateEngine {
  emailPolicy?: EmailPolicy;
  prepareEmail?: (input: { tenantId: string; email: unknown; policyVersion?: string; signal?: AbortSignal }) => Promise<PreparedEmail>;
  screenSignup(input: { tenantId: string; email: string }): Promise<unknown>;
  claimVerified(input: { tenantId: string; userId: string; email: string }): Promise<unknown>;
  assertActive(input: { tenantId: string; userId: string; email: string }): Promise<unknown>;
  getOwnership?: LifecycleGate['getOwnership'];
  changeVerifiedEmail?: LifecycleGate['changeVerifiedEmail'];
  revokeUser?: LifecycleGate['revokeUser'];
}
export interface BetterAuthGateUser {
  id: string;
  email: string;
  emailVerified: boolean;
  gateDeliveryEmail?: unknown;
}
type VerificationMessage = { user: BetterAuthGateUser & Record<string, unknown>; url: string; token: string };
export interface BetterAuthGateOptions {
  tenantId: string;
  engine: BetterAuthGateEngine;
  sendVerificationEmail(message: VerificationMessage, request?: Request): Promise<void>;
  /** Enables durable verification binding, verified email changes and terminal deletion. */
  changes?: BetterAuthChangeStore;
  /** Every enabled provider must be explicitly trusted to attest email ownership. */
  trustedOAuthProviders?: readonly string[];
  socialProviders?: BetterAuthOptions['socialProviders'];
  oauthProviders?: readonly GenericOAuthConfig[];
  /** Only for disposable loopback OIDC tests; HTTPS is otherwise mandatory. */
  allowLocalOAuth?: boolean;
  verificationExpiresIn?: number;
}
interface AuthLike {
  options: BetterAuthOptions;
  handler(request: Request): Promise<Response>;
  api: { getSession(input: { headers: Headers; query: { disableCookieCache: boolean } }): Promise<unknown> };
  $context: Promise<{ secret: string; internalAdapter: { findUserById(id: string): Promise<unknown>; deleteUser(id: string): Promise<unknown> } }>;
}
type ProviderContext = Parameters<NonNullable<NonNullable<BetterAuthOptions['user']>['validateUserInfo']>>[1];
type OAuthProof = { delivery: string; providerId: string; action: string };
function deny(retryable = false): never {
  throw new APIError(retryable ? 'SERVICE_UNAVAILABLE' : 'FORBIDDEN', {
    code: retryable ? 'GATE_UNAVAILABLE' : 'GATE_ACCESS_DENIED', message: 'Unable to complete this request.',
  });
}
function asUser(value: unknown): BetterAuthGateUser {
  if (!value || typeof value !== 'object') return deny();
  const user = value as Partial<BetterAuthGateUser>;
  if (typeof user.id !== 'string' || typeof user.email !== 'string' || typeof user.emailVerified !== 'boolean' ||
      typeof user.gateDeliveryEmail !== 'string' || user.gateDeliveryEmail.toLowerCase() !== user.email) return deny();
  return user as BetterAuthGateUser;
}
const tokenHash = (token: string) => createHash('sha256').update(token).digest('hex');
const changeBody: StandardSchemaV1<unknown, { newEmail: string; callbackURL?: string }> = {
  '~standard': { version: 1, vendor: 'irondome-gate', validate(value) {
    if (!value || typeof value !== 'object' || !('newEmail' in value) || typeof value.newEmail !== 'string' ||
        ('callbackURL' in value && value.callbackURL !== undefined && typeof value.callbackURL !== 'string')) {
      return { issues: [{ message: 'Invalid email change request' }] };
    }
    return { value: value as { newEmail: string; callbackURL?: string } };
  } },
};
interface GatePlugin {
  id: 'irondome-gate';
  version: string;
  endpoints: {
    changeEmail: AuthEndpoint<'/change-email', { method: 'POST'; body: typeof changeBody; use: (typeof sensitiveSessionMiddleware)[] }, { status: boolean; message?: string }>;
    verifyEmail: typeof providerVerifyEmail;
  };
}
export interface BetterAuthGateIntegration {
  authOptions: BetterAuthOptions & { plugins: [GatePlugin, ...ReturnType<typeof genericOAuth>[]] };
  bind(auth: AuthLike): {
    handler(request: Request): Promise<Response>;
    getActiveSession(headers: Headers): Promise<unknown | null>;
    /** Trusted operator/job only, after terminal Gate revocation. Not a public auth API. */
    resumeDeletion(input: { userId: string }): Promise<void>;
  };
}

/** Provider-native proof/session handling plus fail-closed Gate admission and lifecycle binding. */
export function createBetterAuthGate(config: BetterAuthGateOptions): BetterAuthGateIntegration {
  validateContext(config.tenantId);
  const { engine, tenantId, changes, sendVerificationEmail } = config;
  const emailPolicy = engine.emailPolicy;
  const prepare = emailPolicy ? emailPolicy.prepareEmail.bind(emailPolicy) : prepareEmail;
  const prepareForOwnership = engine.prepareEmail?.bind(engine);
  const expiresIn = config.verificationExpiresIn ?? 3600;
  if (!Number.isSafeInteger(expiresIn) || expiresIn < 1 || expiresIn > 3600) throw new TypeError('Invalid verification expiry');
  const getOwnership = engine.getOwnership?.bind(engine);
  const changeVerifiedEmail = engine.changeVerifiedEmail?.bind(engine);
  const revokeUser = engine.revokeUser?.bind(engine);
  if (changes && (!getOwnership || !changeVerifiedEmail || !revokeUser)) throw new TypeError('Lifecycle engine required');
  let authContext: AuthLike['$context'] | undefined;
  let boundAuth: AuthLike | undefined;
  const oauthProofs = new WeakMap<object, OAuthProof>();
  const completedChanges = new WeakMap<object, BetterAuthChange>();
  const deletionScope = new AsyncLocalStorage<string>();
  const trusted = new Set(config.trustedOAuthProviders ?? []);
  const socialProviders: NonNullable<BetterAuthOptions['socialProviders']> = {};
  for (const [id, value] of Object.entries(config.socialProviders ?? {})) {
    if (!trusted.has(id) || !value || typeof value !== 'object') throw new TypeError('OAuth provider trust required');
    Object.assign(socialProviders, { [id]: { ...value, requireEmailVerification: true, overrideUserInfoOnSignIn: false } });
  }
  const configuredProviders = new Set(Object.keys(socialProviders));
  const oauthProviders = (config.oauthProviders ?? []).map(provider => {
    if (configuredProviders.has(provider.providerId)) throw new TypeError('Duplicate OAuth provider');
    configuredProviders.add(provider.providerId);
    if (!trusted.has(provider.providerId) || !provider.discoveryUrl) throw new TypeError('Verified OIDC discovery required');
    const url = new URL(provider.discoveryUrl);
    if (url.protocol !== 'https:' && !(config.allowLocalOAuth === true && url.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(url.hostname))) throw new TypeError('HTTPS OIDC discovery required');
    return { ...provider, pkce: true, requireIdTokenVerification: true, overrideUserInfo: false };
  });
  async function guarded<T>(work: () => Promise<T>): Promise<T> {
    try { return await work(); }
    catch (error) {
      if (error instanceof APIError) return deny(error.statusCode >= 500);
      const retryable = error && typeof error === 'object' && 'retryable' in error && typeof error.retryable === 'boolean'
        ? error.retryable : true;
      deny(retryable);
    }
  }
  async function assertUser(value: unknown): Promise<BetterAuthGateUser> {
    const user = asUser(value);
    if (!user.emailVerified) return deny();
    if (getOwnership) {
      const state = await guarded(() => getOwnership({ tenantId, userId: user.id }));
      if (state.status !== 'active') return deny();
      const prepared = await guarded(() => prepareForOwnership
        ? prepareForOwnership({ tenantId, email: user.gateDeliveryEmail, policyVersion: state.policyVersion })
        : Promise.resolve(prepare(user.gateDeliveryEmail)));
      if (state.canonical !== prepared.canonical) return deny();
    }
    await guarded(() => engine.assertActive({ tenantId, userId: user.id, email: user.gateDeliveryEmail as string }));
    return user;
  }
  async function binding(context: ProviderContext): Promise<BetterAuthChange> {
    const token = context.query?.token;
    if (!changes || typeof token !== 'string' || token.length > 8192) return deny();
    const intent = await guarded(() => changes.find({ tenantId, tokenHash: tokenHash(token) }));
    if (!intent || intent.tenantId !== tenantId || intent.expiresAt.getTime() <= Date.now()) return deny();
    return intent;
  }
  async function completeChange(context: ProviderContext, expectedUserId?: string): Promise<BetterAuthChange> {
    const cached = completedChanges.get(context.context);
    if (cached) { if (expectedUserId && cached.userId !== expectedUserId) return deny(); return cached; }
    const intent = await binding(context);
    if (intent.purpose !== 'change-email' || !changeVerifiedEmail || (expectedUserId && intent.userId !== expectedUserId)) return deny();
    const current = asUser(await guarded(() => context.context.internalAdapter.findUserById(intent.userId)));
    if (!current.emailVerified || current.gateDeliveryEmail !== intent.previousDeliveryEmail || current.email !== intent.previousDeliveryEmail.toLowerCase()) return deny();
    await guarded(() => changeVerifiedEmail({ tenantId, userId: current.id, email: intent.nextDeliveryEmail, expectedRevision: intent.expectedRevision }));
    completedChanges.set(context.context, intent);
    return intent;
  }

  const changeEmail = createAuthEndpoint('/change-email', { method: 'POST', body: changeBody, use: [sensitiveSessionMiddleware] }, async ctx => {
    if (!changes || !getOwnership) return deny();
    const session = ctx.context.session;
    if (!session) return deny();
    const current = await assertUser(await ctx.context.internalAdapter.findUserById(session.user.id));
    if (ctx.context.sessionConfig.freshAge === 0 || Date.now() - new Date(session.session.createdAt).getTime() >= ctx.context.sessionConfig.freshAge * 1000) return deny();
    const next = await guarded(async () => prepare(ctx.body.newEmail));
    if (next.deliveryEmail.toLowerCase() === current.email) return deny();
    const state = await guarded(() => getOwnership({ tenantId, userId: current.id }));
    if (state.status !== 'active') return deny();
    const currentPrepared = await guarded(() => prepareForOwnership
      ? prepareForOwnership({ tenantId, email: current.gateDeliveryEmail, policyVersion: state.policyVersion })
      : Promise.resolve(prepare(current.gateDeliveryEmail)));
    if (state.canonical !== currentPrepared.canonical) return deny();
    await guarded(() => engine.screenSignup({ tenantId, email: next.deliveryEmail }));
    // Keep Better Auth's generic response for an occupied login address.
    if (await guarded(() => ctx.context.internalAdapter.findUserByEmail(next.deliveryEmail.toLowerCase()))) return ctx.json({ status: true });
    const token = await createEmailVerificationToken(ctx.context.secret, current.email, next.deliveryEmail, expiresIn,
      { requestType: 'change-email-verification', gateOperation: randomUUID() });
    const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${encodeURIComponent(ctx.body.callbackURL ?? '/')}`;
    await guarded(() => changes.save({ tenantId, userId: current.id, tokenHash: tokenHash(token), purpose: 'change-email',
      previousDeliveryEmail: current.gateDeliveryEmail as string, nextDeliveryEmail: next.deliveryEmail,
      expectedRevision: state.revision, expiresAt: new Date(Date.now() + expiresIn * 1000) }));
    await guarded(() => sendVerificationEmail({ user: { ...current, email: next.deliveryEmail }, url, token }, ctx.request));
    return ctx.json({ status: true, message: 'Verification email sent' });
  });
  const verifyEmail: typeof providerVerifyEmail = createAuthEndpoint('/verify-email', providerVerifyEmail.options, async ctx => {
    if (changes) {
      // Native proof verification still runs first. Scope its subsequent lookup and
      // update to the token-bound stable principal. An email WHERE predicate can
      // otherwise target a replacement account after a concurrent delete/recreate.
      const adapter = ctx.context.internalAdapter;
      ctx.context.internalAdapter = {
        ...adapter,
        async findUserByEmail(...args: Parameters<typeof adapter.findUserByEmail>) {
          const found = await adapter.findUserByEmail(...args);
          const intent = await binding(ctx);
          if (found && (found.user.id !== intent.userId || args[0].toLowerCase() !== intent.previousDeliveryEmail.toLowerCase())) return deny();
          return found;
        },
        async updateUserByEmail<T extends Record<string, unknown>>(email: string, data: Parameters<typeof adapter.updateUserByEmail>[1]) {
          const intent = await binding(ctx);
          if (email.toLowerCase() !== intent.previousDeliveryEmail.toLowerCase()) return deny();
          const updated = await adapter.updateUser<T>(intent.userId, data);
          if (!updated || updated.id !== intent.userId) return deny();
          return updated;
        },
      };
    }
    return providerVerifyEmail({ context: ctx.context, query: ctx.query,
      ...(ctx.request ? { request: ctx.request } : {}), ...(ctx.headers ? { headers: ctx.headers } : {}),
      asResponse: false, returnHeaders: false });
  });
  const gatePlugin = { id: 'irondome-gate' as const, version: '0.3.0', endpoints: { changeEmail, verifyEmail } };
  const plugins: [typeof gatePlugin, ...ReturnType<typeof genericOAuth>[]] = [gatePlugin, ...(oauthProviders.length ? [genericOAuth({ config: oauthProviders })] : [])];

  const authOptions = {
    logger: { disabled: true },
    // Better Call's fallback console.error runs even when BA logging is disabled.
    // Throw a fixed APIError from its router error callback before that fallback.
    onAPIError: { onError(error: unknown) { if (!(error instanceof APIError)) deny(true); } },
    emailAndPassword: { enabled: true, requireEmailVerification: true, autoSignIn: false },
    plugins, socialProviders,
    emailVerification: {
      expiresIn, sendOnSignUp: true, sendOnSignIn: true, autoSignInAfterVerification: false,
      async sendVerificationEmail(message, request) {
        const user = asUser(message.user);
        await guarded(() => engine.screenSignup({ tenantId, email: user.gateDeliveryEmail as string }));
        if (!changes) return sendVerificationEmail({ ...message, user: { ...message.user, email: user.gateDeliveryEmail as string } }, request);
        if (!authContext) return deny();
        const context = await authContext;
        const token = await createEmailVerificationToken(context.secret, user.email, undefined, expiresIn, { gateOperation: randomUUID() });
        const url = new URL(message.url); url.searchParams.set('token', token);
        await guarded(() => changes.save({ tenantId, userId: user.id, tokenHash: tokenHash(token), purpose: 'verify-email',
          previousDeliveryEmail: user.gateDeliveryEmail as string, nextDeliveryEmail: user.gateDeliveryEmail as string,
          expectedRevision: '1', expiresAt: new Date(Date.now() + expiresIn * 1000) }));
        await guarded(() => sendVerificationEmail({ user: { ...message.user, email: user.gateDeliveryEmail as string }, url: url.href, token }, request));
      },
      async beforeEmailVerification(value) {
        const user = asUser(value);
        // Lifecycle mode binds the proof to the stable user in the pre-write DB hook.
        if (!changes) await guarded(() => engine.claimVerified({ tenantId, userId: user.id, email: user.gateDeliveryEmail as string }));
      },
    },
    user: {
      changeEmail: { enabled: !!changes, updateEmailWithoutVerification: false },
      deleteUser: { enabled: !!changes,
        async beforeDelete(user) {
          if (!changes || !revokeUser) return deny();
          await guarded(() => revokeUser({ tenantId, userId: user.id }));
          await guarded(() => changes.deleteUser({ tenantId, userId: user.id }));
        },
      },
      additionalFields: { gateDeliveryEmail: { type: 'string', input: false, returned: false, required: false } },
      async validateUserInfo(data, context) {
        if (data.source.method !== 'oauth') {
          if (data.source.method !== 'email-password' || context.path !== '/sign-up/email') return { error: 'GATE_ACCESS_DENIED' };
          return;
        }
        const providerId = data.source.oauth?.providerId;
        if (!providerId || !trusted.has(providerId) || data.source.action === 'link-account' || data.user.emailVerified !== true) return { error: 'GATE_ACCESS_DENIED' };
        try {
          // Use the authenticated provider profile to preserve case before BA lowercases create data.
          const profile = data.source.oauth?.profile;
          const delivery = prepare(profile?.email).deliveryEmail;
          if (typeof data.user.email !== 'string' || delivery.toLowerCase() !== data.user.email.toLowerCase()) return { error: 'GATE_ACCESS_DENIED' };
          if (data.source.action === 'create-user') await engine.screenSignup({ tenantId, email: delivery });
          oauthProofs.set(context.context, { delivery, providerId, action: data.source.action });
        } catch { return { error: 'GATE_ACCESS_DENIED' }; }
      },
    },
    session: { cookieCache: { enabled: false } },
    account: { accountLinking: { enabled: false, disableImplicitLinking: true }, storeAccountCookie: false },
    disabledPaths: [...(changes ? [] : ['/change-email', '/delete-user']), '/delete-user/callback', '/link-social', '/unlink-account'],
    databaseHooks: {
      user: {
        create: { async before(user, context) {
          if (!context) return deny();
          const proof = oauthProofs.get(context.context);
          if (proof) {
            if (proof.action !== 'create-user' || user.emailVerified !== true || user.email !== proof.delivery.toLowerCase()) return deny();
            return { data: { ...user, gateDeliveryEmail: proof.delivery } };
          }
          if (context.path !== '/sign-up/email' || user.emailVerified !== false) return deny();
          let original: string;
          try { original = prepare(context.body?.email).deliveryEmail; } catch { return deny(); }
          if (original.toLowerCase() !== user.email) return deny();
          return { data: { ...user, gateDeliveryEmail: original } };
        } },
        update: { async before(update, context) {
          if ('gateDeliveryEmail' in update) return deny();
          if ('email' in update) {
            if (!changes || context?.path !== '/verify-email' || update.emailVerified !== true) return deny();
            const intent = await completeChange(context);
            if (update.email !== intent.nextDeliveryEmail.toLowerCase()) return deny();
            return { data: { ...update, gateDeliveryEmail: intent.nextDeliveryEmail } };
          }
          if ('emailVerified' in update) {
            if (context?.path !== '/verify-email' || update.emailVerified !== true) return deny();
            if (changes) {
              const intent = await binding(context);
              if (intent.purpose !== 'verify-email') return deny();
              const current = asUser(await context.context.internalAdapter.findUserById(intent.userId));
              if (current.gateDeliveryEmail !== intent.previousDeliveryEmail || current.email !== intent.previousDeliveryEmail.toLowerCase()) return deny();
              // Native verifyEmail targets its current lookup row; confirm it is the bound principal.
              const lookup = await context.context.internalAdapter.findUserByEmail(current.email);
              if (lookup?.user.id !== current.id) return deny();
              await guarded(() => engine.claimVerified({ tenantId, userId: current.id, email: intent.previousDeliveryEmail }));
            }
          }
        } },
        delete: { async before(user, context) {
          const trustedCleanup = deletionScope.getStore() === user.id;
          if (!changes || !revokeUser || (!trustedCleanup &&
              (context?.path !== '/delete-user' || context.context.session?.user.id !== user.id))) return deny();
          // Also fence direct internal deletion on the permitted route, before destructive writes.
          await guarded(() => revokeUser({ tenantId, userId: user.id }));
        } },
      },
      session: { create: { async before(session, context) {
        if (!context) return deny();
        const user = asUser(await context.context.internalAdapter.findUserById(session.userId));
        if (context.path === '/verify-email' && changes) {
          await completeChange(context, user.id);
          return;
        }
        const proof = oauthProofs.get(context.context);
        if (proof && (context.path?.startsWith('/callback/') || context.path === '/sign-in/social')) {
          if (!user.emailVerified || user.gateDeliveryEmail !== proof.delivery) return deny();
          await guarded(() => engine.claimVerified({ tenantId, userId: user.id, email: proof.delivery }));
          return;
        }
        if (!['/sign-in/email', '/verify-email'].includes(context.path ?? '')) return deny();
        await assertUser(user);
      } } },
    },
  } satisfies BetterAuthOptions;

  function freezeTree(value: object): void {
    for (const child of Object.values(value)) if (child && typeof child === 'object' && !Object.isFrozen(child)) freezeTree(child);
    Object.freeze(value);
  }
  freezeTree(authOptions);
  function assertConfiguration(options: BetterAuthOptions): void {
    if (options.plugins?.length !== plugins.length || options.plugins.some((plugin, i) => plugin !== plugins[i]) ||
        options.socialProviders !== authOptions.socialProviders || options.secondaryStorage || options.advanced?.backgroundTasks?.handler ||
        options.advanced?.disableCSRFCheck || options.advanced?.disableOriginCheck ||
        options.databaseHooks !== authOptions.databaseHooks || options.emailVerification !== authOptions.emailVerification ||
        options.emailAndPassword !== authOptions.emailAndPassword || options.user !== authOptions.user ||
        options.session !== authOptions.session || options.account !== authOptions.account || options.logger !== authOptions.logger ||
        options.onAPIError !== authOptions.onAPIError ||
        options.disabledPaths !== authOptions.disabledPaths) throw new Error('Unsupported Better Auth Gate configuration');
  }
  return {
    authOptions,
    bind(auth: AuthLike) {
      assertConfiguration(auth.options);
      if (boundAuth && boundAuth !== auth) throw new Error('Gate integration is already bound');
      boundAuth = auth;
      authContext = auth.$context;
      return {
        async handler(request: Request): Promise<Response> {
          assertConfiguration(auth.options);
          try { return await auth.handler(request); }
          catch { return Response.json({ code: 'GATE_UNAVAILABLE', message: 'Unable to complete this request.' }, { status: 503, headers: { 'cache-control': 'no-store' } }); }
        },
        async resumeDeletion(rawInput: { userId: string }): Promise<void> {
          assertConfiguration(auth.options);
          const userId = rawInput.userId;
          validateContext(tenantId, userId);
          if (!changes || !getOwnership) return deny();
          const state = await guarded(() => getOwnership({ tenantId, userId }));
          if (state.status !== 'revoked') return deny();
          const context = await auth.$context;
          await guarded(() => changes.deleteUser({ tenantId, userId }));
          await deletionScope.run(userId, () => guarded(() => context.internalAdapter.deleteUser(userId)));
          if (await guarded(() => context.internalAdapter.findUserById(userId))) return deny(true);
        },
        async getActiveSession(headers: Headers): Promise<unknown | null> {
          assertConfiguration(auth.options);
          const session = await auth.api.getSession({ headers, query: { disableCookieCache: true } });
          if (!session || typeof session !== 'object' || !('user' in session)) return null;
          const user = (session as { user: unknown }).user;
          if (!user || typeof user !== 'object' || !('id' in user) || typeof user.id !== 'string') return deny();
          const context = await auth.$context;
          await assertUser(await context.internalAdapter.findUserById(user.id));
          return session;
        },
      };
    },
  };
}
