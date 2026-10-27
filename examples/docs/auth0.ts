import { createIronDomeClient } from 'irondome-gates';
import { createOnlinePostgresGate } from 'irondome-gates/online/postgres';
import { createAuth0Gate, type Auth0CurrentUser } from 'irondome-gates/auth0';
import type { PgPool } from 'irondome-gates/postgres';
import { createProviderLifecycle } from 'irondome-gates/provider-lifecycle';
import { createPostgresProviderOperationStore } from 'irondome-gates/provider-lifecycle/postgres';

export interface Auth0ExampleOptions {
  pool: PgPool;
  tenantId: string;
  schema: string;
  issuer: string;
  trustedConnections: readonly string[];
  ironDomeApiKey: string;
  // honor cancellation, including token acquisition
  getManagementAccessToken(signal?: AbortSignal): Promise<string>;
  verifyAccessToken(token: string): Promise<{ sub: string }>;
  // honor cancellation and bound every provider request
  deleteSameGeneration(userId: string, generation: string, signal?: AbortSignal): Promise<void>;
}

function providerSignal(signal?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(4_000);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

export function createAuth0Example(options: Auth0ExampleOptions) {
  const issuer = new URL(options.issuer);
  if (issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.pathname !== '/' || issuer.search || issuer.hash) {
    throw new TypeError('Configure an HTTPS Auth0 issuer origin');
  }
  const engine = createOnlinePostgresGate(options.pool, {
    schema: options.schema,
    screening: createIronDomeClient({ apiKey: options.ironDomeApiKey }),
  });
  const operations = createPostgresProviderOperationStore(options.pool, { schema: options.schema });

  async function getUserById(id: string, signal?: AbortSignal): Promise<Auth0CurrentUser | null> {
    const deadline = providerSignal(signal);
    const token = await options.getManagementAccessToken(deadline);
    const response = await fetch(new URL(`/api/v2/users/${encodeURIComponent(id)}`, issuer), {
      headers: { authorization: `Bearer ${token}` },
      signal: deadline,
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error('Auth0 lookup unavailable');
    const user = await response.json() as Auth0CurrentUser;
    if (user.user_id !== id || typeof user.email !== 'string' || typeof user.created_at !== 'string') {
      throw new Error('Invalid Auth0 profile');
    }
    return user;
  }

  const lifecycle = createProviderLifecycle({
    tenantId: options.tenantId,
    namespace: issuer.origin,
    engine,
    operations,
    async getUserById(id, signal) {
      const user = await getUserById(id, signal);
      return user ? {
        id: user.user_id,
        email: user.email as string,
        emailVerified: user.email_verified === true,
        generation: user.created_at as string,
      } : null;
    },
    deleteUser: (id, generation, signal) =>
      options.deleteSameGeneration(id, generation, providerSignal(signal)),
  });
  const adapter = createAuth0Gate({
    tenantId: options.tenantId,
    engine,
    trustedConnections: options.trustedConnections,
    getUserById,
    lifecycle,
    actionTimeoutMs: 10_000,
  });

  async function requireActiveUser(accessToken: string): Promise<{ sub: string }> {
    // the host verifier must check signature, issuer, audience and expiry
    const principal = await options.verifyAccessToken(accessToken);
    await adapter.assertActive(principal);
    return principal;
  }

  return { engine, adapter, lifecycle, operations, requireActiveUser };
}
