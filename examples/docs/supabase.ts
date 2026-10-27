import { createIronDomeClient } from 'irondome-gates';
import { createOnlinePostgresGate } from 'irondome-gates/online/postgres';
import { createSupabaseGate, type SupabaseProviderUser } from 'irondome-gates/supabase';
import type { PgPool } from 'irondome-gates/postgres';
import { createProviderLifecycle } from 'irondome-gates/provider-lifecycle';
import { createPostgresProviderOperationStore } from 'irondome-gates/provider-lifecycle/postgres';

export interface SupabaseExampleOptions {
  pool: PgPool;
  tenantId: string;
  schema: string;
  projectUrl: string;
  serviceRoleKey: string;
  beforeUserCreatedSecret: string;
  customAccessTokenSecret: string;
  ironDomeApiKey: string;
  // honor cancellation and bound every provider request
  deleteSameGeneration(userId: string, generation: string, signal?: AbortSignal): Promise<void>;
}

function providerSignal(signal?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(4_000);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

export function createSupabaseExample(options: SupabaseExampleOptions) {
  const project = new URL(options.projectUrl);
  if (project.protocol !== 'https:' || project.username || project.password || project.pathname !== '/' || project.search || project.hash) {
    throw new TypeError('Configure an HTTPS Supabase project origin');
  }
  const authUrl = new URL('/auth/v1/', project);
  const engine = createOnlinePostgresGate(options.pool, {
    schema: options.schema,
    screening: createIronDomeClient({ apiKey: options.ironDomeApiKey }),
  });
  const operations = createPostgresProviderOperationStore(options.pool, { schema: options.schema });

  async function readUser(path: string, bearer: string, signal?: AbortSignal): Promise<SupabaseProviderUser | null> {
    const deadline = providerSignal(signal);
    const response = await fetch(new URL(path, authUrl), {
      headers: { apikey: options.serviceRoleKey, authorization: `Bearer ${bearer}` },
      signal: deadline,
    });
    if (response.status === 404 || (path === 'user' && response.status === 401)) return null;
    if (!response.ok) throw new Error('Supabase lookup unavailable');
    const user = await response.json() as SupabaseProviderUser;
    if (typeof user.id !== 'string' || !(user.email === null || typeof user.email === 'string') ||
        !(user.email_confirmed_at === null || typeof user.email_confirmed_at === 'string')) {
      throw new Error('Invalid Supabase profile');
    }
    return user;
  }
  const getUserById = (id: string, signal?: AbortSignal) =>
    readUser(`admin/users/${encodeURIComponent(id)}`, options.serviceRoleKey, signal);
  const getUserForAccessToken = (token: string, signal?: AbortSignal) =>
    readUser('user', token, signal);

  const lifecycle = createProviderLifecycle({
    tenantId: options.tenantId,
    namespace: project.origin,
    engine,
    operations,
    async getUserById(id, signal) {
      const user = await getUserById(id, signal);
      if (!user) return null;
      if (user.id !== id || !user.email || typeof user.created_at !== 'string') {
        throw new Error('Invalid Supabase lifecycle profile');
      }
      return {
        id: user.id, email: user.email,
        emailVerified: !!user.email_confirmed_at,
        generation: user.created_at,
      };
    },
    deleteUser: (id, generation, signal) =>
      options.deleteSameGeneration(id, generation, providerSignal(signal)),
  });
  const common = {
    tenantId: options.tenantId,
    gate: engine,
    getUserById,
    getUserForAccessToken,
    lifecycle,
  };
  // keep each adapter alive across requests; each hook has its own signing secret
  const signup = createSupabaseGate({ ...common, webhookSecret: options.beforeUserCreatedSecret });
  const tokens = createSupabaseGate({ ...common, webhookSecret: options.customAccessTokenSecret });

  function handleHook(request: Request): Promise<Response> {
    if (request.method !== 'POST') return Promise.resolve(new Response(null, { status: 405 }));
    switch (new URL(request.url).pathname) {
      case '/hooks/gates/before-user-created': return signup.beforeUserCreated(request);
      case '/hooks/gates/custom-access-token': return tokens.customAccessToken(request);
      default: return Promise.resolve(new Response(null, { status: 404 }));
    }
  }
  return { engine, lifecycle, operations, handleHook, requireActiveUser: tokens.assertActive };
}
