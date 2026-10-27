import { createHash, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

export interface LocalOAuthProfile {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  picture?: string;
  /** Test-only ID-token failure controls. Omit for a valid token. */
  idTokenFault?: 'bad-signature' | 'wrong-nonce' | 'wrong-issuer' | 'wrong-audience' | 'expired';
}

export interface LocalOAuthProvider {
  issuer: string;
  discoveryUrl: string;
  clientId: string;
  clientSecret: string;
  setProfile(profile: LocalOAuthProfile): void;
  authorize(authorizeURL: string): Promise<{ callbackURL: string }>;
  close(): Promise<void>;
}

interface PendingAuthorization {
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  codeChallenge: string;
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  response.end(JSON.stringify(body));
}

async function readForm(request: IncomingMessage): Promise<URLSearchParams> {
  let body = '';
  for await (const chunk of request) {
    body += Buffer.from(chunk).toString('utf8');
    if (Buffer.byteLength(body, 'utf8') > 16 * 1024) throw new Error('request_too_large');
  }
  return new URLSearchParams(body);
}

function bearerToken(request: IncomingMessage): string | undefined {
  const value = request.headers.authorization;
  return value?.startsWith('Bearer ') ? value.slice(7) : undefined;
}

/**
 * Starts a real loopback OIDC server for Better Auth genericOAuth integration
 * tests. It uses generated RSA keys, real discovery/JWKS, signed ID tokens,
 * state/nonce, client-secret token exchange, and S256 PKCE. No external network
 * or provider credentials are involved.
 */
export async function startLocalOAuthProvider(): Promise<LocalOAuthProvider> {
  const clientId = 'local-oauth-client';
  const clientSecret = 'local-oauth-client-secret';
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privateKeyObject = privateKey as KeyObject;
  const publicJwk = publicKey.export({ format: 'jwk' });
  const keyId = 'local-rsa-1';
  const pending = new Map<string, PendingAuthorization>();
  const accessTokens = new Set<string>();
  let profile: LocalOAuthProfile = {
    sub: 'local-user-1', email: 'local-user@example.test', email_verified: true, name: 'Local OIDC User',
  };
  let issuer = '';

  const server: Server = createServer(async (request, response) => {
    try {
      const origin = issuer;
      const requestUrl = new URL(request.url ?? '/', origin);
      if (request.method === 'GET' && requestUrl.pathname === '/.well-known/openid-configuration') {
        return sendJson(response, 200, {
          issuer: origin,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          userinfo_endpoint: `${origin}/userinfo`,
          jwks_uri: `${origin}/jwks`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          scopes_supported: ['openid', 'email', 'profile'],
          token_endpoint_auth_methods_supported: ['client_secret_post'],
          code_challenge_methods_supported: ['S256'],
        });
      }
      if (request.method === 'GET' && requestUrl.pathname === '/jwks') {
        return sendJson(response, 200, { keys: [{ ...publicJwk, kid: keyId, use: 'sig', alg: 'RS256' }] });
      }
      if (request.method === 'GET' && requestUrl.pathname === '/authorize') {
        const query = requestUrl.searchParams;
        const redirectUri = query.get('redirect_uri');
        const state = query.get('state');
        const nonce = query.get('nonce');
        const challenge = query.get('code_challenge');
        if (query.get('response_type') !== 'code' || query.get('client_id') !== clientId ||
            !redirectUri || !state || !nonce || !challenge || query.get('code_challenge_method') !== 'S256' ||
            !query.get('scope')?.split(/\s+/).includes('openid')) {
          return sendJson(response, 400, { error: 'invalid_request' });
        }
        const callback = new URL(redirectUri);
        if (!['http:', 'https:'].includes(callback.protocol)) return sendJson(response, 400, { error: 'invalid_redirect_uri' });
        const code = randomBytes(24).toString('base64url');
        pending.set(code, { clientId, redirectUri, state, nonce, codeChallenge: challenge });
        callback.searchParams.set('code', code);
        callback.searchParams.set('state', state);
        response.writeHead(302, { location: callback.toString(), 'cache-control': 'no-store' });
        return response.end();
      }
      if (request.method === 'POST' && requestUrl.pathname === '/token') {
        const form = await readForm(request);
        const code = form.get('code') ?? '';
        const grant = pending.get(code);
        const verifier = form.get('code_verifier') ?? '';
        const expectedChallenge = createHash('sha256').update(verifier).digest('base64url');
        const authorizedClient = form.get('client_id') === clientId && form.get('client_secret') === clientSecret;
        if (!grant || grant.clientId !== form.get('client_id') || !authorizedClient ||
            form.get('grant_type') !== 'authorization_code' || grant.redirectUri !== form.get('redirect_uri') ||
            !verifier || expectedChallenge !== grant.codeChallenge) {
          return sendJson(response, 400, { error: 'invalid_grant' });
        }
        pending.delete(code); // An authorization code can be redeemed once.
        const accessToken = randomBytes(32).toString('base64url');
        accessTokens.add(accessToken);
        const { SignJWT } = await import('jose');
        let builder = new SignJWT({
          email: profile.email,
          email_verified: profile.email_verified,
          ...(profile.name ? { name: profile.name } : {}),
          ...(profile.picture ? { picture: profile.picture } : {}),
          nonce: grant.nonce,
        }).setProtectedHeader({ alg: 'RS256', kid: keyId, typ: 'JWT' })
          .setIssuedAt().setExpirationTime(profile.idTokenFault === 'expired' ? 1 : '5m').setSubject(profile.sub)
          .setAudience(profile.idTokenFault === 'wrong-audience' ? 'another-client' : clientId);
        builder = builder.setIssuer(profile.idTokenFault === 'wrong-issuer' ? `${origin}/wrong` : origin);
        let idToken = await builder.sign(privateKeyObject);
        if (profile.idTokenFault === 'wrong-nonce') {
          const { decodeJwt } = await import('jose');
          const claims = decodeJwt(idToken);
          let wrongNonce = new SignJWT({
            email: profile.email, email_verified: profile.email_verified,
            ...(profile.name ? { name: profile.name } : {}),
            nonce: `${String(claims.nonce)}-wrong`,
          }).setProtectedHeader({ alg: 'RS256', kid: keyId, typ: 'JWT' })
            .setIssuedAt().setExpirationTime('5m').setSubject(profile.sub)
            .setAudience(clientId).setIssuer(origin);
          idToken = await wrongNonce.sign(privateKeyObject);
        } else if (profile.idTokenFault === 'bad-signature') {
          const parts = idToken.split('.');
          const signature = parts[2]!;
          parts[2] = `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;
          idToken = parts.join('.');
        }
        return sendJson(response, 200, {
          access_token: accessToken, token_type: 'Bearer', expires_in: 300, id_token: idToken,
        });
      }
      if (request.method === 'GET' && requestUrl.pathname === '/userinfo') {
        const token = bearerToken(request);
        if (!token || !accessTokens.has(token)) return sendJson(response, 401, { error: 'invalid_token' });
        return sendJson(response, 200, {
          sub: profile.sub, email: profile.email, email_verified: profile.email_verified,
          ...(profile.name ? { name: profile.name } : {}),
          ...(profile.picture ? { picture: profile.picture } : {}),
        });
      }
      return sendJson(response, 404, { error: 'not_found' });
    } catch {
      if (!response.headersSent) sendJson(response, 400, { error: 'invalid_request' });
      else response.destroy();
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('loopback_listener_failed');
  issuer = `http://127.0.0.1:${address.port}`;

  return {
    issuer,
    discoveryUrl: `${issuer}/.well-known/openid-configuration`,
    clientId,
    clientSecret,
    setProfile(next) { profile = Object.freeze({ ...next }); },
    async authorize(authorizeURL) {
      const destination = new URL(authorizeURL);
      if (destination.origin !== issuer || destination.pathname !== '/authorize') throw new Error('unexpected_authorization_endpoint');
      const result = await fetch(destination, { redirect: 'manual' });
      const location = result.headers.get('location');
      if (result.status !== 302 || !location) throw new Error('authorization_did_not_redirect');
      const callback = new URL(location);
      if (!callback.searchParams.get('code') || !callback.searchParams.get('state')) throw new Error('invalid_authorization_redirect');
      return { callbackURL: callback.toString() };
    },
    async close() {
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    },
  };
}
