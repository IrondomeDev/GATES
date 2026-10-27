# Add GATES to Better Auth

Add GATES to a new Better Auth application without replacing its passwords,
sessions or verification links. This guide uses Better Auth **1.7.7**, PostgreSQL
and GATES' online ownership backend.

After setup, signup screening happens on the server. A canonical email claim is
created only after Better Auth proves ownership. A second verified account cannot
claim the same canonical email within your tenant.

If your application already has users, start with [existing-user migration](../migration.md).
Do not put live accounts behind the access check before their ownership records
and exact delivery addresses are ready.

## Before you start

- Use Node.js 22 or newer and an ESM application.
- Follow [installation](../installation.md) to obtain the current GATES artifact.
  The package name is `@irondome-dev/gate`; the product name is GATES.
- Install the pinned Better Auth release and your PostgreSQL driver:

```sh
npm install --save-exact better-auth@1.7.7 pg@8.23.1
```

- Provide a server-side IronDome API key, a Better Auth secret, and your existing
  email sender. Never put either secret in a browser bundle.
- Choose one stable tenant ID in server configuration. Do not accept it from a
  signup form. This guide uses one tenant per application.

The initial path is verified email/password authentication. Additional providers
and plugins have separate compatibility requirements; finish this path before
adding them.

## 1. Prepare the private database schema

Follow [database setup](../database.md) to create a trusted schema, restrict its
roles and apply GATES migrations **001, 002, 003, 005 and 006**, in that order.
Migration 003 stores durable Better Auth verification bindings; 006 enables the
online backend.

Configure Better Auth's PostgreSQL pool with `trusted_auth` as its search path.
The GATES stores explicitly use that schema, while Better Auth's own tables and
migration runner use the pool's search path. All must resolve to the same schema.
Use finite connection, query, statement and lock timeouts. Keep the schema name a
server-controlled constant.

Better Auth also needs its own tables, including GATES' private
`gateDeliveryEmail` user field. Generate these from the **final** integration
options in the next step, not from a separate minimal Better Auth configuration.

## 2. Run the local starter

The [executable Node server](../../../../examples/docs/better-auth-server.mjs)
provides `/api/auth/*` and a live-checked `GET /api/protected` route. It does not
need a TypeScript loader. Run these commands from the repository root after
[installation](../installation.md) and the GATES migrations above:

```sh
cp examples/docs/.env.example examples/docs/.env
chmod 600 examples/docs/.env
```

Edit the file before continuing. Set the restricted runtime `DATABASE_URL`, the
schema-owner `MIGRATION_DATABASE_URL`, your IronDome key, a stable tenant ID and a
random Better Auth secret. Generate a secret locally with:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Keep `BETTER_AUTH_URL=http://127.0.0.1:3000/api/auth` for this starter. Both database
pools explicitly select `trusted_auth,pg_catalog`; the migration command uses only
the migration URL and the server uses only the runtime URL.

Apply Better Auth's own tables, then apply the runtime grants from
[database setup](../database.md#restrict-access) **after both sets of migrations**:

```sh
node --env-file=examples/docs/.env examples/docs/better-auth-server.mjs migrate
```

This command applies the final integration schema and rejects changes marked
unsafe. It is for a new database, not an unattended production upgrade. After
reviewing and applying the runtime grants, start the server:

```sh
node --env-file=examples/docs/.env examples/docs/better-auth-server.mjs start
```

The server binds only to `127.0.0.1` and refuses `NODE_ENV=production`. Instead of
sending email, it writes messages into a new private temporary directory printed
at startup. The directory is accessible only to your OS user; each message file
has mode `0600`. Open a captured JSON file locally and follow its verification
URL. Never upload these files or put their URLs in logs. Delete the directory when
testing is complete. This is development mail capture, not production delivery.

Without a session, the protected route must deny access:

```sh
curl -i http://127.0.0.1:3000/api/protected
```

Expected: `401` and `{"allowed":false}`. For a local smoke test, replace the
address below with an inbox you control and choose a development-only password:

```sh
curl -i http://127.0.0.1:3000/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://127.0.0.1:3000' \
  --data '{"name":"Test user","email":"you@example.com","password":"local-test-password-123"}'
```

Open the newly captured message locally and visit its verification URL. Then sign
in with the same address and password. The cookie jar is sensitive, so restrict
its permissions before writing it:

```sh
umask 077
COOKIE_JAR=$(mktemp)
curl -i -c "$COOKIE_JAR" \
  http://127.0.0.1:3000/api/auth/sign-in/email \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://127.0.0.1:3000' \
  --data '{"email":"you@example.com","password":"local-test-password-123"}'
curl -i -b "$COOKIE_JAR" http://127.0.0.1:3000/api/protected
rm "$COOKIE_JAR"
```

After successful verification and sign-in, the protected route returns `200` and
`{"allowed":true}`. Keep these commands on a private development machine; do not
use production passwords in shell commands. Signup screening calls the real
IronDome API and uses your API quota; simply starting the server does not perform
an email check. Complete the lifecycle checklist below before production.

## 3. Integrate with your application

For a framework integration or production mail sender, use the typed
[Better Auth setup module](../../../../examples/docs/better-auth.ts)
in this repository as your `better-auth.ts` module. It exports
`configureBetterAuthApplication`, which accepts your PostgreSQL pool and email
callback, constructs the online engine and durable proof store, and returns
migration, startup and maintenance functions.

Connect it to your application's existing services:

```ts
import { configureBetterAuthApplication } from './better-auth.js';

const application = configureBetterAuthApplication({
  pool,
  tenantId: 'my-application',
  baseURL: 'https://app.example.com/api/auth',
  secret: config.betterAuthSecret,
  ironDomeApiKey: config.ironDomeApiKey,
  async sendVerificationEmail({ user, url }) {
    await mailer.send({
      to: user.email,
      subject: 'Verify your email address',
      text: `Verify your email address: ${url}`,
    });
  },
});
```

Here `pool`, `config` and `mailer` are your host application's services, not exports
from GATES. The callback must resolve only after your sender accepts the message;
propagate delivery failures rather than ignoring them. Send to `user.email` exactly
as supplied. Do not send to a canonicalized address, log the verification URL or
place the token in analytics events.

During the reviewed schema deployment, run:

```ts
await application.migrateAuthSchema();
```

This applies Better Auth's schema migration using the integration options and
refuses migrations marked unsafe. Run schema changes as a deployment step with
appropriate database privileges, not on every request or independently in every
replica. Apply runtime grants after the Better Auth tables exist as well as the
GATES tables. Use the same schema/configuration when starting the runtime with its
restricted database role.

Start the application after both sets of migrations complete:

```ts
const bound = await application.start();
```

Startup loads or initializes the tenant's canonical policy. For a new tenant the
built-in policy is used. Existing tenant policy changes require the
[migration workflow](../migration.md), not a changed environment variable.

## 4. Mount only the bound handler

In a Fetch-compatible framework, route `/api/auth/*` to `bound.handler(request)`.
For Node HTTP servers, the example exposes `bound.nodeHandler`, created with
Better Auth's official `toNodeHandler`:

```ts
import { createServer } from 'node:http';

const server = createServer((request, response) => {
  void bound.nodeHandler(request, response).catch(() => {
    if (!response.headersSent) response.writeHead(503);
    response.end();
  });
});
server.listen(3000, '127.0.0.1');
```

This minimal server sends all routes to the auth handler. An application with
other routes should mount it only under `/api/auth/*`. Your reverse proxy must
preserve the intended origin and cookie behavior. Do not expose a second route
using raw `auth.handler`, replace the returned safeguard options, disable CSRF or
origin checks, or bypass the bound handler for authentication operations.

## 5. Check live ownership before granting access

Use `bound.getActiveSession` in protected server routes, before provisioning a
resource, granting a trial or accessing application data:

```ts
const session = await bound.getActiveSession(request.headers);
if (!session) return new Response('Unauthorized', { status: 401 });

return Response.json({ allowed: true });
```

The helper returns `null` when no session exists. Invalid ownership and unavailable
storage throw a denial or availability error. Route those errors through your
server's error boundary; do not catch them and fall back to a raw or cached
Better Auth session. A successful check does not replace your application's own
resource permissions.

The browser can continue using Better Auth's normal signup, sign-in,
`changeEmail` and deletion calls. GATES does not need a client-side email checker
to enforce these rules.

## 6. Verify the complete lifecycle

Use accounts and inboxes you control in a test environment:

| Test | Expected result |
| --- | --- |
| Sign up, before opening the verification link | No canonical ownership claim and no protected access. |
| Open the valid link, then sign in | The verified user owns its canonical address and the live session check succeeds. |
| Register another verified account with an alias of that address | The new user cannot take the existing canonical claim. No account is merged or logged in by matching email alone. |
| Submit an address detected as disposable | Screening prevents verification delivery and active ownership. |
| Request an email change from a fresh session | The old address remains active until the new address is verified. A conflicting target does not replace it. |
| Delete the account | Ownership is terminally revoked before provider cleanup. An old session cannot pass the live check. |

Better Auth may return a generic successful signup response even when a mail
callback fails. A pending user row can remain, but that response does not mean
verification mail was sent, a claim was granted or application access is allowed.
Offer a rate-limited resend path and inspect the protected access result, not just
the signup HTTP status.

## Maintain verification records and recover deletion

Schedule `application.deleteExpiredProofs()` in your normal trusted maintenance
job. Proof records contain exact delivery addresses and token fingerprints; apply
your retention and backup policies to them. Never log raw verification tokens.

If deletion revokes ownership but provider cleanup fails, retry the authenticated
deletion while its provider credentials remain usable. If partial cleanup has
already removed those credentials, a trusted operator/job may call
`bound.resumeDeletion({ userId })`. It requires the user to be terminally revoked.
Never expose that function as an unauthenticated endpoint or reuse the deleted
stable user ID.

## Supported configuration and next steps

The adapter is pinned to Better Auth 1.7.7. It owns the security-sensitive auth
options and rejects unsupported overrides. Account linking, secondary session
storage, background delivery handlers and arbitrary additional plugins are outside
this setup. OTP, magic-link and passkey verification alternatives are not qualified
by this guide.

For OAuth/OIDC, explicitly trust only providers whose verified-email assertion
establishes ownership. The adapter supports a constrained Generic OAuth setup;
built-in social providers need their own qualification. Do not assume enabling an
arbitrary provider makes its email claim trustworthy.

Read [deployment requirements](../deployment.md) before production and
[custom canonical rules](../email-matching.md) before changing normalization.
Provider references: [Better Auth Node integration](https://better-auth.com/docs/integrations/node),
[database configuration](https://better-auth.com/docs/concepts/database), and
[email/password authentication](https://better-auth.com/docs/authentication/email-password).
GATES' pinned adapter contract takes precedence over examples for newer Better Auth
versions.
