# Connect GATES to Supabase Auth

Use GATES with Supabase Auth to screen disposable email signups and enforce one active owner for each canonical email identity. Supabase still handles passwords, confirmation links and sessions. GATES stores ownership and lifecycle state in private PostgreSQL tables.

Start in a development project. This guide covers confirmed-email accounts, not anonymous or phone-only authentication. Existing accounts need the [migration workflow](../migration.md) before enforcement.

## Choose the request path first

The integration has three parts:

- **Before User Created** screens the submitted email before account creation.
- **Custom Access Token** checks the fresh confirmed provider record and claims or checks GATES ownership before a token is issued.
- **Protected server routes** perform a live provider-and-GATES check before using the session to grant access.

The two Auth Hooks are HTTP endpoints on your trusted Node server. They must be reachable by Supabase over HTTPS. Each handler authenticates the raw body with its Standard Webhooks signing secret; no browser should receive that secret or the service-role key. Supabase documents their configuration under [Auth Hooks](https://supabase.com/docs/guides/auth/auth-hooks).

For the initial deployment, route each hook to one long-lived adapter instance. Its bounded replay cache is **local to that instance**. Creating an adapter per request clears that protection; spreading deliveries over replicas does not provide shared replay detection. Multi-instance or restart-resilient replay enforcement requires coordinated delivery control outside this adapter. See [deployment](../deployment.md) before choosing a serverless or replicated topology.

## Prepare private storage

Follow [installation](../installation.md), then [database setup](../database.md). Apply migrations **001, 002, 004, 005 and 006** in a dedicated schema such as `gate_private`, using your migration role. Do not put GATES tables in Supabase's `auth` schema.

Keep the schema out of the Data API's exposed schemas and deny access to browser roles. Give only the restricted GATES server role the required table privileges. The supplied migrations do not enable RLS. That is acceptable only while the tables remain private; your application tables still need their own grants and RLS policies.

A JWT-only RLS policy does not consult GATES revocation. If a browser can access protected data directly, adding a live check to one API route does not protect that separate path. Route relevant operations through the checked backend or design equivalent enforcement for every exposed path. Follow Supabase's [Data API security](https://supabase.com/docs/guides/api/securing-your-api) guidance.

## Initialize the server integration

The complete typed example is [supabase.ts](../../../../examples/docs/supabase.ts). It creates the online engine and durable lifecycle coordinator, performs fresh Auth API reads, and routes both hooks without parsing the body first.

Provide fixed server configuration:

| Value | Purpose |
| --- | --- |
| `tenantId` | Application namespace; never read from hook metadata |
| `projectUrl` | Your hosted project's HTTPS origin |
| `serviceRoleKey` | Server-only access to the Admin API |
| `beforeUserCreatedSecret` | Signing secret for the signup hook |
| `customAccessTokenSecret` | Signing secret for the token hook |
| `ironDomeApiKey` | Server-only disposable email screening |
| `pool`, `schema` | Restricted database connection and private GATES schema |
| `deleteSameGeneration` | Your coordinated admin deletion capability |

The two hooks may have different signing secrets. The example keeps one adapter instance for each secret and reuses both across requests.

The example gives provider fetches and the deletion callback a four-second abort signal, combined with any caller signal. Your deletion callback must honor cancellation and bound each request; passing a signal cannot stop a callback that ignores it.

The supplied deletion callback must check the expected immutable provider generation and delete that exact user while coordinating other administrative writers. The example deliberately does not turn a read-then-delete race into a claimed atomic deletion. Use non-reused provider subjects and route competing administration through the same coordination boundary.

The example targets hosted Supabase's `/auth/v1` paths. A standalone GoTrue deployment has different base paths; adapt and test those explicitly.

## Enable both HTTP hooks

In the project's Auth Hooks configuration, bind:

| Supabase hook | Example server route |
| --- | --- |
| Before User Created | `/hooks/gates/before-user-created` |
| Custom Access Token | `/hooks/gates/custom-access-token` |

Configure each matching secret on the server. Forward the original request headers and raw body to `integration.handleHook(request)`. Do not call `request.json()` and recreate the request before signature verification.

The handlers return Supabase's structured error envelope. A denial can have HTTP status 200 with an `error.http_code` in the JSON body, so a reverse proxy must not replace or discard that body. The default hook deadline is four seconds. Apply finite provider and database deadlines as well, and avoid retry storms when dependencies fail.

Do not use the service-role key as the end user's bearer token. Keep the key exclusively in the trusted server's configuration.

## Use PKCE confirmation

Configure your Supabase client for the [PKCE flow](https://supabase.com/docs/guides/auth/sessions/pkce-flow), with a permitted callback URL and storage that preserves the PKCE verifier across the confirmation round trip.

The required sequence is:

1. Start signup using PKCE.
2. Follow the native confirmation link.
3. Let confirmation commit in Supabase.
4. Exchange the returned authorization code for the session using the same verifier.
5. Run the protected-route check before granting application access.

This order matters for the strict token hook. During some confirmation transactions, an external Admin API read can still see the old unconfirmed record. A code exchange after confirmation commits allows the hook to read the confirmed state. This behavior was qualified against GoTrue v2.197.0; verify it against your project's deployed version.

Do not substitute the implicit confirmation flow or a POST `verifyOtp` token-hash flow for this configuration. Do not set confirmation fields with the Admin API as a shortcut around mailbox proof.

## Check protected requests

After extracting the user's bearer token, call the example's live helper:

```ts
const user = await integration.requireActiveUser(accessToken, request.signal);
await provisionTrialForAuthenticatedUser(user.id);
```

The provisioning function is your application code and still needs operation-specific authorization. The helper calls Supabase's authenticated `/user` endpoint and then checks durable GATES ownership. A decoded JWT, `getSession()` result, metadata field or cached allow decision is not a replacement.

The token hook preserves the provider's claims; it does not invent a permanent `gate_allowed` claim. Already-issued JWTs can outlive revocation or provider deletion, which is why the live check belongs on protected paths.

## Keep changes and deletion in one workflow

Direct lifecycle calls do not inherit the adapter deadline. Supply a fresh finite signal for each operation, as below; combine it with the request signal when available. Database connection, query and lock timeouts must also be finite because cancellation is cooperative.

For an email change:

1. Authenticate and authorize the current user, with reauthentication when required by your application.
2. Call `integration.lifecycle.beginEmailChange({ userId, email, signal: AbortSignal.timeout(10_000) })` before starting the provider change. Keep its returned operation ID.
3. Start Supabase's native secure email change using PKCE. Keep secure email change enabled and complete the required confirmations.
4. Exchange the code after confirmation commits. The token hook can complete the stored pending operation, or your server can call `completeEmailChange({ userId, operationId, signal: AbortSignal.timeout(10_000) })` after proof.

The old address remains usable only while it is still the provider's current confirmed address and owns its GATES claim. A changed provider address without the captured operation does not silently replace ownership. A conflict or partial failure can require supervised recovery; never resolve it by editing canonical keys.

For account deletion, call `integration.lifecycle.deleteAccount({ userId, signal: AbortSignal.timeout(10_000) })` from an authorized server route. GATES revokes first, then your callback deletes the provider user. A failed delete leaves access denied; a trusted job can call `resumeDeletion({ userId, signal: AbortSignal.timeout(10_000) })` to finish it. Do not undo revocation to make a retry succeed.

Run `integration.operations.deleteExpiredChanges()` on a maintenance schedule. Keep deletion intents for recovery. See the [deployment checklist](../deployment.md) for pool sizing, deadlines, data retention and cleanup.

## Verify the complete flow

Use controlled test inboxes and a disposable development database:

| Test | Expected result |
| --- | --- |
| Known disposable signup | Signup hook denies before user creation |
| Allowed signup before confirmation | No active ownership or protected access |
| PKCE confirmation and code exchange | Verified user claims ownership and can pass the live check |
| Confirm an alias of an existing owner | No second active claim or application access |
| Secure email change | Old access while pending; verified completion changes ownership |
| Untracked provider email change | Denial rather than implicit ownership transfer |
| Delete, then reuse an old token | Live check denies |
| Re-send one signed hook delivery ID | Rejected by the same live adapter instance |
| Use an expired signature or modified body | Rejected |
| Lose screening, storage or provider access | Failure remains closed |

Also verify that `anon` and `authenticated` cannot read GATES tables, the private schema is not exposed through REST, and verification mail reaches the real inbox. Unit tests alone do not validate hook routing, project settings or external delivery.
