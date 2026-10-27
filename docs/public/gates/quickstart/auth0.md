# Connect GATES to Auth0

Use GATES to screen new email addresses, reject verified aliases that already belong to another account, and check current account ownership on protected server requests. Auth0 remains responsible for login, email verification and tokens.

This guide uses the PostgreSQL online backend. Start with a development Auth0 tenant and an empty GATES namespace. For an application with existing users, follow [migration](../migration.md) before enabling enforcement.

## What runs where

There are two enforcement points:

1. Auth0 Actions call the GATES adapter before registration and after authentication.
2. Your resource server validates the access token, then checks live GATES ownership before granting access.

An Action cannot revoke an access token that has already been issued. The resource-server check closes that gap. A canonical match never authenticates a user or links two Auth0 accounts.

GATES does not install Actions, create an Auth0 Management API client, or supply a production RPC service. Decide how the Actions reach the trusted engine before beginning. They can use a deployment with approved database connectivity, or an authenticated backend integration you operate. Do not expose raw `claimVerified` methods to browsers. The repository's hosted-test transport is a qualification fixture, not a production service.

## Prepare the backend

Follow [installation](../installation.md) for the reviewed package artifact and [database setup](../database.md) for the private schema. For this configuration, apply migrations **001, 002, 004, 005 and 006**. Migration 004 stores pending provider operations; 006 enables the online backend.

Configure these server-owned values:

| Value | Source |
| --- | --- |
| Tenant ID | Your fixed application namespace; not an HTTP parameter |
| Auth0 issuer | Your tenant's HTTPS origin |
| Trusted connection IDs | The exact Auth0 connections whose email-verification semantics you accept |
| IronDome API key | A server secret |
| Management API token provider | Your server's client with permission to read users by ID |
| PostgreSQL pool | A restricted server role in the private schema |

Keep the connection list narrow. Adding a social connection means trusting its verified-email result; it is not simply enabling another UI button. Hosted social identity providers need their own qualification.

The complete typed initialization example is [auth0.ts](../../../../examples/docs/auth0.ts). It constructs the online engine, durable operation store, lifecycle coordinator and adapter. You provide three host capabilities:

- `getManagementAccessToken`: obtains an Auth0 Management API token and honors the supplied abort signal. Token caching is allowed; user-profile caching is not used by this example.
- `verifyAccessToken`: validates signature, issuer, audience and expiry and returns the authenticated subject.
- `deleteSameGeneration`: checks the expected immutable provider generation, coordinates competing administrative writers, and deletes that exact principal. A read followed by an uncoordinated delete is insufficient if your administration can replace or reuse IDs.

The example caps each provider lookup and deletion callback at a four-second abort signal, combined with any caller signal. Your token and deletion callbacks must honor that signal and use finite request deadlines; passing a signal cannot stop a callback that ignores it. The JWT verifier must also bound any remote key fetch.

The example performs fresh user reads itself. It expects the Management API record's `user_id`, `email`, `email_verified` and `created_at`, not user-controlled metadata.

Construct the integration once per server instance. Use finite database and HTTP deadlines, and enough pool connections for the lifecycle coordinator to hold its operation lock while the engine performs database work. See [deployment](../deployment.md).

## Bind both Actions

Configure the adapter's `onExecutePreUserRegistration` on **Pre User Registration**, and `onExecutePostLogin` on **Login / Post Login**. Deploy each Action and add it to its corresponding flow. Merely saving an Action does not bind it.

Auth0 entry files use CommonJS exports; GATES is ESM. A bundled Action entry or an asynchronous initializer must bridge those formats. This is the forwarding code after your trusted initializer has created the integration:

```js
exports.onExecutePreUserRegistration = async (event, api) => {
  const integration = await getIntegration(event.secrets);
  await integration.adapter.onExecutePreUserRegistration(event, api);
};

exports.onExecutePostLogin = async (event, api) => {
  const integration = await getIntegration(event.secrets);
  await integration.adapter.onExecutePostLogin(event, api);
};
```

`getIntegration` is host deployment glue, not a GATES export. It must load the reviewed ESM artifact, configure its trusted dependencies, and reuse the initialized integration. Do not copy this fragment alone and assume an Action is deployed. Before npm publication, an Action cannot resolve GATES from npm; use your reviewed bundle according to the [installation status](../installation.md).

If the engine is remote, authenticate the Action-to-backend transport, restrict operations and select the tenant on the backend. An online engine proxy must preserve `prepareEmail`, ownership methods, cancellation and error semantics. A client-submitted event body is not an authenticated Auth0 event.

The triggers have different jobs:

- **Pre-registration** screens the submitted address. There is no mailbox proof yet, so it does not reserve ownership. Auth0 runs this trigger for database/passwordless registration, not every social signup.
- **Post-login** requires a trusted connection and a verified email. The first verified admission claims ownership after screening; an existing subject must retain valid ownership. A pending authorized change may complete after fresh provider verification. Untracked changes, conflicts and revoked identities deny token issuance.

These behaviors follow Auth0's [Pre User Registration](https://auth0.com/docs/customize/actions/explore-triggers/pre-user-registration) and [Post Login](https://auth0.com/docs/customize/actions/explore-triggers/post-login) contracts. Keep the adapter's deadline below your Action budget; its default is 10 seconds and maximum is 15 seconds.

## Protect server operations

Use the typed example's `requireActiveUser` after extracting the bearer token. It calls your JWT verifier and then the adapter's live check:

```ts
const principal = await integration.requireActiveUser(accessToken);
await provisionTrialForAuthenticatedUser(principal.sub);
```

The provisioning function is your application code. Authorize the requested operation as well as checking identity. Reject failures; do not fall back to a decoded token, cached allow result or token email claim. Return a generic error to clients and record only sanitized failure codes.

The live check reads the current Auth0 profile and durable GATES ownership. Plan for Management API rate limits and latency. Revocation affects checks after it commits; it does not cancel application work already authorized.

## Email changes and deletion

Direct lifecycle calls do not inherit the adapter deadline. Supply a fresh finite signal for each operation, as below; combine it with the request signal when available. Database connection, query and lock timeouts must also be finite because cancellation is cooperative.

Use one server-owned workflow for each lifecycle operation. Do not let an independent admin route bypass it.

For an email change:

1. Authenticate the current user and authorize the change, including any reauthentication your application requires.
2. Call `integration.lifecycle.beginEmailChange({ userId, email, signal: AbortSignal.timeout(10_000) })` with the exact proposed delivery address. Persist the returned operation ID with your workflow.
3. Run the provider-native verification flow for that exact address. Never set `email_verified: true` merely to make GATES accept it.
4. After the fresh provider profile reports the verified target, call `completeEmailChange({ userId, operationId, signal: AbortSignal.timeout(10_000) })`, or let Post Login complete the previously staged operation.

The old claim remains while verification is pending. If the provider changes first but GATES cannot complete the swap, access stays denied until reconciliation. Do not release a claim, merge accounts, or invent a new revision to bypass a conflict.

For deletion, authorize the request and call `integration.lifecycle.deleteAccount({ userId, signal: AbortSignal.timeout(10_000) })`. It records the intent and revokes GATES before invoking your provider deletion callback. A provider failure does not restore ownership. Retry through `resumeDeletion({ userId, signal: AbortSignal.timeout(10_000) })` from an authorized maintenance job. Never reuse the stable provider subject.

Schedule `integration.operations.deleteExpiredChanges()` to remove expired change records. Preserve deletion intents and terminal revocation records. See [deployment and recovery](../deployment.md).

## Verify before enabling real signups

Use accounts and inboxes you control in the development tenant:

| Test | Expected result |
| --- | --- |
| Known disposable signup | Registration screening denies |
| Allowed but unverified account | No verified GATES claim or protected access |
| Verify and log in with a new address | Active claim; protected check succeeds |
| Verify an alias of an existing account | Conflict; no second active claim |
| Change email through the staged workflow | Old claim retained while pending; verified completion advances ownership |
| Change the provider email outside that workflow | No silent ownership transfer |
| Delete, then reuse an old access token | Live protected check denies |
| Fail the provider deletion once | Revocation stays effective; authorized retry finishes cleanup |
| Make screening, storage or provider reads unavailable | No fail-open access |

Retest the actual Action bindings and the application's resource server, not only the adapter functions. Also test external mail delivery: captured test mail does not establish that a user's inbox will receive verification links.
