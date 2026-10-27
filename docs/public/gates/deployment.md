# Deploy and operate GATES

A working signup hook is only one part of the integration. Before granting data access, trial credits or provisioning, the server must check current provider state and active GATES ownership.

## Protect every access path

Use the provider adapter's live helper:

| Adapter | Protected operation check |
| --- | --- |
| Better Auth | `getActiveSession(request.headers)` from the bound integration. |
| Auth0 | Verify the token in the host, then call the adapter's `assertActive(...)` with the verified context. |
| Supabase | `assertActive(accessToken)`, backed by a live provider lookup. |

A missing session, revoked identity or unavailable check must not fall back to a cached allow. A previously issued JWT can remain cryptographically valid after an account is revoked or deleted. Apply equivalent enforcement to background jobs and directly exposed data paths, not only page navigation.

Provider proof, GATES ownership and application authorization are separate decisions. GATES does not replace your tenant-membership or resource-permission checks. An operation already authorized before revocation may still finish; coordinate cancellation where your application requires stronger semantics.

## Choose a deployment topology

The PostgreSQL engine coordinates ownership across server instances. Every instance serving a tenant must use the same supported engine and policy protocol.

The Supabase adapter's webhook replay cache is per process. Do not assume that starting several instances creates a shared replay fence. The initial supported deployment must either keep that hook handling within a single coordinated process or provide a reviewed shared ingress/replay arrangement. Process restarts also lose the in-memory replay history. Describe this limitation in your own operational review rather than treating the cache as durable storage.

Auth0 integrations need bounded access to the current provider user record. Management API limits and latency are part of your authentication capacity planning. Avoid unbounded retries or refreshing a service token per request without a controlled cache.

Direct lifecycle calls also need finite deadlines. Pass an abort signal to email-change and deletion operations, and ensure your provider HTTP and administrative deletion implementations honor it. Hook and protected-request adapter timeouts do not automatically bound separate lifecycle calls.

## Decide how failures appear to users

The shipped GATES integrations fail closed. Screening or storage failures do not grant an account claim or protected access. That protects the enforcement boundary but can delay legitimate users during an outage.

- Reject malformed input without calling the screening API.
- Distinguish a known blocked address from an unavailable screening service internally.
- Show a generic retryable failure where appropriate; do not leak another user's email or ownership record.
- Retry only the same still-authorized operation after an uncertain commit. Never invent a new revision or release the old claim to make a retry succeed.

The IronDome client has a finite request timeout and bounded in-flight calls. It does not automatically retry, because a timed-out request may already have reached the API. Size quotas for signup screening, activation and verified changes, not just initial form submissions. See [the reference](reference.md#irondome-client-options).

## Schedule maintenance

GATES does not install background jobs. Add these to your existing scheduler:

- Better Auth: `changes.deleteExpired()` removes expired proof bindings.
- Auth0/Supabase lifecycle store: `deleteExpiredChanges()` removes expired email-change operations.
- Online migrations: run bounded `migration.cleanup(...)` batches after activation or abort.
- Provider deletion: retry incomplete cleanup after terminal revocation, using the adapter's documented trusted recovery path.

Do not purge terminal revocation fences automatically or reuse stable GATES user IDs. A provider that recycles subjects needs an application-controlled, never-reused principal mapping. Account restoration is not an implicit reversal of deletion.

## Keep private identity data private

Use the schema and grants in [database setup](database.md). Keep exact delivery addresses, user IDs, pending operations and database backups access-controlled. GATES does not make your entire database safe merely by using a private schema.

Log sanitized result codes, latency and aggregate counts. Avoid raw provider bodies, driver errors, tokens, API keys or email addresses. Error codes are useful for diagnosis without turning logs into another identity store.

## Release checklist

Before directing real users through the integration:

- Test signup, blocked signup, verification, duplicate claim, email change, deletion and cleanup recovery.
- Confirm that protected requests fail after revocation even when an old token remains valid.
- Exercise screening timeout, provider lookup failure and PostgreSQL unavailability.
- Verify browser-role storage isolation and application data permissions separately.
- Validate your exact provider version and settings, including Supabase PKCE confirmation and Better Auth's supported plugin set.
- Test migrations with competing writes and unresolved collisions on a disposable copy.
- Confirm pool deadlines, request limits, API quota and alert ownership.

A successful package build does not establish these deployment properties. Keep the test environment isolated from production and do not point destructive qualification scripts at an application database.
