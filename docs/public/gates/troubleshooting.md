# Troubleshoot GATES

Start with the sanitized error code and the workflow stage. Do not disable a hook, rewrite a canonical key or grant access to test whether the problem disappears.

## Signup succeeds but no verification email arrives

Some Better Auth signup paths return a generic response even when the mail callback fails. Check whether GATES blocked screening, screening was unavailable, or the mail provider failed. The pending provider row does not own a canonical identity and must not receive benefits. Recover through a rate-limited resend after fixing the cause.

## A verified user receives `ownership_required`

Confirm that the provider adapter completed the claim, that the configured tenant/schema are correct, and that the protected route reads fresh provider state. Existing users may not have been backfilled. Do not call `claimVerified` merely because the browser submitted an email or a JWT contains an old verified-email claim.

If the provider's email changed outside the lifecycle workflow, deny access until the authorized operation is reconciled. A new provider email alone does not authorize replacing an existing ownership claim.

## Supabase confirmation rolls back or never issues a session

Check the confirmation flow first. The strict Custom Access Token hook reads current provider state through the Admin API; some confirmation transactions have not committed when the hook runs. Use the documented PKCE confirmation and subsequent code-exchange flow. Do not substitute implicit confirmation or token-hash `verifyOtp` without qualifying that exact provider behavior. See the [Supabase quickstart](quickstart/supabase.md).

## Signup or login reports `screening_unavailable`

Check server credential configuration, quota, transport, timeouts and in-flight capacity. Keep the distinction from `screening_blocked` in internal metrics. Do not treat an API outage as an allowed result. The client does not automatically retry billable requests.

## A change reports `stale_revision`

Another verified change, deletion or incompatible operation may have advanced the state. Read the current provider record and stored ownership through trusted server code. Retry the original still-valid proof only when the adapter supports reconciliation. Do not fetch the newest revision and attach it to an older proof.

## Online migration is `blocked`

Inspect the private operator report for missing verified source addresses, invalid target addresses or collisions. Active-policy traffic can continue while these are resolved. Resolve through verified changes or revocation, then resume bounded backfill. Never select a collision winner automatically.

An earlier canonical key cannot restore stripped dots, tags or case. Supply a current verified provider source or require renewed verification.

## Deletion failed after GATES revocation

Keep the stable user revoked. Retry provider cleanup through the documented server-only recovery path. Do not recreate the GATES claim because a provider API was unavailable. Keep this job's status visible to operators until cleanup completes.

## A revoked account still reaches application data

Find the path that skipped the live GATES check. Common examples are raw Better Auth session reads, locally decoded JWTs, background workers and directly exposed Data API tables. Fix those authorization boundaries; removing an existing provider session alone does not revoke every previously issued token.

## TypeScript cannot find a module or SQL export

Use Node.js 22+, ESM and an installed package artifact. Confirm that the application imports `@irondome-dev/gate`, not the old `@irondome/gate` name or private `dist/` paths. Check the package version and its exports before changing bundler resolution options.
