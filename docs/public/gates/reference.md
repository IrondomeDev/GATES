# GATES API reference

The public package is `@irondome-dev/gate`. The brand name is GATES; imports retain the package identifier. The prepared 0.3.0 release uses Node.js 22+ and ESM. See [installation](installation.md) for its current availability.

## Recommended engine

Import `createOnlinePostgresGate` from `@irondome-dev/gate/online/postgres`. It accepts a `pg.Pool`-compatible pool and server-owned configuration. Pass the resulting engine to your provider adapter.

| Method | Purpose and trust boundary |
| --- | --- |
| `screenSignup({ tenantId, email, signal? })` | Validate and screen an address. Does not claim ownership. |
| `claimVerified({ tenantId, userId, email, signal? })` | Re-screen and claim after the provider proves control of the exact address. Server-only. |
| `assertActive({ tenantId, userId, email, signal? })` | Check active ownership for trusted current provider state. Does not validate a JWT itself. |
| `getOwnership({ tenantId, userId, signal? })` | Read active, unclaimed or terminally revoked ownership state. |
| `changeVerifiedEmail({ tenantId, userId, email, expectedRevision, signal? })` | Replace verified ownership at the captured revision. Provider adapters coordinate this with provider state. |
| `revokeUser({ tenantId, userId, signal? })` | Terminally revoke the stable user ID. Retrying does not restore it. |
| `prepareEmail({ tenantId, email, policyVersion?, signal? })` | Prepare using the tenant's policy, including a historical policy when valid. Does not screen. |
| `getEmailPolicy(tenantId)` | Load the active policy; also initializes a new tenant's policy state. |

Use adapter workflows instead of exposing these methods as public HTTP endpoints. `tenantId` and `userId` come from trusted server context, never an arbitrary request field.

### Online PostgreSQL options

| Option | Default | Meaning |
| --- | --- | --- |
| `schema` | `public` | Set an explicit private schema in deployments. |
| `screening` | Required | A `screen(email, signal?)` implementation; normally `createIronDomeClient`. |
| `canonicalRules` / `emailPolicy` | Built-in policy | Mutually exclusive initial policy configuration. Existing tenants need migration. |
| `maxCachedPolicies` | 64 | Immutable policy configurations cached per process; range 2–1,024. Not an address cache. |
| `lockTimeoutMs` | 2,000 | Transaction lock timeout; range 50–10,000. |
| `statementTimeoutMs` | 5,000 | Statement timeout; range 100–60,000. |
| `exclusiveWaitMs` | 5,000 | Administrative tenant-lock wait budget; range 1–5,000. |

### Online migration methods

`engine.migration` exposes `begin`, `backfill`, `status`, `activate`, `abort` and `cleanup`. Persist the epoch returned by `begin`; supply it when resuming the job. Batch size defaults to 100 and is bounded to 1–1,000. Exact counts are opt-in with `includeCounts: true`.

Follow the [migration runbook](migration.md), not an ad hoc loop inside a public request handler. `abort` abandons a pending epoch; it is not a rollback of an already active policy.

## IronDome client options

Import `createIronDomeClient` from the package root.

| Option | Default | Meaning |
| --- | --- | --- |
| `apiKey` | Required | Server-side API credential. |
| `timeoutMs` | 3,000 | Covers response headers and body. |
| `maxInFlight` | 64 | Excess calls fail immediately instead of joining an unbounded queue. |
| `fetch` | Runtime fetch | Trusted compatible transport, normally omitted. It must honor cancellation. |

The client screens the original delivery address. It does not use an allow cache or automatically retry requests. The engine maps transport failures to sanitized GATES errors.

## Error handling

`GateError` exposes `code` and `retryable`. Its message contains no submitted address or upstream body. `retryable` describes the failure, not permission to retry an expired or no-longer-authorized operation.

| Code | Meaning | Application action |
| --- | --- | --- |
| `invalid_email` | Unsupported or malformed address. | Ask for a valid address. |
| `invalid_context` | Invalid trusted tenant/user context. | Fix server configuration or mapping. |
| `screening_blocked` | Screening did not allow the address. | Do not proceed with the protected workflow. |
| `screening_unavailable` | No usable screening result. | Deny temporarily; investigate timeout, quota or transport. |
| `identity_conflict` | Another user owns the canonical key. | Offer normal login/recovery without revealing the owner. |
| `identity_revoked` | Stable user ID is terminally revoked. | Deny; do not reclaim that ID. |
| `stale_revision` | Operation no longer matches current ownership. | Reconcile the original operation, not a fabricated revision. |
| `ownership_required` | Current verified ownership is absent or mismatched. | Deny access and inspect the provider workflow. |
| `storage_unavailable` | Storage could not establish a valid result. | Deny temporarily; inspect bounded server-side diagnostics. |
| `policy_mismatch` | Runtime and stored policy cannot be reconciled. | Follow migration/rollout recovery. |
| `cancelled` | Operation was cancelled. | Stop further work; an already-started write may have committed. |

Provider adapters map errors to their own fixed responses. Do not replace those responses with raw database or provider exceptions.

## Other exports

- `createEmailPolicy`, `prepareEmail`, `DEFAULT_EMAIL_POLICY` and `POLICY_VERSION`: [email policy](email-matching.md).
- `dryRunBackfill` and `applyBackfill`: supervised fixed-policy adoption, covered in [migration](migration.md).
- `createGate`, `createLifecycleGate` and `/postgres`: fixed-policy primitives retained for custom integrations. The current public quickstarts use the online engine.
- `/better-auth`, `/better-auth/postgres`, `/auth0`, `/supabase`, `/provider-lifecycle` and `/provider-lifecycle/postgres`: provider integration modules.
- `/policy-migration/postgres`: maintenance-window migration from the current built-in policy to additive custom rules. It is not the online engine.
- `/migrations/001_identity.sql` through `/migrations/006_online_policy.sql`: versioned SQL exports.

The installed TypeScript declarations are the exact signature reference. Do not deep-import internal `dist/` paths.
