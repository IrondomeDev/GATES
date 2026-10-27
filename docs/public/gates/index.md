# GATES documentation

GATES adds disposable email screening and verified, alias-aware email ownership to your existing authentication system. IronDome screens the submitted address. Mail Canon derives the matching key. PostgreSQL records which verified user owns that key within your application tenant.

Your auth provider still owns passwords, sessions and email verification. A matching email key never signs a user in, merges accounts or proves that two accounts belong to the same person.

## Start with your provider

| Provider | Start here | Integration boundary |
| --- | --- | --- |
| Better Auth 1.7.7 | [Better Auth quickstart](quickstart/better-auth.md) | A server plugin, durable verification bindings and a bound session helper. |
| Auth0 | [Auth0 quickstart](quickstart/auth0.md) | Actions, a trusted backend and fresh provider checks. |
| Supabase Auth | [Supabase quickstart](quickstart/supabase.md) | Signed Auth Hooks, PKCE confirmation and live protected-route checks. |

The guides target the prepared `@irondome-dev/gate` 0.3.0 package, Node.js 22+ and ESM. The package is not yet published to npm. Follow [installation](installation.md) to use a reviewed local artifact; do not assume a registry install is available.

For a new application, follow your provider quickstart from an empty GATES registry. For an application with users, read [migration](migration.md) before enabling enforcement. Existing verified accounts need reviewed ownership records; installing a hook alone does not backfill them.

## Understand the flow

1. A signup submits its exact email address. GATES validates and screens it before the integration proceeds to its verification boundary.
2. The provider establishes ownership of that address. GATES then claims its canonical key for the stable user ID. A competing claim is rejected atomically.
3. Protected server operations check current provider state and live GATES ownership. They do not rely only on a previously issued token.
4. Verified email changes use a captured ownership revision. Deletion revokes the stable user ID before provider cleanup.

Unverified signups do not reserve canonical identities. A provider can still retain a pending account after an interrupted signup; that pending record is not permission to grant access or trial benefits.

## Configure and operate

- [Database setup](database.md): migrations, server roles and private storage.
- [Email matching](email-matching.md): delivery addresses, canonical keys and custom rules.
- [Migration](migration.md): existing-user adoption and online policy changes are different operations.
- [Deployment](deployment.md): protected routes, multiple instances, failures and cleanup.
- [API reference](reference.md): engine methods, configuration and errors.
- [Troubleshooting](troubleshooting.md): diagnose a failed signup or denied session without bypassing enforcement.

GATES addresses email-based signup abuse. It does not establish a person's identity or prevent every form of trial abuse. Read the provider's supported configuration before adding other authentication plugins or login methods.
