# GATES integration examples

These examples are maintained with the public documentation. The Better Auth starter is an executable localhost development server. The TypeScript modules are integration building blocks, not deployable applications or hosted RPC services. Supply your application's PostgreSQL pool, secrets, mail sender, JWT verifier and coordinated provider administration as indicated by each interface.

| File | Companion guide | Host responsibilities |
| --- | --- | --- |
| `better-auth-server.mjs` | [Better Auth](../../docs/public/gates/quickstart/better-auth.md#2-run-the-local-starter) | Development PostgreSQL roles and migrations, local secrets and private mail capture. |
| `better-auth.ts` | [Better Auth](../../docs/public/gates/quickstart/better-auth.md) | A trusted pool, mail sender, deployment migrations and HTTP routing. |
| `auth0.ts` | [Auth0](../../docs/public/gates/quickstart/auth0.md) | Action deployment/transport, Management API token acquisition, JWT verification and generation-safe deletion. |
| `supabase.ts` | [Supabase](../../docs/public/gates/quickstart/supabase.md) | HTTPS hook hosting, PKCE client/callback, private storage and coordinated deletion. |

No example embeds credentials or provisions provider resources. The TypeScript factories do not run hosted mutations when imported. The executable starter runs only when explicitly invoked: `migrate` changes Better Auth tables and `start` initializes the tenant and listens locally. Construct the factory once per application instance; do not create webhook replay caches per request. Do not expose raw engine or administrative lifecycle methods directly to browsers.

## Run the Better Auth development server

Follow the [quickstart](../../docs/public/gates/quickstart/better-auth.md) to install
the package, prepare the private schema and apply GATES migrations. From the
repository root:

```sh
cp examples/docs/.env.example examples/docs/.env
chmod 600 examples/docs/.env
```

Replace every placeholder, then run:

```sh
node --env-file=examples/docs/.env examples/docs/better-auth-server.mjs migrate
```

Apply runtime grants after these Better Auth migrations, then:

```sh
node --env-file=examples/docs/.env examples/docs/better-auth-server.mjs start
```

This server is localhost-only and rejects production mode. Its private temporary
mail files contain verification URLs: open them only locally and remove the
printed directory after testing. Replace this capture callback with your real
sender when integrating the typed module into an application.

## Check the examples

From the repository root:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run build:package
node node_modules/typescript/bin/tsc -p examples/docs/tsconfig.json
node tools/check-public-docs.mjs
```

The TypeScript check verifies the examples against the package's actual public declarations. The documentation check validates the explicit page/example manifest, links and formatting and runs local canonicalization assertions. Neither proves your provider deployment, PostgreSQL grants or external email delivery. Complete the acceptance checklist in the relevant guide before using the integration with real accounts.

Node.js 22+ and ESM are required. Better Auth's supported peer is pinned to 1.7.7. Install `irondome-gates` from npm; [installation](../../docs/public/gates/installation.md) also describes building a local artifact.
