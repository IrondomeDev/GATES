# Install GATES

Use GATES only in trusted server code. It requires Node.js 22 or later, ESM, PostgreSQL and an IronDome API key. Keep the key and database credentials out of browser bundles.

## Install the current release candidate

`@irondome-dev/gate` 0.3.0 is prepared but not yet published. Build a package from the reviewed repository checkout or use the artifact supplied by the project maintainer:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run package:smoke
npm pack
```

The first commands run inside the GATES checkout. `npm pack` produces `irondome-dev-gate-0.3.0.tgz`; it does not publish anything. In your application's directory, install that file:

```sh
npm install /absolute/path/to/irondome-dev-gate-0.3.0.tgz
npm install pg
```

Use your application's normal lockfile and review the artifact before distributing it internally. Do not copy `src/` files individually or edit generated `dist/` files. The package exports its public modules, TypeScript declarations and SQL migrations.

Better Auth integrations also require the qualified peer version:

```sh
npm install better-auth@1.7.7
```

Auth0 and Supabase consumers do not need Better Auth. The package bundles its exact Mail Canon, TR46 and Punycode runtime dependencies. PostgreSQL and your provider SDK remain application dependencies.

## Confirm the installed package

Run this from an ESM application:

```sh
node --input-type=module -e "import { prepareEmail } from '@irondome-dev/gate'; console.log(prepareEmail('alex+trial@gmail.com').canonical)"
```

Expected output:

```text
alex@gmail.com
```

This check is local and makes no API call. It verifies module loading and the built-in canonicalizer, not your database, provider hooks or IronDome credentials.

## Keep secrets server-side

Store the IronDome API key in your deployment's secret store. The provider guides name the additional secrets they need. Do not put production credentials into examples, screenshots or checked-in `.env` files.

Next, [prepare PostgreSQL](database.md), then follow the quickstart for [Better Auth](quickstart/better-auth.md), [Auth0](quickstart/auth0.md) or [Supabase](quickstart/supabase.md).
