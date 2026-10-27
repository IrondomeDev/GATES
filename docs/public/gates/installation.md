# Install GATES

Use GATES only in trusted server code. It requires Node.js 22 or later, ESM, PostgreSQL and an IronDome API key. Keep the key and database credentials out of browser bundles.

## Install from npm

```sh
npm install irondome-gates pg
```

Use `irondome-gates@0.1.0` to pin this release explicitly. Commit your application's lockfile. The package exports its public modules, TypeScript declarations and SQL migrations.

To build a local artifact from a reviewed repository checkout:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run package:smoke
npm pack
```

In your application's directory, install the generated archive:

```sh
npm install /absolute/path/to/irondome-gates-0.1.0.tgz
npm install pg
```

Do not copy `src/` files individually or edit generated `dist/` files.

Better Auth integrations also require the qualified peer version:

```sh
npm install better-auth@1.7.7
```

Auth0 and Supabase consumers do not need Better Auth. The package bundles its exact Mail Canon, TR46 and Punycode runtime dependencies. PostgreSQL and your provider SDK remain application dependencies.

## Confirm the installed package

Run this from an ESM application:

```sh
node --input-type=module -e "import { prepareEmail } from 'irondome-gates'; console.log(prepareEmail('alex+trial@gmail.com').canonical)"
```

Expected output:

```text
alex@gmail.com
```

This check is local and makes no API call. It verifies module loading and the built-in canonicalizer, not your database, provider hooks or IronDome credentials.

## Keep secrets server-side

Store the IronDome API key in your deployment's secret store. The provider guides name the additional secrets they need. Do not put production credentials into examples, screenshots or checked-in `.env` files.

Next, [prepare PostgreSQL](database.md), then follow the quickstart for [Better Auth](quickstart/better-auth.md), [Auth0](quickstart/auth0.md) or [Supabase](quickstart/supabase.md).
