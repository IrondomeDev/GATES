# Contributing to GATES

Use Node.js 22 or newer and npm. Install the pinned dependencies without dependency
lifecycle scripts:

```sh
npm ci --ignore-scripts
npm test
npm run docs:check
npm run check:public
npm run package:smoke
```

`npm test` builds the project and runs the test suite. Database-dependent tests skip
when their prerequisites are missing. A passing run with skips is not a complete
integration qualification.

## Database and auth integration tests

Use a disposable PostgreSQL database on loopback and an official GoTrue binary.
Never use a live application database. Configure `GATE_TEST_POSTGRES_URL` and
`GATE_TEST_GOTRUE_BIN` in your local environment, then run:

```sh
npm run test:qualified
```

The qualified command requires every test to pass with zero skips. It does not
perform hosted Auth0 or Supabase configuration changes. Package consumer checks
remain a separate command.

## Change and review workflow

- Keep regression tests with the behavior they protect.
- Update the public guide and its example when a public API changes.
- Run the documentation checks, build, relevant tests and package smoke before review.
- Treat migrations and changes to canonical email policy as compatibility changes.
- Do not claim a hosted deployment was reverified unless it was run.

## Public documentation

The public documentation entrypoint is [docs/public/gates/index.md](docs/public/gates/index.md).
Its manifest is an explicit list of pages and examples intended for publication.
Keep local qualification reports, provider receipts, screenshots, environment
inventories and experimental notes outside the repository.

Tests, fixtures and repeatable contributor tools belong in the repository. Their
machine-specific output does not. The npm package includes the runtime, migrations,
public guides and examples, plus license notices; it must not include internal
reports, test source or a vendored source archive.

## Release checks and npm publication

Run from a clean checkout of the exact commit you intend to publish. Use Node.js
22 or newer and configure the disposable PostgreSQL and GoTrue prerequisites
above. Then run:

```sh
npm ci --ignore-scripts
npm run release:check
npm pack --dry-run
npm whoami
```

`release:check` checks the public tree and documentation, requires the complete
integration suite to pass with zero skips, and installs the packed artifact in
fresh consumer projects. It stops at the first failure. It does not publish, tag,
push or change hosted provider configuration. Missing integration prerequisites
are a failed release check, not permission to skip qualification.

Confirm that the npm account has publish access to the `@irondome-dev` scope and
meets npm's authentication requirements. Confirm the intended version in
`package.json` has not already been published, and review the dry-run file list.
The package uses `prepack` to build its runtime; this does **not** automatically
run `release:check`. Keep the source unchanged between checks and publication.

Only the release owner should run the following command after approving a stable
release; it publishes publicly with npm's default `latest` tag:

```sh
npm publish --access public
```

For a prerelease, choose a prerelease version and an explicit distribution tag
before running the checks instead of publishing an unqualified build as `latest`.
Never put npm tokens in repository files or command examples. After publication,
verify the registry version and update the unpublished notice and installation
guide to match the version that is actually available.

## Optional checks with external effects

`npm run test:live` uses an IronDome API key and makes billable API requests. It is
not part of the default suite. Use a test key and keep credentials out of shell
arguments, logs and commits. The online qualification
command requires explicitly configured disposable databases; inspect their
prerequisites before running them.

Do not commit `.env` files, credentials, local reports or generated package archives.
If a secret is committed, removing the file from the current tree is not sufficient:
revoke or rotate it and arrange a history review before publishing the repository.
