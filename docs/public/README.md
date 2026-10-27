# Public documentation source

`gates/manifest.json` is the explicit list of pages and example sources intended for the GATES documentation site. These files are drafts until an approved documentation release is published. The manifest's routes are planned website paths, not a claim that those URLs are live.

The website exporter must read this manifest from a reviewed immutable commit or release tag. Do not copy the entire repository, recursively publish `docs/`, or follow links to private files automatically. Include only listed files. Rewrite relative page links to their manifest routes and example links to the corresponding public source or downloadable example asset.

Keep historical test logs, customer data, credentials, raw provider responses and internal verification notes outside this public tree. A private-repository source link is not a usable public website link; the publishing step must provide accessible example assets before going live.

## Update procedure

1. Change the guide and its maintained example together.
2. Run the TypeScript example check and `node tools/check-public-docs.mjs` after building the package.
3. Test any changed provider behavior using the relevant disposable integration environment. Do not label a typecheck as an end-to-end test.
4. Review wording, failure behavior and disclosure scope. Keep code fences language-tagged and comments short and lowercase.
5. Add or remove manifest entries deliberately. Publish the same validated snapshot as the package version the guide documents.

The current source is plain Markdown so the existing IronDome docs renderer can consume it without a separate CMS. Website rendering and deployment are separate changes. Stage a reviewed snapshot into a new local directory:

```sh
node tools/check-public-docs.mjs
node tools/export-public-docs.mjs /tmp/gates-docs-preview
```

The exporter refuses an existing output directory. It copies only manifest-listed sources, rewrites guide links to their planned routes, and maps example links to `/docs/gates/examples/<filename>`. `routes.json` records each route and staged file. The website must serve those example assets as downloads and render the staged Markdown at the mapped routes. This local export is not a deployed site or a publication approval.
