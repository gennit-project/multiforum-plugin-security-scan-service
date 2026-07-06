# security-attachment-scan (plugin shim)

This is the Multiforum plugin that wires the [security-scan
service](../README.md) into the forum backend. It is intentionally thin — all
scanning logic lives in the Python service; this shim only forwards attachment
URLs and maps the verdict back to a `PluginRunResult`.

> **Where this belongs.** Multiforum loads plugins from their own published
> GitHub repos (e.g. `gennit-project/multiforum-plugin-security-attachment-scan`),
> built to `dist/index.js` and released as a `.tgz` with `plugin.json`. This
> folder is kept alongside the service for reference and to keep the request
> contract in one place; to ship it, move `src/`, `plugin.json`, `package.json`,
> and `tsconfig.json` into that plugin repo and follow the standard publish flow.

## How it runs

1. A `downloadableFile.created` (or `.updated` / `.downloaded`) event fires.
2. The backend constructs the plugin with its `context` (settings + decrypted
   `secrets.server`) and calls `handleEvent({ type, payload })`.
3. For each `payload.attachmentUrls[]`, the shim `POST`s to the service's
   `/scan` with `X-API-Key: <secrets.server.apiKey>`.
4. The worst verdict across attachments decides the result. If it meets the
   configured `blockOn` threshold (default `malicious`), the step returns
   `success: false`, which fails the pipeline step and blocks the upload.

## Configuration

| Setting (scope) | Meaning |
|---|---|
| `serviceUrl` (server) | Base URL of the deployed Cloud Run service. |
| `blockOn` (server) | Minimum verdict that blocks the upload (`suspicious` \| `malicious` \| `error`). |
| `policy.require_readme` / `require_license` (channel) | Enforce root docs in ZIP uploads. |
| `apiKey` (server **secret**) | Shared secret sent as `X-API-Key`. |

## Build

```bash
npm install
npm run build   # → dist/index.js
```
