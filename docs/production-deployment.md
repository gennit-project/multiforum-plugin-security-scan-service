# Production deployment

The scanner has one supported production path:

1. GitHub Actions authenticates to Google Cloud with short-lived Workload
   Identity Federation credentials.
2. Terraform provisions Artifact Registry, Secret Manager, the runtime service
   account, Cloud Run, health probes, scaling limits, and public invocation.
3. The workflow builds an immutable SHA-tagged container and pushes it to
   Artifact Registry.
4. GitHub environment secrets are copied to new Secret Manager versions without
   entering Terraform state.
5. Terraform deploys the image and the verifier checks service health,
   VirusTotal configuration, API-key enforcement, and an optional safe fixture.
6. A pinned `mfctl` authenticates with OAuth client credentials and reconciles
   the plugin version, scanner URL, security policy, shared API key, and server
   download pipelines.

Cloud Run permits requests to reach FastAPI, but the `POST /scan` route
requires `X-API-Key`. The public `GET /health` route contains no secret data.
This matches a Multiforum backend hosted outside Google Cloud, such as Heroku,
without storing a long-lived Google service-account key there.

## Ownership and sources of truth

| Concern | Source of truth |
| --- | --- |
| Cloud resources, IAM, probes, and scaling | `terraform/` |
| Scanner image | Commit SHA in Artifact Registry |
| Terraform state | Versioned private GCS bucket |
| Deployment identity | GitHub OIDC + GCP Workload Identity Federation |
| Scanner and VirusTotal secret values | GitHub `production` environment secrets |
| Runtime copies of secrets | Google Secret Manager |
| Safe end-to-end fixture | `SCAN_TEST_FILE_URL` GitHub environment variable |
| Multiforum plugin desired state | `scripts/render_multiforum_configuration.py` |
| Multiforum scanner URL | Terraform `service_url` output, reconciled by `mfctl` |
| Multiforum scanner secret | `SCAN_API_KEY`, transferred ephemerally by `mfctl` |

Terraform deliberately manages secret containers and access policies but not
secret values. This prevents plaintext keys from being written into Terraform
state.

## One-time bootstrap

The state bucket and GitHub-to-GCP trust must exist before Terraform can manage
anything. Run the idempotent helper using a Google Cloud project-owner account
and a GitHub account that can edit Actions variables:

```bash
export GCP_PROJECT_ID="your-project"
export GITHUB_REPOSITORY="gennit-project/multiforum-plugin-security-scan-service"
export GCP_REGION="us-central1"

./scripts/bootstrap_gcp.sh
```

The script enables only the APIs needed for bootstrapping, creates a versioned
state bucket, creates the GitHub deployment service account and identity
provider, grants its deployment roles, and writes the non-secret GitHub
repository variables.

Create a GitHub environment named `production`. Add:

### Environment secrets

- `SCAN_API_KEY`: at least 32 random characters. Store this in a password
  manager because the Multiforum plugin must receive the identical value.
- `SCAN_VIRUSTOTAL_API_KEY`: the VirusTotal API key used only by the scanner.
- `MULTIFORUM_OAUTH_CLIENT_SECRET`: the client secret for the narrowly scoped
  Multiforum plugin-configuration automation identity.

For example, generate the shared scanner key locally with:

```bash
openssl rand -hex 32
```

### Environment variable

- `SCAN_TEST_FILE_URL`: a stable, non-sensitive URL for a known-safe ZIP test
  fixture. The default deployment requires it and expects a `clean` verdict.
- `MULTIFORUM_GRAPHQL_URL`: the production Multiforum GraphQL endpoint.
- `MULTIFORUM_OAUTH_TOKEN_URL`: the OAuth provider's HTTPS token endpoint.
- `MULTIFORUM_OAUTH_CLIENT_ID`: the automation application's client ID.
- `MULTIFORUM_OAUTH_AUDIENCE`: the Multiforum API audience.

The Multiforum backend must allowlist the automation token's exact `sub` claim
in `PLUGIN_CONFIGURATION_AUTOMATION_SUBJECTS`. The identity must receive only
the `plugin-configuration:write` permission. It can call the reconciliation
preview and apply operations, but it is not a Multiforum user and cannot call
other administrative operations.

Optional repository variables are:

- `CLOUD_RUN_SERVICE` (default `security-scan-service`)
- `ARTIFACT_REPOSITORY` (default `multiforum-services`)
- `SCAN_BLOCK_ON` (`malicious` by default; may be `suspicious`)
- `SCAN_ON_ERROR` (`block` by default; may be `allow`)

## Deploy

Run **Deploy security scanner** from the repository's Actions tab. The workflow
is intentionally manual until the production integration is stable.

A successful run prints the Cloud Run URL and reconciliation result in its job
summary. After service verification, the workflow installs/enables
`security-attachment-scan` v0.5.0 and reconciles the URL, security policy,
matching `SCAN_SERVICE_API_KEY`, and all three server download pipelines
without writing the key to the manifest, Terraform state, or logs.

The desired state is authoritative for the complete server pipeline list. It
matches the imported production topology: the security scanner is the only
step for `downloadableFile.created`, `downloadableFile.updated`, and
`downloadableFile.downloaded`; each pipeline stops on failure and uses
`ALL_FILES_IMMEDIATE`. Generated `effectiveAt` and `policyId` values remain
server-owned and are intentionally omitted, preventing perpetual drift.

Because reconciliation replaces the complete server pipeline list, add any
future server-scoped plugin pipeline to the renderer before deploying it. A
manually added server pipeline that is absent from this desired state will be
reported as drift and removed by the next successful deployment.

## Verify or diagnose from a terminal

```bash
python scripts/verify_deployment.py --service-url "https://SERVICE.run.app" --api-key "${SCAN_API_KEY}" --require-virustotal
```

To exercise a known-safe fixture:

```bash
python scripts/verify_deployment.py --service-url "https://SERVICE.run.app" --api-key "${SCAN_API_KEY}" --require-virustotal --test-file-url "https://example.test/safe.zip" --expected-verdict clean
```

The verifier never prints the API key or test-file URL.

## Secret rotation

1. Replace the relevant GitHub `production` environment secret.
2. Run the deployment workflow.
3. The workflow updates the Cloud Run secret and Multiforum's matching
   `SCAN_SERVICE_API_KEY` in the same run.
4. Confirm the reconciliation summary, then retry a quarantined test download.

Secret Manager retains older versions for recovery and audit purposes. Disable
old versions after the new configuration has been verified.

## Rollback

Container images are immutable and tagged with commit SHAs. Re-run the workflow
from a known-good commit to deploy that image and reconcile the same Terraform
configuration. Do not edit Cloud Run by hand; the next Terraform apply will
replace manual drift.
