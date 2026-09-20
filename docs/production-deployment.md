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
| Multiforum plugin setting | Terraform `service_url` output |

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

For example, generate the shared scanner key locally with:

```bash
openssl rand -hex 32
```

### Environment variable

- `SCAN_TEST_FILE_URL`: a stable, non-sensitive URL for a known-safe ZIP test
  fixture. The default deployment requires it and expects a `clean` verdict.

Optional repository variables are:

- `CLOUD_RUN_SERVICE` (default `security-scan-service`)
- `ARTIFACT_REPOSITORY` (default `multiforum-services`)

## Deploy

Run **Deploy security scanner** from the repository's Actions tab. The workflow
is intentionally manual until the production integration is stable.

A successful run prints the Cloud Run URL in its job summary. Configure that
value as the `security-attachment-scan` plugin's `serviceUrl`, and configure
the same `SCAN_API_KEY` value as the plugin's `SCAN_SERVICE_API_KEY` secret.

Phase 2 will automate that final Multiforum reconciliation. In Phase 1 those are
the only two values that still need to be transferred to Multiforum.

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
3. If rotating `SCAN_API_KEY`, immediately update the Multiforum
   `SCAN_SERVICE_API_KEY` plugin secret to the same value.
4. Run the verifier and then retry a quarantined test download.

Secret Manager retains older versions for recovery and audit purposes. Disable
old versions after the new configuration has been verified.

## Rollback

Container images are immutable and tagged with commit SHAs. Re-run the workflow
from a known-good commit to deploy that image and reconcile the same Terraform
configuration. Do not edit Cloud Run by hand; the next Terraform apply will
replace manual drift.
