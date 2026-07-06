# Multiforum Security Scan Service

A small **Python / FastAPI** microservice that scans file attachments uploaded to
[Multiforum](https://github.com/gennit-project) forums. It is invoked
out-of-process by the `security-attachment-scan` plugin — a thin TypeScript shim
that runs inside the Node.js backend and calls this service over HTTP whenever a
`downloadableFile.*` event fires.

> **Why a separate Python service?** Multiforum plugins execute in-process inside
> the Node backend, so they can't run Python directly. File-security work,
> however, is a better fit for Python's ecosystem — VirusTotal's official client,
> archive/zip handling, and (future) image and document inspection. Splitting the
> heavy lifting into an independently deployable service also keeps untrusted-file
> processing off the main backend and lets it scale to zero on Cloud Run.

## What it checks

Each `POST /scan` runs two independent checks and folds them into one verdict
(`clean` < `suspicious` < `malicious` < `error`, most-severe wins):

| Check | What it does |
|-------|--------------|
| **VirusTotal** | Looks the file up by SHA-256 in the VirusTotal v3 REST API. Malicious engine hits → `malicious`; unknown file → skipped. |
| **ZIP static analysis** | Reads the archive's central directory (no extraction): blocks dangerous file types (`.exe`, `.dll`, …), catches zip bombs via decompression ratio + entry-count caps, flags path-traversal entries, and can require a root `README`/`LICENSE` (the downloads workflow). |

## API

```
GET  /health                      → { status, version, virustotal_configured }
POST /scan   (X-API-Key required)  → ScanResult
```

Request:

```json
{
  "file_url": "https://cdn.example.com/files/bundle.zip",
  "file_name": "bundle.zip",
  "policy": { "require_readme": true, "blocked_extensions": ["exe", "dll"] }
}
```

Response:

```json
{
  "verdict": "malicious",
  "summary": "Disallowed file type: 'setup.exe' (.exe).",
  "sha256": "…",
  "size_bytes": 20480,
  "checks": [
    { "name": "virustotal", "status": "skipped", "verdict": "clean", "summary": "…" },
    { "name": "zip_static_analysis", "status": "failed", "verdict": "malicious", "summary": "…", "details": { "findings": [ … ] } }
  ]
}
```

## Local development

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # set SCAN_API_KEY (and optionally SCAN_VIRUSTOTAL_API_KEY)
uvicorn app.main:app --reload
```

Run the checks:

```bash
ruff check .
pytest -q
```

## Deployment (GCP Cloud Run)

- **Container:** `Dockerfile` (Python 3.11 slim, non-root, listens on `$PORT`).
- **CI/CD:** `.gitlab-ci.yml` runs lint → test → build → deploy. GCP auth uses
  Workload Identity Federation (OIDC, no long-lived keys). Deploy runs on `main`
  and sets `--no-allow-unauthenticated`, so only the backend's service account
  (granted `run.invoker`) can call it.
- **Infra:** `terraform/` provisions the Cloud Run service, a dedicated runtime
  service account, the two Secret Manager secrets, and the invoker IAM binding.

```bash
cd terraform
terraform init
terraform apply \
  -var project_id=my-proj \
  -var image=us-central1-docker.pkg.dev/my-proj/plugins/security-scan-service:latest \
  -var invoker_service_account=multiforum-backend@my-proj.iam.gserviceaccount.com
```

## The plugin shim

`plugin-shim/` contains the TypeScript plugin that calls this service. It belongs
in its own published plugin repo (`multiforum-plugin-security-attachment-scan`)
and is included here for reference and to keep the contract in one place. See
[`plugin-shim/README.md`](plugin-shim/README.md).

## Layout

```
app/
  main.py              FastAPI app (/health, /scan)
  config.py            Env-driven settings
  security.py          X-API-Key auth dependency
  models.py            Pydantic request/response contract
  scanning/
    downloader.py      Size-capped fetch + sha256
    virustotal.py      VirusTotal v3 REST client (httpx, injectable)
    zip_inspector.py   Static ZIP analysis
    orchestrator.py    Runs checks, folds into one verdict
tests/                 pytest unit + integration (hermetic; mock transport)
terraform/             Cloud Run + IAM + secrets
plugin-shim/           TypeScript plugin that calls this service
```
