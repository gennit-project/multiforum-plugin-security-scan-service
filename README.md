# Multiforum Security Scan Service

A small **Python / FastAPI** microservice that scans user‑uploaded files for
malware and unsafe archive contents, returning a single `clean` / `suspicious` /
`malicious` verdict. It is a plugin backend for
[**Multiforum**](https://github.com/gennit-project) — an open‑source,
self‑hostable community platform (think Reddit‑style forums with discussions,
events, wikis, and **file downloads**).

> **Context for readers new to the project.** Multiforum lets communities publish
> downloadable files — for example, a Sims‑house build or a game mod packaged as
> a `.zip`. Anything a community accepts from the public needs to be checked for
> malware and abuse before other users download it. This service is what performs
> that check.

---

## Why this exists as its own service

Multiforum's backend is **Node.js**, and its plugin system runs plugins
**in‑process** inside that backend — so a plugin can't be written in Python, and
you wouldn't want to unpack untrusted archives inside your main API server
anyway.

The design splits the work in two:

- A tiny **TypeScript plugin** ([`multiforum-plugin-security-attachment-scan`](https://github.com/gennit-project/multiforum-plugin-security-attachment-scan))
  runs inside the backend. When a file is uploaded it does nothing heavy — it
  just makes an authenticated HTTP call to this service.
- **This Python service** does the actual work: fetching the file, running a
  VirusTotal reputation lookup, and statically analysing ZIP archives.

```
 user uploads a file
        │
        ▼
 Multiforum backend (Node.js)  ──fires "downloadableFile.created" event
        │
        ▼
 security-attachment-scan plugin (TypeScript, in-process)
        │  POST /scan  { file_url }   (X-API-Key)
        ▼
 THIS SERVICE  (Python / FastAPI)  ── VirusTotal + ZIP static analysis
        │  { verdict: "malicious", … }
        ▼
 plugin blocks the upload when the verdict crosses a configured threshold
```

Keeping the scanning in a standalone service also means it can be deployed,
scaled, and secured independently of the main application, and scale to zero when
idle.

---

## What it does

Each `POST /scan` runs two independent checks and folds them into one verdict
(`clean` < `suspicious` < `malicious` < `error`; most‑severe wins):

| Check | What it does |
|-------|--------------|
| **VirusTotal reputation** | Looks the file up by SHA‑256 in the VirusTotal v3 REST API. Malicious engine hits → `malicious`; a file VirusTotal has never seen is reported as `skipped` rather than failed. Runs only if an API key is configured. |
| **ZIP static analysis** | Inspects the archive's central directory **without extracting anything**: blocks dangerous file types (`.exe`, `.dll`, scripts…), detects "zip bombs" via decompression‑ratio and entry‑count limits, flags path‑traversal entries (`../…`), and can require a root `README`/`LICENSE`. |

The file is streamed with a hard size cap, so a hostile URL can't exhaust memory.

---

## Tech stack & engineering highlights

- **Language / framework:** Python 3.11, FastAPI, Pydantic v2, `httpx` (async).
- **Testing:** `pytest` — 29 tests, fully **hermetic** (no network): the
  VirusTotal and file‑download calls are driven through an injected `httpx`
  mock transport, and ZIP fixtures are built in‑memory.
- **Auth:** service‑to‑service API key (`X-API-Key`), constant‑time compared.
- **Containerized:** multi‑stage‑friendly `Dockerfile` (slim base, non‑root user,
  listens on `$PORT`) built for **Google Cloud Run**.
- **CI/CD:** GitHub Actions — lint (`ruff`) + tests on every PR; deploy to Cloud
  Run on `main` using **Workload Identity Federation** (keyless OIDC auth to GCP,
  no long‑lived service‑account keys).
- **Infrastructure as code:** `terraform/` provisions the Cloud Run service, a
  least‑privilege runtime service account, Secret Manager secrets, and an IAM
  binding so **only the Multiforum backend** may invoke it.
- **Verified end‑to‑end:** exercised through the real Multiforum stack — a `.zip`
  containing an `.exe` was uploaded, this service returned `malicious`, and the
  upload was blocked.

---

## API

```
GET  /health                       → { status, version, virustotal_configured }
POST /scan   (X-API-Key required)  → ScanResult
```

**Request**

```json
{
  "file_url": "https://storage.example.com/files/bundle.zip",
  "file_name": "bundle.zip",
  "policy": { "require_readme": true, "blocked_extensions": ["exe", "dll"] }
}
```

**Response**

```json
{
  "verdict": "malicious",
  "summary": "Disallowed file type: 'installer.exe' (.exe).",
  "sha256": "e39e7755…",
  "size_bytes": 363,
  "checks": [
    { "name": "virustotal", "status": "skipped", "verdict": "clean", "summary": "…" },
    { "name": "zip_static_analysis", "status": "failed", "verdict": "malicious",
      "summary": "…", "details": { "findings": [ … ] } }
  ]
}
```

---

## Run it locally

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # set SCAN_API_KEY (and optionally SCAN_VIRUSTOTAL_API_KEY)
uvicorn app.main:app --reload
```

Lint and test:

```bash
ruff check .
pytest -q
```

Try a scan:

```bash
curl -s -X POST http://127.0.0.1:8000/scan \
  -H 'content-type: application/json' -H 'x-api-key: <your SCAN_API_KEY>' \
  -d '{"file_url":"https://example.com/bundle.zip"}'
```

---

## Deploy (Google Cloud Run)

- **Container:** `Dockerfile` (Python 3.11 slim, non‑root, listens on `$PORT`).
- **CI/CD:** `.github/workflows/ci.yml` runs ruff + pytest; `deploy.yml` runs
  `gcloud run deploy --source` on `main` via Workload Identity Federation and
  deploys with `--no-allow-unauthenticated` (only the backend's service account,
  granted `run.invoker`, can call it).
- **Terraform:** `terraform/` stands up the Cloud Run service + runtime SA +
  Secret Manager secrets + invoker IAM binding.

```bash
cd terraform
terraform init
terraform apply \
  -var project_id=my-proj \
  -var image=us-central1-docker.pkg.dev/my-proj/plugins/security-scan-service:latest \
  -var invoker_service_account=multiforum-backend@my-proj.iam.gserviceaccount.com
```

---

## Project layout

```
app/
  main.py              FastAPI app (/health, /scan)
  config.py            Env-driven settings (pydantic-settings)
  security.py          X-API-Key auth dependency
  models.py            Pydantic request/response contract
  scanning/
    downloader.py      Size-capped fetch + sha256
    virustotal.py      VirusTotal v3 REST client (httpx, injectable)
    zip_inspector.py   Static ZIP analysis
    orchestrator.py    Runs the checks, folds them into one verdict
tests/                 pytest unit + integration (hermetic; mock transport)
terraform/             Cloud Run + IAM + Secret Manager
.github/workflows/     CI (ruff + pytest) and Cloud Run deploy
```

## Related repositories

- [`multiforum-plugin-security-attachment-scan`](https://github.com/gennit-project/multiforum-plugin-security-attachment-scan) — the TypeScript plugin that calls this service.
- [Multiforum](https://github.com/gennit-project) — the platform this plugs into.

## License

MIT
