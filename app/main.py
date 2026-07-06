"""FastAPI application: the REST surface of the security-scan service.

Endpoints
---------
* ``GET  /health`` — liveness/readiness probe (no auth).
* ``POST /scan``   — scan one attachment; requires the ``X-API-Key`` header.
"""

from __future__ import annotations

import httpx
from fastapi import Depends, FastAPI

from . import __version__
from .config import Settings, get_settings
from .models import HealthResponse, ScanRequest, ScanResult
from .scanning.orchestrator import Scanner
from .security import require_api_key


def get_http_client() -> httpx.AsyncClient | None:
    """HTTP client used by the scanner.

    Returns ``None`` in production so the scanner creates short-lived clients
    per request. Tests override this dependency to inject a mock transport,
    which keeps the whole ``/scan`` path hermetic.
    """
    return None

app = FastAPI(
    title="Multiforum Security Scan Service",
    version=__version__,
    summary="Scans forum file attachments with VirusTotal + ZIP static analysis.",
)


@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(
        version=__version__,
        virustotal_configured=bool(settings.virustotal_api_key),
    )


@app.post(
    "/scan",
    response_model=ScanResult,
    dependencies=[Depends(require_api_key)],
    tags=["scan"],
)
async def scan(
    request: ScanRequest,
    settings: Settings = Depends(get_settings),
    http_client: httpx.AsyncClient | None = Depends(get_http_client),
) -> ScanResult:
    scanner = Scanner(settings, http_client=http_client)
    return await scanner.scan(request)
