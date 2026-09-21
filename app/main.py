"""FastAPI application: the REST surface of the security-scan service.

Endpoints
---------
* ``GET  /health`` — liveness/readiness probe (no auth).
* ``POST /scan``   — scan one attachment; requires the ``X-API-Key`` header.
"""

from __future__ import annotations

import json
import logging
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, Response

from . import __version__
from .config import Settings, get_settings
from .models import HealthResponse, ScanRequest, ScanResult
from .scanning.orchestrator import Scanner
from .security import require_api_key

logger = logging.getLogger(__name__)


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
    response: Response,
    x_correlation_id: str | None = Header(
        default=None,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
    settings: Settings = Depends(get_settings),
    http_client: httpx.AsyncClient | None = Depends(get_http_client),
) -> ScanResult:
    correlation_id = x_correlation_id or str(uuid4())
    response.headers["X-Correlation-ID"] = correlation_id
    logger.info(
        json.dumps(
            {"event": "scan_started", "correlation_id": correlation_id},
            sort_keys=True,
        )
    )
    scanner = Scanner(settings, http_client=http_client)
    try:
        result = await scanner.scan(request)
    except Exception:
        logger.exception(
            json.dumps(
                {"event": "scan_failed", "correlation_id": correlation_id},
                sort_keys=True,
            )
        )
        raise
    logger.info(
        json.dumps(
            {
                "event": "scan_completed",
                "correlation_id": correlation_id,
                "verdict": result.verdict.value,
            },
            sort_keys=True,
        )
    )
    return result
