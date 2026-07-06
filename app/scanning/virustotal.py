"""VirusTotal v3 reputation lookup by file hash.

We query ``GET /files/{sha256}`` rather than uploading the file: it is faster,
avoids sending user content to a third party, and covers the common case where
the file is already known to VirusTotal. An unknown file (HTTP 404) is reported
as ``skipped`` — absence of a record is not evidence of malice.

The httpx client is injectable so tests can drive it with a mock transport and
no network access. In production ``vt-py`` could be swapped in behind the same
``VirusTotalClient`` interface; the REST call is kept explicit here because the
contract (and its failure modes) is easier to test directly.
"""

from __future__ import annotations

import httpx

from ..config import Settings
from ..models import CheckResult, CheckStatus, Verdict

CHECK_NAME = "virustotal"


class VirusTotalClient:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None):
        self._settings = settings
        self._client = client

    async def check(self, sha256: str) -> CheckResult:
        settings = self._settings
        if not settings.virustotal_api_key:
            return CheckResult(
                name=CHECK_NAME,
                status=CheckStatus.SKIPPED,
                verdict=Verdict.CLEAN,
                summary="VirusTotal not configured; reputation check skipped.",
            )

        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            timeout=settings.virustotal_timeout_seconds
        )
        try:
            response = await client.get(
                f"{settings.virustotal_base_url}/files/{sha256}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
        except httpx.HTTPError as exc:
            return CheckResult(
                name=CHECK_NAME,
                status=CheckStatus.ERROR,
                verdict=Verdict.SUSPICIOUS,
                summary=f"VirusTotal request failed: {exc}",
            )
        finally:
            if owns_client:
                await client.aclose()

        if response.status_code == 404:
            return CheckResult(
                name=CHECK_NAME,
                status=CheckStatus.SKIPPED,
                verdict=Verdict.CLEAN,
                summary="File not previously seen by VirusTotal.",
                details={"sha256": sha256},
            )
        if response.status_code != 200:
            return CheckResult(
                name=CHECK_NAME,
                status=CheckStatus.ERROR,
                verdict=Verdict.SUSPICIOUS,
                summary=f"VirusTotal returned HTTP {response.status_code}.",
            )

        return self._interpret(sha256, response.json())

    def _interpret(self, sha256: str, body: dict) -> CheckResult:
        stats = (
            body.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        threshold = self._settings.virustotal_malicious_threshold

        details = {
            "sha256": sha256,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
        }

        if malicious >= threshold:
            return CheckResult(
                name=CHECK_NAME,
                status=CheckStatus.FAILED,
                verdict=Verdict.MALICIOUS,
                summary=f"{malicious} engine(s) flagged this file as malicious.",
                details=details,
            )
        if suspicious > 0:
            return CheckResult(
                name=CHECK_NAME,
                status=CheckStatus.FAILED,
                verdict=Verdict.SUSPICIOUS,
                summary=f"{suspicious} engine(s) flagged this file as suspicious.",
                details=details,
            )
        return CheckResult(
            name=CHECK_NAME,
            status=CheckStatus.PASSED,
            verdict=Verdict.CLEAN,
            summary="No engines flagged this file.",
            details=details,
        )
