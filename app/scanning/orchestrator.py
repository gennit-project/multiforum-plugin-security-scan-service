"""Coordinate the individual checks into a single ScanResult.

Flow: download the attachment (with a size cap and sha256) → run the VirusTotal
reputation check and the ZIP static-analysis check → fold the per-check verdicts
into one overall verdict by taking the most severe.
"""

from __future__ import annotations

import httpx

from ..config import Settings
from ..models import (
    CheckResult,
    CheckStatus,
    ScanPolicy,
    ScanRequest,
    ScanResult,
    Verdict,
)
from .downloader import DownloadError, download_file
from .virustotal import VirusTotalClient
from .zip_inspector import analyze_zip_bytes

# Severity ordering used to reduce many check verdicts to one.
_SEVERITY = {
    Verdict.CLEAN: 0,
    Verdict.SUSPICIOUS: 1,
    Verdict.MALICIOUS: 2,
    Verdict.ERROR: 3,
}

ZIP_CHECK_NAME = "zip_static_analysis"


def _worst(verdicts: list[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _SEVERITY[v]) if verdicts else Verdict.CLEAN


def _resolve(policy: ScanPolicy, settings: Settings) -> dict:
    """Merge per-request policy over service-level defaults."""
    return {
        "allowed_extensions": (
            set(policy.allowed_extensions) if policy.allowed_extensions else None
        ),
        "blocked_extensions": (
            set(policy.blocked_extensions) if policy.blocked_extensions is not None else None
        ),
        "max_decompression_ratio": (
            policy.max_decompression_ratio
            if policy.max_decompression_ratio is not None
            else settings.max_decompression_ratio
        ),
        "max_entries": (
            policy.max_zip_entries
            if policy.max_zip_entries is not None
            else settings.max_zip_entries
        ),
        "require_readme": (
            policy.require_readme
            if policy.require_readme is not None
            else settings.require_readme
        ),
        "require_license": (
            policy.require_license
            if policy.require_license is not None
            else settings.require_license
        ),
    }


def _run_zip_check(content: bytes, policy: ScanPolicy, settings: Settings) -> CheckResult:
    opts = _resolve(policy, settings)
    analysis = analyze_zip_bytes(content, **opts)

    if not analysis.is_zip:
        return CheckResult(
            name=ZIP_CHECK_NAME,
            status=CheckStatus.SKIPPED,
            verdict=Verdict.CLEAN,
            summary="Attachment is not a ZIP archive; static analysis skipped.",
        )

    details = {
        "entry_count": analysis.entry_count,
        "total_uncompressed": analysis.total_uncompressed,
        "max_ratio": round(analysis.max_ratio, 2),
        "has_readme": analysis.has_readme,
        "has_license": analysis.has_license,
        "findings": [{"code": f.code, "message": f.message} for f in analysis.findings],
    }

    if analysis.ok:
        return CheckResult(
            name=ZIP_CHECK_NAME,
            status=CheckStatus.PASSED,
            verdict=Verdict.CLEAN,
            summary=f"ZIP passed static analysis ({analysis.entry_count} entries).",
            details=details,
        )

    # A dangerous file type or zip bomb is malicious; missing docs are merely
    # suspicious (policy violation, not an attack).
    hard_codes = {
        "blocked_type",
        "not_in_allow_list",
        "zip_bomb",
        "path_traversal",
        "too_many_entries",
    }
    is_hard = any(f.code in hard_codes for f in analysis.findings)
    return CheckResult(
        name=ZIP_CHECK_NAME,
        status=CheckStatus.FAILED,
        verdict=Verdict.MALICIOUS if is_hard else Verdict.SUSPICIOUS,
        summary="; ".join(f.message for f in analysis.findings),
        details=details,
    )


class Scanner:
    """Owns the checks; takes an optional httpx client for test injection."""

    def __init__(self, settings: Settings, http_client: httpx.AsyncClient | None = None):
        self._settings = settings
        self._http_client = http_client

    async def scan(self, request: ScanRequest) -> ScanResult:
        settings = self._settings
        try:
            downloaded = await download_file(
                request.file_url,
                max_bytes=settings.max_download_bytes,
                timeout_seconds=settings.download_timeout_seconds,
                client=self._http_client,
            )
        except DownloadError as exc:
            return ScanResult(
                verdict=Verdict.ERROR,
                summary=str(exc),
                checks=[
                    CheckResult(
                        name="download",
                        status=CheckStatus.ERROR,
                        verdict=Verdict.ERROR,
                        summary=str(exc),
                    )
                ],
            )

        vt_client = VirusTotalClient(settings, client=self._http_client)
        vt_result = await vt_client.check(downloaded.sha256)
        zip_result = _run_zip_check(downloaded.content, request.policy, settings)

        checks = [vt_result, zip_result]
        overall = _worst([c.verdict for c in checks])

        return ScanResult(
            verdict=overall,
            summary=_overall_summary(overall, checks),
            sha256=downloaded.sha256,
            size_bytes=downloaded.size_bytes,
            checks=checks,
        )


def _overall_summary(verdict: Verdict, checks: list[CheckResult]) -> str:
    if verdict == Verdict.CLEAN:
        return "No problems detected."
    failing = [c.summary for c in checks if c.verdict == verdict]
    return " | ".join(failing) or f"Overall verdict: {verdict.value}."
