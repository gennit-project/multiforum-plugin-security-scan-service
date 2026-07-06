"""Pydantic request/response schemas — the REST contract of the service.

These types are the boundary the TypeScript plugin shim codes against.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """Overall outcome of a scan, in ascending order of severity."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class ScanPolicy(BaseModel):
    """Per-request overrides for the ZIP static-analysis rules.

    Omitted fields fall back to the service-level defaults in Settings.
    """

    allowed_extensions: list[str] | None = Field(
        default=None,
        description="If set, ZIP entries with any other extension fail the scan.",
    )
    blocked_extensions: list[str] | None = Field(
        default=None,
        description="ZIP entries with these extensions always fail the scan.",
    )
    max_decompression_ratio: float | None = None
    max_zip_entries: int | None = None
    require_readme: bool | None = None
    require_license: bool | None = None


class ScanRequest(BaseModel):
    file_url: str = Field(..., description="Publicly fetchable URL of the attachment.")
    file_name: str | None = Field(
        default=None,
        description="Original filename, used to detect archive type when the URL has no extension.",
    )
    policy: ScanPolicy = Field(default_factory=ScanPolicy)


class CheckResult(BaseModel):
    """Result of one independent check (VirusTotal, zip static analysis, ...)."""

    name: str
    status: CheckStatus
    verdict: Verdict
    summary: str
    details: dict = Field(default_factory=dict)


class ScanResult(BaseModel):
    verdict: Verdict
    summary: str
    sha256: str | None = None
    size_bytes: int | None = None
    checks: list[CheckResult] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    virustotal_configured: bool
