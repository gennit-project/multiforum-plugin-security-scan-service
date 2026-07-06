"""Unit tests for the Scanner orchestrator (download + VT + zip fold-in)."""

from __future__ import annotations

import httpx

from app.models import ScanPolicy, ScanRequest, Verdict
from app.scanning.orchestrator import Scanner

from .conftest import make_settings, mock_client, vt_stats_response
from .fixtures import make_zip, make_zip_bomb

ATTACHMENT_URL = "https://cdn.example.com/files/bundle.zip"


def _router(*, file_bytes: bytes, malicious: int = 0, suspicious: int = 0):
    """Route download requests to the file bytes and VT requests to stats."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "virustotal" in request.url.host:
            return vt_stats_response(malicious=malicious, suspicious=suspicious)
        return httpx.Response(200, content=file_bytes)

    return handler


async def test_clean_zip_overall_clean():
    content = make_zip({"README.md": b"# hi", "art.png": b"PNG"})
    scanner = Scanner(make_settings(), http_client=mock_client(_router(file_bytes=content)))
    result = await scanner.scan(ScanRequest(file_url=ATTACHMENT_URL))
    assert result.verdict == Verdict.CLEAN


async def test_virustotal_malicious_dominates():
    content = make_zip({"README.md": b"# hi"})
    scanner = Scanner(
        make_settings(), http_client=mock_client(_router(file_bytes=content, malicious=5))
    )
    result = await scanner.scan(ScanRequest(file_url=ATTACHMENT_URL))
    assert result.verdict == Verdict.MALICIOUS


async def test_zip_bomb_makes_overall_malicious():
    scanner = Scanner(
        make_settings(), http_client=mock_client(_router(file_bytes=make_zip_bomb()))
    )
    result = await scanner.scan(ScanRequest(file_url=ATTACHMENT_URL))
    assert result.verdict == Verdict.MALICIOUS


async def test_missing_readme_policy_makes_suspicious():
    content = make_zip({"main.txt": b"x"})
    scanner = Scanner(make_settings(), http_client=mock_client(_router(file_bytes=content)))
    result = await scanner.scan(
        ScanRequest(file_url=ATTACHMENT_URL, policy=ScanPolicy(require_readme=True))
    )
    assert result.verdict == Verdict.SUSPICIOUS


async def test_download_failure_is_error_verdict():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    scanner = Scanner(make_settings(), http_client=mock_client(handler))
    result = await scanner.scan(ScanRequest(file_url=ATTACHMENT_URL))
    assert result.verdict == Verdict.ERROR


async def test_sha256_is_reported():
    content = make_zip({"a.txt": b"x"})
    scanner = Scanner(make_settings(), http_client=mock_client(_router(file_bytes=content)))
    result = await scanner.scan(ScanRequest(file_url=ATTACHMENT_URL))
    assert result.sha256 is not None and len(result.sha256) == 64
