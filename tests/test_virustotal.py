"""Unit tests for the VirusTotal client, driven by a mock transport."""

from __future__ import annotations

import httpx

from app.models import CheckStatus, Verdict
from app.scanning.virustotal import VirusTotalClient

from .conftest import make_settings, mock_client, vt_stats_response

SHA = "a" * 64


async def test_skipped_when_no_api_key():
    client = VirusTotalClient(make_settings(virustotal_api_key=""))
    result = await client.check(SHA)
    assert result.status == CheckStatus.SKIPPED


async def test_clean_when_no_engines_flag():
    def handler(_request: httpx.Request) -> httpx.Response:
        return vt_stats_response(malicious=0, suspicious=0)

    client = VirusTotalClient(make_settings(), client=mock_client(handler))
    result = await client.check(SHA)
    assert result.verdict == Verdict.CLEAN


async def test_malicious_when_engine_flags():
    def handler(_request: httpx.Request) -> httpx.Response:
        return vt_stats_response(malicious=3)

    client = VirusTotalClient(make_settings(), client=mock_client(handler))
    result = await client.check(SHA)
    assert result.verdict == Verdict.MALICIOUS


async def test_suspicious_when_only_suspicious_hits():
    def handler(_request: httpx.Request) -> httpx.Response:
        return vt_stats_response(malicious=0, suspicious=2)

    client = VirusTotalClient(make_settings(), client=mock_client(handler))
    result = await client.check(SHA)
    assert result.verdict == Verdict.SUSPICIOUS


async def test_unknown_file_is_skipped():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    client = VirusTotalClient(make_settings(), client=mock_client(handler))
    result = await client.check(SHA)
    assert result.status == CheckStatus.SKIPPED


async def test_server_error_is_reported_as_error():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = VirusTotalClient(make_settings(), client=mock_client(handler))
    result = await client.check(SHA)
    assert result.status == CheckStatus.ERROR


async def test_sends_api_key_header():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers.get("x-apikey", "")
        return vt_stats_response()

    client = VirusTotalClient(
        make_settings(virustotal_api_key="secret"), client=mock_client(handler)
    )
    await client.check(SHA)
    assert seen["key"] == "secret"
