"""Shared pytest fixtures.

Everything here keeps tests hermetic: no real network, no real env file. The
``httpx.MockTransport`` lets us drive both the attachment download and the
VirusTotal call from a single request handler.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from app.config import Settings


def make_settings(**overrides) -> Settings:
    base = dict(
        api_key="test-key",
        virustotal_api_key="vt-key",
        max_download_bytes=10 * 1024 * 1024,
        _env_file=None,  # ignore any local .env during tests
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def settings() -> Settings:
    return make_settings()


def mock_client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    """Build an AsyncClient whose requests are answered by ``handler``."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def vt_stats_response(
    malicious: int = 0, suspicious: int = 0, harmless: int = 70
) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                    }
                }
            }
        },
    )
