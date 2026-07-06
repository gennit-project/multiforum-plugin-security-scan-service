"""End-to-end tests of the HTTP surface via FastAPI's TestClient.

The download + VirusTotal calls are mocked by overriding the ``get_http_client``
dependency, and settings are overridden so no real env/secret is needed.
"""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app, get_http_client

from .conftest import make_settings, mock_client, vt_stats_response
from .fixtures import make_zip

ATTACHMENT_URL = "https://cdn.example.com/files/bundle.zip"


def _install_overrides(*, file_bytes: bytes, malicious: int = 0, **settings_kwargs):
    def handler(request: httpx.Request) -> httpx.Response:
        if "virustotal" in request.url.host:
            return vt_stats_response(malicious=malicious)
        return httpx.Response(200, content=file_bytes)

    app.dependency_overrides[get_settings] = lambda: make_settings(**settings_kwargs)
    app.dependency_overrides[get_http_client] = lambda: mock_client(handler)


def teardown_function():
    app.dependency_overrides.clear()


def test_health_ok():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200


def test_scan_requires_api_key():
    _install_overrides(file_bytes=make_zip({"a.txt": b"x"}))
    with TestClient(app) as client:
        response = client.post("/scan", json={"file_url": ATTACHMENT_URL})
    assert response.status_code == 401


def test_scan_clean_zip_returns_clean_verdict():
    _install_overrides(file_bytes=make_zip({"README.md": b"# hi", "a.png": b"PNG"}))
    with TestClient(app) as client:
        response = client.post(
            "/scan",
            json={"file_url": ATTACHMENT_URL},
            headers={"X-API-Key": "test-key"},
        )
    assert response.json()["verdict"] == "clean"


def test_scan_flags_executable_as_malicious():
    _install_overrides(file_bytes=make_zip({"setup.exe": b"MZ"}))
    with TestClient(app) as client:
        response = client.post(
            "/scan",
            json={"file_url": ATTACHMENT_URL},
            headers={"X-API-Key": "test-key"},
        )
    assert response.json()["verdict"] == "malicious"
