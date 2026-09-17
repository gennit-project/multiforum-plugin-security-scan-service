from __future__ import annotations

import json
from argparse import Namespace
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from scripts import verify_deployment
from scripts.verify_deployment import Response, request_json, verify


class FakeHttpResponse:
    def __init__(self, status: int, body: dict):
        self.status = status
        self._body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._body


def test_request_json_sends_authenticated_json_request():
    response = FakeHttpResponse(200, {"verdict": "clean"})

    with patch("scripts.verify_deployment.urlopen", return_value=response) as urlopen:
        result = request_json(
            url="https://scanner.example/scan",
            method="POST",
            payload={"file_url": "https://fixtures.example/safe.zip"},
            api_key="secret",
        )

    request = urlopen.call_args.args[0]
    assert {
        "response": result,
        "method": request.method,
        "api_key": request.headers["X-api-key"],
    } == {
        "response": Response(200, {"verdict": "clean"}),
        "method": "POST",
        "api_key": "secret",
    }


def test_request_json_returns_http_error_response():
    error = HTTPError(
        "https://scanner.example/scan",
        401,
        "Unauthorized",
        {},
        BytesIO(b'{"detail":"Invalid API key"}'),
    )

    with patch("scripts.verify_deployment.urlopen", side_effect=error):
        result = request_json(url="https://scanner.example/scan")

    assert result == Response(401, {"detail": "Invalid API key"})


def test_request_json_explains_network_failure():
    with (
        patch(
            "scripts.verify_deployment.urlopen",
            side_effect=URLError("connection refused"),
        ),
        pytest.raises(RuntimeError, match="connection refused"),
    ):
        request_json(url="https://scanner.example/health")


def test_verify_checks_health_and_rejects_unauthenticated_scans():
    responses = [
        Response(200, {"status": "ok", "virustotal_configured": True}),
        Response(401, {"detail": "Invalid or missing API key."}),
    ]

    with patch("scripts.verify_deployment.request_json", side_effect=responses) as request:
        checks = verify(
            service_url="https://scanner.example/",
            api_key="secret",
            require_virustotal=True,
            test_file_url=None,
            expected_verdict="clean",
        )

    assert checks == [
        "health endpoint is ready",
        "unauthenticated scans are rejected",
    ]
    assert request.call_count == 2


def test_verify_runs_authenticated_safe_fixture_scan():
    responses = [
        Response(200, {"status": "ok", "virustotal_configured": True}),
        Response(401, {}),
        Response(200, {"verdict": "clean"}),
    ]

    with patch("scripts.verify_deployment.request_json", side_effect=responses):
        checks = verify(
            service_url="https://scanner.example",
            api_key="secret",
            require_virustotal=True,
            test_file_url="https://fixtures.example/safe.zip",
            expected_verdict="clean",
        )

    assert checks[-1] == "authenticated test scan returned clean"


@pytest.mark.parametrize(
    ("responses", "message"),
    [
        ([Response(503, {})], "Health check failed"),
        (
            [Response(200, {"status": "ok", "virustotal_configured": False})],
            "VirusTotal is not configured",
        ),
        (
            [
                Response(200, {"status": "ok", "virustotal_configured": True}),
                Response(200, {}),
            ],
            "Unauthenticated scan was not rejected",
        ),
    ],
)
def test_verify_rejects_unhealthy_deployments(responses, message):
    with (
        patch("scripts.verify_deployment.request_json", side_effect=responses),
        pytest.raises(RuntimeError, match=message),
    ):
        verify(
            service_url="https://scanner.example",
            api_key="secret",
            require_virustotal=True,
            test_file_url=None,
            expected_verdict="clean",
        )


def test_main_prints_successful_checks(capsys):
    args = Namespace(
        service_url="https://scanner.example",
        api_key="secret",
        require_virustotal=True,
        test_file_url=None,
        expected_verdict="clean",
    )
    with (
        patch("scripts.verify_deployment.parse_args", return_value=args),
        patch("scripts.verify_deployment.verify", return_value=["health endpoint is ready"]),
    ):
        exit_code = verify_deployment.main()

    assert {
        "exit_code": exit_code,
        "output": capsys.readouterr().out,
    } == {
        "exit_code": 0,
        "output": "PASS: health endpoint is ready\n",
    }


def test_main_reports_verification_failure(capsys):
    args = Namespace(
        service_url="https://scanner.example",
        api_key="secret",
        require_virustotal=True,
        test_file_url=None,
        expected_verdict="clean",
    )
    with (
        patch("scripts.verify_deployment.parse_args", return_value=args),
        patch(
            "scripts.verify_deployment.verify",
            side_effect=RuntimeError("scanner is unavailable"),
        ),
    ):
        exit_code = verify_deployment.main()

    assert {
        "exit_code": exit_code,
        "error": capsys.readouterr().err,
    } == {
        "exit_code": 1,
        "error": "Verification failed: scanner is unavailable\n",
    }
