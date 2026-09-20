#!/usr/bin/env python3
"""Verify a deployed scanner without exposing credentials or signed file URLs."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class Response:
    status: int
    body: dict[str, Any]


def request_json(
    *,
    url: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    api_key: str | None = None,
) -> Response:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"content-type": "application/json"}
    if api_key is not None:
        headers["x-api-key"] = api_key
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=130) as response:
            return Response(response.status, json.loads(response.read()))
    except HTTPError as error:
        return Response(error.code, json.loads(error.read()))
    except URLError as error:
        raise RuntimeError(f"Could not reach scanner: {error.reason}") from error


def verify(
    *,
    service_url: str,
    api_key: str,
    require_virustotal: bool,
    test_file_url: str | None,
    expected_verdict: str,
) -> list[str]:
    base_url = service_url.rstrip("/")
    checks: list[str] = []

    health = request_json(url=f"{base_url}/health")
    if health.status != 200 or health.body.get("status") != "ok":
        raise RuntimeError(f"Health check failed with HTTP {health.status}")
    if require_virustotal and not health.body.get("virustotal_configured"):
        raise RuntimeError("Health check reports that VirusTotal is not configured")
    checks.append("health endpoint is ready")

    unauthorized = request_json(
        url=f"{base_url}/scan",
        method="POST",
        payload={"file_url": "https://example.invalid/auth-check"},
    )
    if unauthorized.status != 401:
        raise RuntimeError(
            "Unauthenticated scan was not rejected; expected HTTP 401, "
            f"received HTTP {unauthorized.status}"
        )
    checks.append("unauthenticated scans are rejected")

    if test_file_url:
        scan = request_json(
            url=f"{base_url}/scan",
            method="POST",
            payload={"file_url": test_file_url},
            api_key=api_key,
        )
        if scan.status != 200:
            raise RuntimeError(f"Authenticated test scan failed with HTTP {scan.status}")
        verdict = scan.body.get("verdict")
        if verdict != expected_verdict:
            raise RuntimeError(
                f"Expected test verdict {expected_verdict!r}, received {verdict!r}"
            )
        checks.append(f"authenticated test scan returned {verdict}")

    return checks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--require-virustotal", action="store_true")
    parser.add_argument("--test-file-url")
    parser.add_argument("--expected-verdict", default="clean")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        checks = verify(
            service_url=args.service_url,
            api_key=args.api_key,
            require_virustotal=args.require_virustotal,
            test_file_url=args.test_file_url,
            expected_verdict=args.expected_verdict,
        )
    except (RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"Verification failed: {error}", file=sys.stderr)
        return 1

    for check in checks:
        print(f"PASS: {check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
