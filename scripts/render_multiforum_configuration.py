"""Render the scanner's non-secret Multiforum plugin desired state."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

API_VERSION = "multiforum.gennit.dev/v1alpha1"
PLUGIN_ID = "security-attachment-scan"
PLUGIN_VERSION = "0.5.0"


def normalize_service_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(
            "service URL must be an HTTPS origin without credentials, path, query, or fragment"
        )
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def build_manifest(
    *,
    service_url: str,
    block_on: str = "malicious",
    on_error: str = "block",
) -> dict[str, Any]:
    if block_on not in {"suspicious", "malicious"}:
        raise ValueError("block_on must be suspicious or malicious")
    if on_error not in {"block", "allow"}:
        raise ValueError("on_error must be block or allow")

    return {
        "apiVersion": API_VERSION,
        "plugins": [
            {
                "pluginId": PLUGIN_ID,
                "version": PLUGIN_VERSION,
                "enabled": True,
                "settingsJson": {
                    "serviceUrl": normalize_service_url(service_url),
                    "blockOn": block_on,
                    "onError": on_error,
                    "policy": {},
                },
                "secretRefs": [
                    {
                        "key": "SCAN_SERVICE_API_KEY",
                        "valueFrom": "env:SCAN_API_KEY",
                    }
                ],
            }
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render the security scanner's Multiforum configuration manifest."
    )
    parser.add_argument("--service-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--block-on",
        choices=("suspicious", "malicious"),
        default="malicious",
    )
    parser.add_argument(
        "--on-error",
        choices=("block", "allow"),
        default="block",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = build_manifest(
        service_url=args.service_url,
        block_on=args.block_on,
        on_error=args.on_error,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
