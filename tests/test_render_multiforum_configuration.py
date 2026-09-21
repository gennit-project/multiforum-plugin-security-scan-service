import json
from pathlib import Path

import pytest

from scripts.render_multiforum_configuration import (
    API_VERSION,
    PIPELINE_APPLICABILITY,
    PIPELINE_EVENTS,
    PLUGIN_ID,
    PLUGIN_VERSION,
    build_manifest,
    main,
    normalize_service_url,
)


def test_build_manifest_wires_service_secret_and_security_pipelines() -> None:
    manifest = build_manifest(
        service_url="https://scanner-abc.run.app/",
        block_on="suspicious",
        on_error="allow",
    )

    assert manifest == {
        "apiVersion": API_VERSION,
        "plugins": [
            {
                "pluginId": PLUGIN_ID,
                "version": PLUGIN_VERSION,
                "enabled": True,
                "settingsJson": {
                    "serviceUrl": "https://scanner-abc.run.app",
                    "blockOn": "suspicious",
                    "onError": "allow",
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
        "pipelines": [
            {
                "event": event,
                "steps": [
                    {
                        "pluginId": PLUGIN_ID,
                        "version": PLUGIN_VERSION,
                        "continueOnError": False,
                        "condition": "ALWAYS",
                    }
                ],
                "stopOnFirstFailure": True,
                "applicability": PIPELINE_APPLICABILITY,
            }
            for event in PIPELINE_EVENTS
        ],
    }
    secret_reference = manifest["plugins"][0]["secretRefs"][0]
    assert secret_reference == {
        "key": "SCAN_SERVICE_API_KEY",
        "valueFrom": "env:SCAN_API_KEY",
    }
    assert "value" not in secret_reference


def test_manifest_manages_each_supported_download_event_once() -> None:
    manifest = build_manifest(service_url="https://scanner.example.test")
    pipelines = manifest["pipelines"]

    assert tuple(pipeline["event"] for pipeline in pipelines) == PIPELINE_EVENTS
    assert len({pipeline["event"] for pipeline in pipelines}) == len(PIPELINE_EVENTS)
    assert all(
        pipeline["applicability"] == "ALL_FILES_IMMEDIATE"
        and pipeline["stopOnFirstFailure"] is True
        for pipeline in pipelines
    )
    assert all(
        pipeline["steps"] == [
            {
                "pluginId": "security-attachment-scan",
                "version": "0.5.1",
                "continueOnError": False,
                "condition": "ALWAYS",
            }
        ]
        for pipeline in pipelines
    )


@pytest.mark.parametrize(
    "value",
    [
        "http://scanner.example.test",
        "https://user:password@scanner.example.test",
        "https://scanner.example.test/scan",
        "https://scanner.example.test?token=value",
        "https://scanner.example.test#fragment",
        "not-a-url",
    ],
)
def test_normalize_service_url_rejects_unsafe_or_non_origin_urls(value: str) -> None:
    with pytest.raises(ValueError, match="HTTPS origin"):
        normalize_service_url(value)


def test_build_manifest_rejects_unknown_policy_values() -> None:
    with pytest.raises(ValueError, match="block_on"):
        build_manifest(service_url="https://scanner.example.test", block_on="clean")
    with pytest.raises(ValueError, match="on_error"):
        build_manifest(service_url="https://scanner.example.test", on_error="retry")


def test_main_writes_the_manifest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output = tmp_path / "plugin-configuration.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "render_multiforum_configuration.py",
            "--service-url",
            "https://scanner.example.test/",
            "--output",
            str(output),
        ],
    )

    assert main() == 0
    rendered = json.loads(output.read_text(encoding="utf-8"))
    assert rendered["plugins"][0]["settingsJson"] == {
        "serviceUrl": "https://scanner.example.test",
        "blockOn": "malicious",
        "onError": "block",
        "policy": {},
    }
