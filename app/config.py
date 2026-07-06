"""Runtime configuration, loaded from environment variables.

On Cloud Run these are supplied as service environment variables / secrets.
Locally they come from a ``.env`` file (see ``.env.example``).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SCAN_",
        extra="ignore",
    )

    # --- Service auth -------------------------------------------------------
    # Shared secret the plugin must send in the `X-API-Key` header. When empty,
    # auth is disabled (useful for local development only).
    api_key: str = Field(default="", description="Shared secret for X-API-Key")

    # --- VirusTotal ---------------------------------------------------------
    # When empty the VirusTotal check is skipped and reported as "skipped"
    # rather than failing the whole scan.
    virustotal_api_key: str = Field(default="")
    virustotal_base_url: str = Field(default="https://www.virustotal.com/api/v3")
    virustotal_timeout_seconds: float = Field(default=15.0)
    # Number of malicious engine hits at or above which a file is "malicious".
    virustotal_malicious_threshold: int = Field(default=1)

    # --- File download ------------------------------------------------------
    # Hard ceiling on how many bytes we will pull from an attachment URL. Guards
    # against memory exhaustion and gives the zip-bomb check an outer bound.
    max_download_bytes: int = Field(default=100 * 1024 * 1024)  # 100 MiB
    download_timeout_seconds: float = Field(default=30.0)

    # --- ZIP static-analysis policy defaults --------------------------------
    # Overridable per-request via ScanRequest.policy.
    max_decompression_ratio: float = Field(default=100.0)
    max_zip_entries: int = Field(default=10_000)
    require_readme: bool = Field(default=False)
    require_license: bool = Field(default=False)


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance.

    Cached so the env file is parsed once; tests clear the cache when they need
    to inject overrides.
    """
    return Settings()
