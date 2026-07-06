"""API-key authentication.

The plugin shim sends the shared secret in the ``X-API-Key`` header. We compare
it with a constant-time check to avoid leaking the key through timing. When no
key is configured (``SCAN_API_KEY`` empty) auth is disabled — intended only for
local development, never production.
"""

from __future__ import annotations

import secrets

from fastapi import Depends, Header, HTTPException, status

from .config import Settings, get_settings


async def require_api_key(
    x_api_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    expected = settings.api_key
    if not expected:
        # Auth disabled (local dev). Let the request through.
        return

    if x_api_key is None or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
