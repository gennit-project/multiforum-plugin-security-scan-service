"""Fetch attachment bytes with a hard size cap and compute a digest.

The size cap matters: attachment URLs are attacker-influenced, so we stream the
body and abort as soon as it exceeds ``max_bytes`` instead of trusting the
``Content-Length`` header.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import httpx


class DownloadError(Exception):
    """Raised when an attachment cannot be fetched or is too large."""


class FileTooLargeError(DownloadError):
    pass


@dataclass
class DownloadedFile:
    content: bytes
    sha256: str
    size_bytes: int
    content_type: str | None


async def download_file(
    url: str,
    *,
    max_bytes: int,
    timeout_seconds: float,
    client: httpx.AsyncClient | None = None,
) -> DownloadedFile:
    """Stream ``url`` into memory, aborting if it exceeds ``max_bytes``.

    A caller-supplied ``client`` is used when provided (tests inject one backed
    by a mock transport); otherwise a short-lived client is created.
    """
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True)

    try:
        chunks: list[bytes] = []
        total = 0
        async with client.stream("GET", url) as response:
            if response.status_code >= 400:
                raise DownloadError(
                    f"Attachment fetch failed with HTTP {response.status_code}."
                )
            content_type = response.headers.get("content-type")
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise FileTooLargeError(
                        f"Attachment exceeds the {max_bytes}-byte limit."
                    )
                chunks.append(chunk)
    except httpx.HTTPError as exc:  # network/timeout/connection errors
        raise DownloadError(f"Attachment fetch failed: {exc}") from exc
    finally:
        if owns_client:
            await client.aclose()

    content = b"".join(chunks)
    return DownloadedFile(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        content_type=content_type,
    )
