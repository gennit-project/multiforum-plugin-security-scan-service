"""Helpers for building in-memory ZIP archives used across tests."""

from __future__ import annotations

import io
import zipfile


def make_zip(entries: dict[str, bytes], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    """Build a ZIP archive from ``{name: bytes}`` and return its bytes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def make_zip_bomb(*, uncompressed_size: int = 5_000_000) -> bytes:
    """A tiny archive that decompresses to a large, highly compressible payload."""
    return make_zip({"bomb.txt": b"0" * uncompressed_size})
