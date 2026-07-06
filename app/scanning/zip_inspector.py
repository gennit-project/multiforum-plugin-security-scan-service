"""Static analysis of ZIP archives.

This is the "download docs" half of the roadmap: when a forum accepts uploaded
ZIP bundles we want to catch three classes of problem without executing
anything:

1. **Disallowed file types** — e.g. an ``.exe`` hiding inside a "wallpaper
   pack". Enforced by extension allow/block lists.
2. **Zip bombs** — a tiny archive that expands to gigabytes. Caught by the
   ratio of declared uncompressed size to compressed size, plus an entry-count
   cap, both read from the central directory (no extraction required).
3. **Missing docs** — the downloads workflow wants a README and/or LICENSE at
   the archive root; their absence can be flagged.

The archive is read straight from bytes via ``zipfile``; nothing is written to
disk and no entry is decompressed.
"""

from __future__ import annotations

import io
import posixpath
import zipfile
from dataclasses import dataclass, field

# File types we treat as dangerous by default (executables, scripts, installers).
DEFAULT_BLOCKED_EXTENSIONS = frozenset(
    {
        "exe", "dll", "scr", "com", "bat", "cmd", "msi", "ps1", "vbs", "js",
        "jar", "app", "sh", "bash", "so", "dylib", "deb", "rpm", "apk",
    }
)

README_STEMS = ("readme",)
LICENSE_STEMS = ("license", "licence", "copying")


@dataclass
class ZipFinding:
    code: str
    message: str


@dataclass
class ZipAnalysis:
    is_zip: bool
    entry_count: int = 0
    total_uncompressed: int = 0
    total_compressed: int = 0
    max_ratio: float = 0.0
    has_readme: bool = False
    has_license: bool = False
    findings: list[ZipFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings


def _extension(name: str) -> str:
    base = posixpath.basename(name)
    _, _, ext = base.rpartition(".")
    return ext.lower() if "." in base else ""


def _is_root_doc(name: str, stems: tuple[str, ...]) -> bool:
    """True if ``name`` is a documentation file at the archive root.

    Matches ``README``, ``README.md``, ``LICENSE.txt`` etc., but not
    ``docs/README.md`` — the downloads workflow wants them at the top level.
    """
    if "/" in name.strip("/"):
        return False
    stem = posixpath.basename(name).split(".", 1)[0].lower()
    return stem in stems


def analyze_zip_bytes(
    content: bytes,
    *,
    blocked_extensions: frozenset[str] | set[str] | None = None,
    allowed_extensions: set[str] | None = None,
    max_decompression_ratio: float,
    max_entries: int,
    require_readme: bool,
    require_license: bool,
) -> ZipAnalysis:
    """Inspect ``content`` as a ZIP archive and return findings.

    ``blocked_extensions=None`` uses the built-in dangerous-type list; pass an
    explicit (possibly empty) set to override it. ``allowed_extensions`` is an
    optional strict allow-list applied on top of the block list.
    """
    if not zipfile.is_zipfile(io.BytesIO(content)):
        return ZipAnalysis(is_zip=False)

    blocked = (
        DEFAULT_BLOCKED_EXTENSIONS if blocked_extensions is None else set(blocked_extensions)
    )
    allowed = {e.lower() for e in allowed_extensions} if allowed_extensions else None

    analysis = ZipAnalysis(is_zip=True)

    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        infos = zf.infolist()
        analysis.entry_count = len(infos)

        if len(infos) > max_entries:
            analysis.findings.append(
                ZipFinding(
                    "too_many_entries",
                    f"Archive has {len(infos)} entries (limit {max_entries}).",
                )
            )

        for info in infos:
            name = info.filename
            if info.is_dir():
                continue

            analysis.total_uncompressed += info.file_size
            analysis.total_compressed += info.compress_size

            # Path traversal via a crafted entry name (e.g. "../../etc/x").
            normalized = posixpath.normpath(name)
            if normalized.startswith("..") or normalized.startswith("/"):
                analysis.findings.append(
                    ZipFinding("path_traversal", f"Unsafe entry path: {name!r}.")
                )

            ext = _extension(name)
            if ext and ext in blocked:
                analysis.findings.append(
                    ZipFinding("blocked_type", f"Disallowed file type: {name!r} (.{ext}).")
                )
            elif allowed is not None and ext not in allowed:
                analysis.findings.append(
                    ZipFinding(
                        "not_in_allow_list",
                        f"File type not in allow-list: {name!r} (.{ext or 'none'}).",
                    )
                )

            # Per-entry decompression ratio (the zip-bomb signal).
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                analysis.max_ratio = max(analysis.max_ratio, ratio)
                if ratio > max_decompression_ratio:
                    analysis.findings.append(
                        ZipFinding(
                            "zip_bomb",
                            f"Entry {name!r} expands {ratio:.0f}x "
                            f"(limit {max_decompression_ratio:.0f}x).",
                        )
                    )

            if _is_root_doc(name, README_STEMS):
                analysis.has_readme = True
            if _is_root_doc(name, LICENSE_STEMS):
                analysis.has_license = True

    if require_readme and not analysis.has_readme:
        analysis.findings.append(
            ZipFinding("missing_readme", "Archive has no README at its root.")
        )
    if require_license and not analysis.has_license:
        analysis.findings.append(
            ZipFinding("missing_license", "Archive has no LICENSE at its root.")
        )

    return analysis
