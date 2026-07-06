"""Unit tests for the ZIP static-analysis module."""

from __future__ import annotations

from app.scanning.zip_inspector import analyze_zip_bytes

from .fixtures import make_zip, make_zip_bomb

DEFAULTS = dict(
    max_decompression_ratio=100.0,
    max_entries=1000,
    require_readme=False,
    require_license=False,
)


def test_non_zip_bytes_reported_as_not_zip():
    result = analyze_zip_bytes(b"not a zip at all", **DEFAULTS)
    assert result.is_zip is False


def test_clean_zip_passes():
    content = make_zip({"art/wallpaper.png": b"\x89PNG data", "notes.txt": b"hi"})
    result = analyze_zip_bytes(content, **DEFAULTS)
    assert result.ok is True


def test_blocked_executable_is_flagged():
    content = make_zip({"installer.exe": b"MZ..."})
    result = analyze_zip_bytes(content, **DEFAULTS)
    assert any(f.code == "blocked_type" for f in result.findings)


def test_allow_list_rejects_unlisted_extension():
    content = make_zip({"model.blend": b"blob"})
    result = analyze_zip_bytes(content, allowed_extensions={"png", "txt"}, **DEFAULTS)
    assert any(f.code == "not_in_allow_list" for f in result.findings)


def test_zip_bomb_exceeds_ratio():
    result = analyze_zip_bytes(make_zip_bomb(), **DEFAULTS)
    assert any(f.code == "zip_bomb" for f in result.findings)


def test_entry_count_cap():
    content = make_zip({f"f{i}.txt": b"x" for i in range(50)})
    result = analyze_zip_bytes(content, **{**DEFAULTS, "max_entries": 10})
    assert any(f.code == "too_many_entries" for f in result.findings)


def test_path_traversal_entry_flagged():
    content = make_zip({"../../etc/passwd": b"root:x:0:0"})
    result = analyze_zip_bytes(content, **DEFAULTS)
    assert any(f.code == "path_traversal" for f in result.findings)


def test_root_readme_detected():
    content = make_zip({"README.md": b"# hi", "main.txt": b"x"})
    result = analyze_zip_bytes(content, **DEFAULTS)
    assert result.has_readme is True


def test_nested_readme_not_counted_as_root():
    content = make_zip({"docs/README.md": b"# hi"})
    result = analyze_zip_bytes(content, **DEFAULTS)
    assert result.has_readme is False


def test_require_readme_flags_missing():
    content = make_zip({"main.txt": b"x"})
    result = analyze_zip_bytes(content, **{**DEFAULTS, "require_readme": True})
    assert any(f.code == "missing_readme" for f in result.findings)


def test_require_license_flags_missing():
    content = make_zip({"README.md": b"# hi"})
    result = analyze_zip_bytes(content, **{**DEFAULTS, "require_license": True})
    assert any(f.code == "missing_license" for f in result.findings)


def test_license_variant_spelling_detected():
    content = make_zip({"LICENCE": b"MIT"})
    result = analyze_zip_bytes(content, **DEFAULTS)
    assert result.has_license is True
