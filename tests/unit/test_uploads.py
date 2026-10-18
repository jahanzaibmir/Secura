import io
import stat
import zipfile

import pytest

from backend.exceptions import ValidationError
from backend.storage.uploads import (
    materialize_archive,
    materialize_files,
    sanitize_label,
    sanitize_rel_path,
)


@pytest.mark.parametrize("raw, expected", [
    ("project/src/app.py", "project/src/app.py"),
    ("./a.py", "a.py"),
    ("project\\src\\app.py", "project/src/app.py"),
    ("/etc/passwd.py", "etc/passwd.py"),
    ("../../etc/passwd.py", None),
    ("a/../../b.py", None),
    ("C:/Windows/evil.py", None),
    ("proj/node_modules/x.js", None),
    ("proj/.git/config.py", None),
    ("proj/logo.png", None),
    ("evil\x00.py", None),
    ("", None),
])
def test_sanitize_rel_path(raw, expected):
    assert sanitize_rel_path(raw) == expected


def test_sanitize_label():
    assert sanitize_label("my project!") == "my project"
    assert sanitize_label("../..") == "upload"
    assert len(sanitize_label("x" * 200)) == 60


def test_materialize_files_writes_only_relevant_files(settings):
    files = [
        ("proj/app.py", io.BytesIO(b"print(1)")),
        ("proj/image.png", io.BytesIO(b"\x89PNG")),
        ("../escape.py", io.BytesIO(b"x")),
    ]
    result = materialize_files(files, settings)
    assert result.written == 1 and result.skipped == 2
    assert (result.root / "proj" / "app.py").read_bytes() == b"print(1)"
    assert result.root.is_relative_to(settings.workspace_dir)


def test_materialize_files_enforces_limits(settings):
    small = settings.with_overrides(upload_max_file_bytes=10)
    with pytest.raises(ValidationError, match="per-file"):
        materialize_files([("a.py", io.BytesIO(b"x" * 11))], small)

    tight = settings.with_overrides(upload_max_total_bytes=15)
    with pytest.raises(ValidationError, match="total"):
        materialize_files([("a.py", io.BytesIO(b"x" * 8)), ("b.py", io.BytesIO(b"y" * 8))], tight)

    few = settings.with_overrides(upload_max_files=1)
    with pytest.raises(ValidationError, match="Too many"):
        materialize_files([("a.py", io.BytesIO(b"1")), ("b.py", io.BytesIO(b"2"))], few)

    assert not any(settings.workspace_dir.iterdir())


def test_materialize_files_requires_something_scannable(settings):
    with pytest.raises(ValidationError, match="No scannable files"):
        materialize_files([("logo.png", io.BytesIO(b"x"))], settings)
    assert not any(settings.workspace_dir.iterdir())


def _zip(entries, symlink=None) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "/etc/passwd")
    buffer.seek(0)
    return buffer


def test_materialize_archive_strips_root_and_blocks_escapes(settings):
    archive = _zip({
        "repo-main/app.py": "print(1)",
        "repo-main/src/util.js": "x()",
        "repo-main/../../escape.py": "x",
    }, symlink="repo-main/link.py")
    result = materialize_archive(archive, settings)
    assert (result.root / "app.py").exists()
    assert (result.root / "src" / "util.js").exists()
    assert not (result.root / "link.py").exists()
    assert result.written == 2 and result.skipped == 2


def test_materialize_archive_rejects_bad_input(settings):
    with pytest.raises(ValidationError, match="not a valid zip"):
        materialize_archive(io.BytesIO(b"not a zip"), settings)

    bomb = settings.with_overrides(upload_max_total_bytes=1000)
    with pytest.raises(ValidationError, match="expands beyond"):
        materialize_archive(_zip({"a.py": "x" * 900, "b.py": "y" * 900}), bomb)
