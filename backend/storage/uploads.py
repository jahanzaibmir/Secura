"""Materialises uploaded files or a zip archive into a private workspace folder.

Every client-supplied path is sanitised: traversal and absolute paths are rejected,
excluded directories are never written, only files relevant to a scan are kept,
and hard limits bound file count, per-file size and total size, including the
uncompressed size of archive members.
"""
from __future__ import annotations

import io
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from backend.config import Settings
from backend.engines.inventory import is_relevant_path
from backend.exceptions import ValidationError
from backend.storage.workspace import create_workdir, remove_tree

_CHUNK = 64 * 1024


@dataclass
class UploadResult:
    root: Path
    written: int
    skipped: int
    total_bytes: int


def sanitize_rel_path(raw: str) -> str | None:
    """Normalises a client-supplied relative path. None means the file is skipped."""
    if not raw or "\x00" in raw:
        return None
    parts = [p for p in raw.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts or ":" in parts[0]:
        return None
    rel = "/".join(parts)
    return rel if is_relevant_path(rel) else None


def sanitize_label(raw: str) -> str:
    cleaned = "".join(c for c in (raw or "").strip() if c.isalnum() or c in "._- ")
    return cleaned.strip(". ")[:60] or "upload"


class _Writer:
    def __init__(self, root: Path, settings: Settings) -> None:
        self.root = root
        self.settings = settings
        self.written = 0
        self.skipped = 0
        self.total = 0

    def write(self, raw_path: str, stream: BinaryIO) -> None:
        rel = sanitize_rel_path(raw_path)
        if rel is None:
            self.skipped += 1
            return
        if self.written >= self.settings.upload_max_files:
            raise ValidationError(f"Too many files; the limit is {self.settings.upload_max_files}.")
        target = self.root.joinpath(*PurePosixPath(rel).parts)
        if not target.resolve().is_relative_to(self.root.resolve()):
            self.skipped += 1
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        size = 0
        with open(target, "wb") as out:
            while True:
                chunk = stream.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                self.total += len(chunk)
                if size > self.settings.upload_max_file_bytes:
                    limit_mb = self.settings.upload_max_file_bytes // (1024 * 1024)
                    raise ValidationError(f"'{rel}' exceeds the {limit_mb} MB per-file limit.")
                if self.total > self.settings.upload_max_total_bytes:
                    limit_mb = self.settings.upload_max_total_bytes // (1024 * 1024)
                    raise ValidationError(f"The upload exceeds the {limit_mb} MB total limit.")
                out.write(chunk)
        self.written += 1


def _strip_common_root(names: Iterable[str]) -> str:
    """Returns the single top-level folder shared by every archive member, if any."""
    tops = {PurePosixPath(n.replace("\\", "/")).parts[0] for n in names if n.strip("/")}
    return next(iter(tops)) if len(tops) == 1 else ""


def materialize_files(files: Iterable[tuple[str, BinaryIO]], settings: Settings) -> UploadResult:
    root = create_workdir(settings.workspace_dir, "upload_")
    writer = _Writer(root, settings)
    try:
        for raw_path, stream in files:
            writer.write(raw_path, stream)
        return _finish(writer)
    except BaseException:
        remove_tree(root)
        raise


def materialize_archive(stream: BinaryIO, settings: Settings) -> UploadResult:
    data = stream.read(settings.upload_max_total_bytes + 1)
    if len(data) > settings.upload_max_total_bytes:
        raise ValidationError("The archive exceeds the upload size limit.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValidationError("The file is not a valid zip archive.") from exc

    members = [m for m in archive.infolist() if not m.is_dir()]
    declared = sum(m.file_size for m in members)
    if declared > settings.upload_max_total_bytes:
        raise ValidationError("The archive expands beyond the upload size limit.")

    prefix = _strip_common_root(m.filename for m in members)
    root = create_workdir(settings.workspace_dir, "upload_")
    writer = _Writer(root, settings)
    try:
        for member in members:
            if member.flag_bits & 0x1:
                raise ValidationError("Encrypted archives are not supported.")
            if member.external_attr >> 28 == 0xA:
                writer.skipped += 1
                continue
            name = member.filename.replace("\\", "/")
            if prefix and name.startswith(prefix + "/"):
                name = name[len(prefix) + 1:]
            with archive.open(member) as handle:
                writer.write(name, handle)
        return _finish(writer)
    except BaseException:
        remove_tree(root)
        raise


def _finish(writer: _Writer) -> UploadResult:
    if writer.written == 0:
        raise ValidationError(
            "No scannable files were found. Secura reads source code, configuration, "
            "lockfiles and Dockerfiles.")
    return UploadResult(writer.root, writer.written, writer.skipped, writer.total)
