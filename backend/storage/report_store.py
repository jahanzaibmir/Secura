"""Report persistence as JSON files, with an in-memory index for fast listings.

Writes are atomic (temp file then rename), ids are validated before touching the
filesystem, and one corrupt file never breaks the listing.
"""
from __future__ import annotations

import builtins
import logging
import os
import re
import tempfile
import threading
from pathlib import Path

from backend.exceptions import ReportNotFound
from backend.schemas import Report, ReportMeta

logger = logging.getLogger("secura.storage")

_ID_RE = re.compile(r"rpt_[a-f0-9]{12}")


class ReportStore:
    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._index: dict[str, tuple[float, ReportMeta]] = {}

    def save(self, report: Report) -> Path:
        path = self._dir / f"{report.report_id}.json"
        payload = report.model_dump_json(indent=2)
        fd, tmp = tempfile.mkstemp(prefix=".rpt_", suffix=".tmp", dir=str(self._dir))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        with self._lock:
            self._index[report.report_id] = (path.stat().st_mtime, ReportMeta.from_report(report))
        return path

    def load(self, report_id: str) -> Report:
        path = self._path(report_id)
        try:
            return Report.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ReportNotFound(f"Report {report_id} is unreadable.") from exc

    def delete(self, report_id: str) -> None:
        path = self._path(report_id)
        path.unlink(missing_ok=True)
        with self._lock:
            self._index.pop(report_id, None)

    def list(self, limit: int | None = None) -> builtins.list[ReportMeta]:
        entries = []
        for path in self._dir.glob("rpt_*.json"):
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            entries.append((mtime, path))
        entries.sort(reverse=True)
        if limit is not None:
            entries = entries[:limit]

        metas: list[ReportMeta] = []
        live = set()
        for mtime, path in entries:
            report_id = path.stem
            live.add(report_id)
            meta = self._cached(report_id, mtime)
            if meta is None:
                meta = self._index_file(report_id, path, mtime)
            if meta is not None:
                metas.append(meta)
        if limit is None:
            with self._lock:
                for stale in set(self._index) - live:
                    self._index.pop(stale, None)
        return metas

    def count(self) -> int:
        return sum(1 for _ in self._dir.glob("rpt_*.json"))

    def _cached(self, report_id: str, mtime: float) -> ReportMeta | None:
        with self._lock:
            hit = self._index.get(report_id)
        if hit is not None and hit[0] == mtime:
            return hit[1]
        return None

    def _index_file(self, report_id: str, path: Path, mtime: float) -> ReportMeta | None:
        try:
            meta = ReportMeta.from_report(Report.model_validate_json(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            logger.warning("Skipping unreadable report file %s", path.name)
            return None
        with self._lock:
            self._index[report_id] = (mtime, meta)
        return meta

    def _path(self, report_id: str) -> Path:
        if not _ID_RE.fullmatch(report_id or ""):
            raise ReportNotFound(f"Invalid report id: {report_id}")
        path = self._dir / f"{report_id}.json"
        if not path.is_file():
            raise ReportNotFound(f"No report found with id {report_id}")
        return path
