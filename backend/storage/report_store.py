"""Report persistence — JSON files under reports/, path-traversal safe."""
import re
from pathlib import Path
from typing import List

from backend.api.schemas import Report, ReportMeta
from backend.exceptions import ReportNotFound

_ID_RE = re.compile(r"rpt_[a-f0-9]{12}")


class ReportStore:
    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, report: Report) -> Path:
        path = self._dir / f"{report.report_id}.json"
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        return path

    def path_for(self, report_id: str) -> Path:
        if not _ID_RE.fullmatch(report_id):
            raise ReportNotFound(f"Invalid report id: {report_id}")
        path = self._dir / f"{report_id}.json"
        if not path.is_file():
            raise ReportNotFound(f"No report found for id: {report_id}")
        return path

    def load(self, report_id: str) -> Report:
        path = self.path_for(report_id)
        return Report.model_validate_json(path.read_text(encoding="utf-8"))

    def list_reports(self) -> List[ReportMeta]:
        metas: List[ReportMeta] = []
        paths = sorted(
            self._dir.glob("rpt_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for path in paths:
            try:
                report = Report.model_validate_json(path.read_text(encoding="utf-8"))
            except Exception:
                continue  # never let one corrupt file break the listing
            metas.append(
                ReportMeta(
                    report_id=report.report_id,
                    target=report.target,
                    target_type=report.target_type,
                    finished_at=report.finished_at,
                    total_findings=report.summary.total,
                    critical=report.summary.critical,
                    high=report.summary.high,
                    medium=report.summary.medium,
                    low=report.summary.low,
                )
            )
        return metas
