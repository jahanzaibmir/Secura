from typing import List

from fastapi import APIRouter, HTTPException, Query, Response

from backend.api.schemas import Report, ReportMeta
from backend.core import context
from backend.exceptions import ReportNotFound
from backend.storage.report_export import export_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("", response_model=List[ReportMeta])
def list_reports() -> List[ReportMeta]:
    return context.store.list_reports()


@router.get("/{report_id}", response_model=Report)
def get_report(report_id: str) -> Report:
    try:
        return context.store.load(report_id)
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    format: str = Query(default="json", pattern="^(json|md|html)$"),
) -> Response:
    try:
        report = context.store.load(report_id)
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    content, filename, media_type = export_report(report, format)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{report_id}/view")
def view_report(report_id: str) -> Response:
    """Inline HTML — open in a browser tab, print to PDF."""
    try:
        report = context.store.load(report_id)
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    content, _, media_type = export_report(report, "html")
    return Response(content=content, media_type=media_type)
