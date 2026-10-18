"""Stored reports: list, read, export and delete."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response, status

from backend.api.dependencies import get_container
from backend.core.container import Container
from backend.schemas import Report, ReportMeta
from backend.storage.exporters import export_report

router = APIRouter(prefix="/reports", tags=["reports"])

_REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"


@router.get("", response_model=list[ReportMeta], summary="Stored reports, newest first")
def list_reports(
    limit: int | None = Query(default=None, ge=1, le=1000),
    container: Container = Depends(get_container),
) -> list[ReportMeta]:
    return container.store.list(limit=limit)


@router.get("/{report_id}", response_model=Report, summary="One full report")
def get_report(report_id: str, container: Container = Depends(get_container)) -> Report:
    return container.store.load(report_id)


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a report")
def delete_report(report_id: str, container: Container = Depends(get_container)) -> Response:
    container.store.delete(report_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{report_id}/export", summary="Download a report as json, md, html or sarif")
def export(
    report_id: str,
    format: str = Query(default="json", pattern="^(json|md|html|sarif)$"),
    container: Container = Depends(get_container),
) -> Response:
    content, filename, media_type = export_report(container.store.load(report_id), format)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if format == "html":
        headers["Content-Security-Policy"] = _REPORT_CSP
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/{report_id}/view", summary="Printable HTML report, rendered inline")
def view(report_id: str, container: Container = Depends(get_container)) -> Response:
    content, _, media_type = export_report(container.store.load(report_id), "html")
    return Response(content=content, media_type=media_type, headers={"Content-Security-Policy": _REPORT_CSP})
