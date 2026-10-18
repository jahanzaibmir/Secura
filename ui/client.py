"""Typed HTTP client: the interface's only door to the backend."""
from __future__ import annotations

from typing import Any

import requests

from backend.schemas import (
    AISettingsResponse,
    HealthResponse,
    JobView,
    Report,
    ReportMeta,
    ScanAccepted,
)


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class SecuraClient:
    def __init__(self, base_url: str, timeout: int = 20) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "secura-ui"

    def _request(self, method: str, path: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
        try:
            response = self._session.request(
                method, f"{self.base_url}{path}", timeout=timeout or self.timeout, **kwargs,
            )
        except requests.ConnectionError as exc:
            raise ApiError(0, "The Secura backend is not reachable.") from exc
        except requests.Timeout as exc:
            raise ApiError(0, "The Secura backend took too long to respond.") from exc
        except requests.RequestException as exc:
            raise ApiError(0, f"Request failed: {exc.__class__.__name__}") from exc
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail") or response.text
            except ValueError:
                detail = response.text or f"HTTP {response.status_code}"
            raise ApiError(response.status_code, str(detail)[:500])
        return response

    def health(self) -> HealthResponse:
        return HealthResponse.model_validate(self._request("GET", "/api/health", timeout=8).json())

    def list_scans(self) -> list[JobView]:
        return [JobView.model_validate(item) for item in self._request("GET", "/api/scans").json()]

    def get_scan(self, job_id: str) -> JobView:
        return JobView.model_validate(self._request("GET", f"/api/scans/{job_id}").json())

    def start_scan(self, target: str, target_type: str = "github_repo") -> ScanAccepted:
        response = self._request("POST", "/api/scans", json={"target_type": target_type, "target": target})
        return ScanAccepted.model_validate(response.json())

    def cancel_scan(self, job_id: str) -> JobView:
        return JobView.model_validate(self._request("POST", f"/api/scans/{job_id}/cancel").json())

    def upload_archive(self, name: str, filename: str, payload: bytes) -> ScanAccepted:
        response = self._request(
            "POST", "/api/scans/upload", timeout=300,
            files={"archive": (filename, payload, "application/zip")},
            data={"name": name},
        )
        return ScanAccepted.model_validate(response.json())

    def list_reports(self, limit: int | None = None) -> list[ReportMeta]:
        params = {"limit": limit} if limit else None
        return [ReportMeta.model_validate(item) for item in self._request("GET", "/api/reports", params=params).json()]

    def get_report(self, report_id: str) -> Report:
        return Report.model_validate(self._request("GET", f"/api/reports/{report_id}").json())

    def delete_report(self, report_id: str) -> None:
        self._request("DELETE", f"/api/reports/{report_id}")

    def export_report(self, report_id: str, fmt: str) -> bytes:
        return self._request("GET", f"/api/reports/{report_id}/export", params={"format": fmt}).content

    def ai_settings(self) -> AISettingsResponse:
        return AISettingsResponse.model_validate(self._request("GET", "/api/settings/ai").json())

    def connect_key(self, api_key: str) -> AISettingsResponse:
        response = self._request("POST", "/api/settings/ai/key", json={"api_key": api_key}, timeout=120)
        return AISettingsResponse.model_validate(response.json())

    def update_ai(self, provider: str, api_base: str = "", api_key: str = "", model: str = "") -> AISettingsResponse:
        response = self._request(
            "PUT", "/api/settings/ai", timeout=60,
            json={"provider": provider, "api_base": api_base, "api_key": api_key, "model": model},
        )
        return AISettingsResponse.model_validate(response.json())
