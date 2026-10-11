"""Typed HTTP client — the UI's only door to the backend."""
from typing import Optional, Tuple

import requests

from backend.api.schemas import (
    AISettingsResponse, JobSummary, JobView, Report, ReportMeta,
    ScanAccepted, ScanRequest,
)


class VulnWeaveClient:
    def __init__(self, base_url: str, timeout: int = 15,
                 public_base: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        # Origin for URLs the BROWSER opens (report links). Behind nginx
        # the app and API share one origin, so this can differ.
        self.public_base = (public_base or base_url).rstrip("/")
        self.timeout = timeout

    def health(self) -> Optional[dict]:
        try:
            response = requests.get(f"{self.base_url}/api/health", timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        except requests.RequestException:
            pass
        return None

    def list_jobs(self) -> list:
        """All recent jobs, newest first — the persistence backbone."""
        try:
            response = requests.get(
                f"{self.base_url}/api/scan", timeout=self.timeout)
            if response.status_code == 200:
                return [JobSummary.model_validate(item)
                        for item in response.json()]
        except (requests.RequestException, ValueError):
            pass
        return []

    def get_ai_settings(self) -> Optional[AISettingsResponse]:
        try:
            response = requests.get(
                f"{self.base_url}/api/settings/ai", timeout=self.timeout)
            if response.status_code == 200:
                return AISettingsResponse.model_validate(response.json())
        except requests.RequestException:
            pass
        return None

    def connect_api_key(
        self, api_key: str,
    ) -> Tuple[Optional[AISettingsResponse], Optional[str]]:
        """Paste-a-key flow. Returns (response, None) or (None, error)."""
        try:
            response = requests.post(
                f"{self.base_url}/api/settings/ai/auto",
                json={"api_key": api_key},
                timeout=90,
            )
            if response.status_code == 200:
                return AISettingsResponse.model_validate(response.json()), None
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            return None, str(detail)[:400]
        except requests.RequestException as exc:
            return None, str(exc)

    def set_ai_settings(
        self, provider: str, api_base: str = "", api_key: str = "",
        model: str = "",
    ) -> Tuple[Optional[AISettingsResponse], Optional[str]]:
        """Manual flow (custom endpoints). (response, None) or (None, error)."""
        try:
            response = requests.post(
                f"{self.base_url}/api/settings/ai",
                json={"provider": provider, "api_base": api_base,
                      "api_key": api_key, "model": model},
                timeout=45,
            )
            if response.status_code == 200:
                return AISettingsResponse.model_validate(response.json()), None
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            return None, str(detail)[:300]
        except requests.RequestException as exc:
            return None, str(exc)

    def start_scan(self, request: ScanRequest) -> Optional[ScanAccepted]:
        try:
            response = requests.post(
                f"{self.base_url}/api/scan",
                json=request.model_dump(mode="json"),
                timeout=self.timeout,
            )
            if response.status_code == 202:
                return ScanAccepted.model_validate(response.json())
        except requests.RequestException:
            pass
        return None

    def get_job(self, job_id: str) -> Optional[JobView]:
        try:
            response = requests.get(
                f"{self.base_url}/api/scan/{job_id}", timeout=self.timeout
            )
            if response.status_code == 200:
                return JobView.model_validate(response.json())
        except requests.RequestException:
            pass
        return None

    def get_report(self, report_id: str) -> Optional[Report]:
        try:
            response = requests.get(
                f"{self.base_url}/api/reports/{report_id}", timeout=self.timeout
            )
            if response.status_code == 200:
                return Report.model_validate(response.json())
        except requests.RequestException:
            pass
        return None

    def list_reports(self) -> list:
        try:
            response = requests.get(f"{self.base_url}/api/reports", timeout=self.timeout)
            if response.status_code == 200:
                return [ReportMeta.model_validate(item) for item in response.json()]
        except (requests.RequestException, ValueError):
            pass
        return []

    def fetch_report_file(self, report_id: str, fmt: str) -> Optional[Tuple[str, str]]:
        """Returns (content, filename) for md/html, or None on failure."""
        try:
            response = requests.get(
                f"{self.base_url}/api/reports/{report_id}/download",
                params={"format": fmt},
                timeout=self.timeout,
            )
            if response.status_code == 200:
                return response.text, f"secura_{report_id}.{fmt}"
        except requests.RequestException:
            pass
        return None

    def report_view_url(self, report_id: str) -> str:
        return f"{self.public_base}/api/reports/{report_id}/view"
