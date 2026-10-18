"""Client for the OSV.dev vulnerability database.

Batch queries resolve which dependencies are affected; advisory details are then
fetched in parallel and cached in memory, so repeated scans of similar projects
stay fast and polite to the public API.
"""
from __future__ import annotations

import re
import threading
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import requests

from backend.engines.dependencies.cvss import base_score
from backend.engines.dependencies.models import Dependency, version_key
from backend.schemas import Severity

_BATCH_LIMIT = 500
_DETAIL_WORKERS = 8
_CACHE_TTL = 6 * 3600

_LABELS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


@dataclass
class Advisory:
    vuln_id: str
    summary: str
    severity: Severity
    aliases: list[str] = field(default_factory=list)
    cwe: str | None = None
    cvss_score: float | None = None
    references: list[str] = field(default_factory=list)
    fixed_versions: dict[str, list[str]] = field(default_factory=dict)

    @property
    def display_id(self) -> str:
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return self.vuln_id

    def fixed_for(self, dependency: Dependency) -> str | None:
        candidates = self.fixed_versions.get(dependency.normalized_name.lower(), [])
        current = version_key(dependency.version)
        newer = sorted((v for v in candidates if version_key(v) > current), key=version_key)
        return newer[0] if newer else None


class OSVError(Exception):
    pass


class OSVClient:
    _cache: dict[str, tuple] = {}
    _cache_lock = threading.Lock()

    def __init__(self, base_url: str, timeout: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "Secura security scanner"

    def affected(self, dependencies: Sequence[Dependency]) -> dict[int, list[str]]:
        """Maps each dependency index to the advisory ids that affect it."""
        result: dict[int, list[str]] = {}
        for offset in range(0, len(dependencies), _BATCH_LIMIT):
            chunk = dependencies[offset:offset + _BATCH_LIMIT]
            payload = {"queries": [
                {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                for d in chunk
            ]}
            try:
                response = self._session.post(
                    f"{self.base_url}/v1/querybatch", json=payload, timeout=self.timeout,
                )
            except requests.RequestException as exc:
                raise OSVError(f"OSV is unreachable: {exc.__class__.__name__}") from exc
            if response.status_code != 200:
                raise OSVError(f"OSV returned HTTP {response.status_code}")
            try:
                rows = response.json().get("results") or []
            except ValueError as exc:
                raise OSVError("OSV returned invalid JSON") from exc
            for index, row in enumerate(rows):
                ids = [v.get("id") for v in (row or {}).get("vulns") or [] if v.get("id")]
                if ids:
                    result[offset + index] = ids
        return result

    def advisories(self, vuln_ids: Iterable[str], limit: int = 200) -> dict[str, Advisory]:
        unique = list(dict.fromkeys(vuln_ids))[:limit]
        found: dict[str, Advisory] = {}
        missing: list[str] = []
        now = time.monotonic()
        with self._cache_lock:
            for vuln_id in unique:
                cached = self._cache.get(vuln_id)
                if cached and now - cached[0] < _CACHE_TTL:
                    found[vuln_id] = cached[1]
                else:
                    missing.append(vuln_id)
        if missing:
            with ThreadPoolExecutor(max_workers=_DETAIL_WORKERS) as pool:
                for advisory in pool.map(self._fetch, missing):
                    if advisory is not None:
                        found[advisory.vuln_id] = advisory
                        with self._cache_lock:
                            self._cache[advisory.vuln_id] = (time.monotonic(), advisory)
        return found

    def _fetch(self, vuln_id: str) -> Advisory | None:
        try:
            response = self._session.get(f"{self.base_url}/v1/vulns/{vuln_id}", timeout=self.timeout)
            if response.status_code != 200:
                return None
            return parse_advisory(response.json())
        except (requests.RequestException, ValueError):
            return None


def parse_advisory(data: dict) -> Advisory:
    database = data.get("database_specific") or {}
    severity = _LABELS.get(str(database.get("severity", "")).upper())
    score = None
    for entry in data.get("severity") or []:
        if str(entry.get("type", "")).upper() == "CVSS_V3":
            score = base_score(str(entry.get("score", "")))
            if score is not None:
                break
    if severity is None:
        severity = _severity_from_score(score)

    fixed: dict[str, list[str]] = {}
    for affected in data.get("affected") or []:
        name = str((affected.get("package") or {}).get("name", "")).lower()
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or []:
                if event.get("fixed"):
                    fixed.setdefault(name, []).append(str(event["fixed"]))
        if "-" in name or "_" in name or "." in name:
            fixed.setdefault(_pep503(name), fixed.get(name, []))

    cwe_ids = database.get("cwe_ids") or []
    refs = [r.get("url") for r in data.get("references") or [] if r.get("url")]
    vuln_id = str(data.get("id", ""))
    summary = (data.get("summary") or data.get("details") or "").strip().splitlines()
    return Advisory(
        vuln_id=vuln_id,
        summary=summary[0][:200] if summary else "Known vulnerability",
        severity=severity,
        aliases=[str(a) for a in data.get("aliases") or []],
        cwe=str(cwe_ids[0]) if cwe_ids else None,
        cvss_score=score,
        references=[f"https://osv.dev/vulnerability/{vuln_id}", *refs[:3]],
        fixed_versions=fixed,
    )


def _severity_from_score(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()
