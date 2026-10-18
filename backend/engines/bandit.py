"""Python static analysis through Bandit.

Bandit runs as a subprocess with JSON output, its most stable public interface,
so internal Bandit API changes can never break the pipeline. Files are passed
explicitly in batches, which keeps the scanned set identical to the inventory
(no symlinks, no vendored directories) and lets cancellation take effect
between batches.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from backend.config import Settings
from backend.core.cancellation import CancelToken
from backend.engines.base import Engine, EngineContext, EngineResult, optional_int
from backend.engines.inventory import Inventory, SourceFile, is_test_path
from backend.engines.rules import bandit as catalog
from backend.exceptions import EngineError, ScanCancelled
from backend.schemas import Finding

logger = logging.getLogger("secura.engines.bandit")

_BATCH_SIZE = 400
_CODE_LINE_RE = re.compile(r"^(\d+)\s?(.*)$")


class BanditEngine(Engine):
    name = "bandit"
    label = "Python SAST"
    description = "Bandit static analysis for Python: injection, unsafe APIs, weak crypto."

    def availability(self, settings: Settings) -> tuple[bool, str]:
        if importlib.util.find_spec("bandit") is None:
            return False, "Bandit is not installed (pip install bandit)."
        return True, ""

    def applies(self, inventory: Inventory) -> bool:
        return bool(inventory.of_kind("Python"))

    def run(self, context: EngineContext) -> EngineResult:
        files = context.inventory.of_kind("Python")
        result = EngineResult()
        errors = 0
        batches = [files[i:i + _BATCH_SIZE] for i in range(0, len(files), _BATCH_SIZE)]
        deadline = time.monotonic() + context.settings.bandit_timeout

        for index, batch in enumerate(batches):
            context.token.raise_if_cancelled()
            context.progress(
                f"{min((index + 1) * _BATCH_SIZE, len(files))}/{len(files)} Python files",
                index / max(1, len(batches)),
            )
            data = self._run_batch(batch, context.token, deadline)
            for item in data.get("results") or []:
                finding = self._to_finding(item, context.root)
                if finding is not None:
                    result.findings.append(finding)
            errors += len(data.get("errors") or [])

        if errors:
            result.notes.append(f"Bandit could not parse {errors} Python file(s); they were skipped.")
        result.detail = f"{len(files)} Python file(s)"
        return result

    def _run_batch(self, batch: list[SourceFile], token: CancelToken, deadline: float) -> dict:
        with tempfile.TemporaryDirectory(prefix="secura_bandit_") as tmp:
            output = Path(tmp) / "bandit.json"
            command = [
                sys.executable, "-m", "bandit", "-f", "json", "-o", str(output),
                "-q", "--exit-zero", *[str(f.path) for f in batch],
            ]
            process = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )
            while True:
                try:
                    _, stderr = process.communicate(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    if token.cancelled:
                        process.kill()
                        process.communicate()
                        raise ScanCancelled("The scan was cancelled.") from None
                    if time.monotonic() > deadline:
                        process.kill()
                        process.communicate()
                        raise EngineError(
                            "Bandit exceeded its time limit; the codebase may be too large.") from None

            data = _load_json(output)
            if data is None:
                detail = (stderr or b"").decode("utf-8", errors="replace").strip()[:300]
                raise EngineError(f"Bandit produced no readable output. {detail}".strip())
            return data

    @staticmethod
    def _to_finding(item: dict, root: Path) -> Finding | None:
        try:
            test_id = str(item.get("test_id", ""))
            rel = _relative(str(item.get("filename", "")), root)
            if test_id in catalog.SKIP_IN_TESTS and is_test_path(rel):
                return None
            raw_severity = str(item.get("issue_severity", ""))
            raw_confidence = str(item.get("issue_confidence", ""))
            cwe = (item.get("issue_cwe") or {}).get("id")
            more_info = item.get("more_info")
            return Finding(
                engine="bandit",
                rule_id=test_id,
                title=catalog.title_for(test_id, str(item.get("test_name", ""))),
                description=str(item.get("issue_text", "")).strip(),
                severity=catalog.severity_for(test_id, raw_severity, raw_confidence),
                confidence=catalog.CONFIDENCE.get(raw_confidence.upper(), 0.4),
                file_path=rel,
                line=optional_int(item.get("line_number")),
                snippet=_clean_code(str(item.get("code", ""))),
                cwe=f"CWE-{cwe}" if cwe else None,
                references=[more_info] if more_info else [],
            )
        except Exception:
            logger.exception("Skipping a malformed Bandit result")
            return None


def _load_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _relative(filename: str, root: Path) -> str:
    try:
        return Path(filename).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(filename).name


def _clean_code(code: str) -> str:
    """Normalises Bandit's numbered excerpt to the shared snippet format."""
    numbered = []
    for raw in code.splitlines():
        match = _CODE_LINE_RE.match(raw.rstrip())
        if match:
            numbered.append((match.group(1), match.group(2)))
    while numbered and not numbered[0][1].strip():
        numbered.pop(0)
    while numbered and not numbered[-1][1].strip():
        numbered.pop()
    if not numbered:
        return code.strip()[:600]
    pad = max(len(number) for number, _ in numbered)
    return "\n".join(f"{number.rjust(pad)}  {text[:240]}" for number, text in numbered[:8])
