"""Code scanning — Bandit (Python) + pattern checks (JavaScript/TypeScript).

Shared by the GitHub repo scanner and the local codebase scanner.
Bandit is invoked as a subprocess with JSON output — its most stable public
interface — so internal Bandit API changes can never break this pipeline.
"""
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from backend.api.schemas import Finding, Severity, TargetType
from backend.config import settings
from backend.core.registry import registry
from backend.exceptions import ScannerError
from backend.scanners.base import BaseScanner
from backend.scanners.utils.git_handler import clone_repository, remove_tree

logger = logging.getLogger("secura.scanners.code")

_EXCLUDED_DIRS = (".git", ".hg", ".svn", "__pycache__", "node_modules",
                  "venv", ".venv", ".tox", ".nox", "dist", "build",
                  ".eggs", ".mypy_cache", ".pytest_cache", ".idea", ".vscode")

_PY_EXTENSIONS = {".py"}
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_BANDIT_SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
_BANDIT_CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.35}

_EVIDENCE_MAX = 1500

_BANDIT_TYPES = {
    "B101": "Assertion used for control flow",
    "B102": "Use of exec()",
    "B103": "Insecure file permissions",
    "B104": "Binding to all network interfaces (0.0.0.0)",
    "B105": "Hardcoded password (string)",
    "B106": "Hardcoded password (function argument)",
    "B107": "Hardcoded password (default value)",
    "B108": "Insecure temporary file path",
    "B110": "Silent exception handling (try/except/pass)",
    "B112": "Silent exception handling (try/except/continue)",
    "B201": "Flask debug mode enabled",
    "B301": "Insecure deserialization (pickle)",
    "B302": "Insecure deserialization (marshal)",
    "B303": "Weak hash algorithm",
    "B304": "Weak cipher",
    "B305": "Weak cipher mode",
    "B306": "Insecure temporary file (mktemp)",
    "B307": "Use of eval()",
    "B310": "Unvalidated URL open (urllib)",
    "B311": "Non-cryptographic random (random module)",
    "B312": "Telnet client usage",
    "B323": "Unverified SSL context",
    "B324": "Weak hash algorithm (hashlib)",
    "B404": "subprocess imported",
    "B501": "Request without certificate verification",
    "B502": "Weak SSL/TLS version",
    "B503": "Weak SSL/TLS defaults",
    "B504": "No SSL/TLS version specified",
    "B505": "Weak cryptographic key",
    "B506": "Unsafe YAML load",
    "B507": "SSH without host key verification",
    "B601": "Paramiko command execution",
    "B602": "Shell injection (subprocess with shell=True)",
    "B603": "Subprocess without shell — validate arguments",
    "B604": "Shell injection (shell=True with external input)",
    "B605": "Process started with a shell",
    "B606": "Process started without a shell",
    "B607": "Process started with partial path",
    "B608": "Hardcoded SQL expression (SQL injection)",
    "B609": "Wildcard injection in Linux command",
    "B610": "Django extra() query",
    "B611": "Django RawSQL usage",
    "B701": "Jinja2 autoescape disabled",
    "B702": "Mako template usage",
    "B703": "Django mark_safe usage",
}

_JS_PATTERNS = [
    (re.compile(r"\beval\s*\("), "Unsafe eval() in JavaScript", Severity.MEDIUM, 0.6,
     "eval() executes arbitrary strings as code — a classic injection sink."),
    (re.compile(r"\bnew\s+Function\s*\("), "Dynamic code construction (new Function)", Severity.MEDIUM, 0.6,
     "new Function() compiles strings at runtime — the same risks as eval()."),
    (re.compile(r"\.innerHTML\s*=", re.IGNORECASE), "Assignment to innerHTML (DOM XSS sink)", Severity.MEDIUM, 0.5,
     "Assigning raw strings to innerHTML renders them as HTML — use textContent or sanitize."),
    (re.compile(r"\bdocument\.write\s*\(", re.IGNORECASE), "document.write usage (DOM XSS sink)", Severity.MEDIUM, 0.5,
     "document.write parses strings as HTML — a DOM XSS vector."),
    (re.compile(r"dangerouslySetInnerHTML"), "React dangerouslySetInnerHTML usage", Severity.MEDIUM, 0.5,
     "A deliberate raw-HTML injection point in React — must only ever receive sanitized input."),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "Hardcoded private key", Severity.HIGH, 0.9,
     "A private key is committed in source. Rotate it and move it to a secret manager."),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Hardcoded AWS access key ID", Severity.HIGH, 0.85,
     "AWS access key IDs start with AKIA and are 20 characters. Deactivate the key in IAM and rotate."),
]

_JS_SECRET_RE = re.compile(
    r"""(?i)\b(password|passwd|secret|api[_-]?key|apikey|token|auth[_-]?token|access[_-]?key|private[_-]?key)\b\s*[:=]\s*["']([^"']{8,})["']"""
)
_JS_SECRET_PLACEHOLDERS = (
    "changeme", "change_me", "change-me", "example", "xxxx", "password",
    "placeholder", "your_", "todo", "fixme", "dummy", "sample", "test",
    "xxx", "...", "none", "null", "true", "false", "<", "%s", "%d", "${",
)


def _walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in _EXCLUDED_DIRS and not d.startswith(".")]
        for filename in filenames:
            yield Path(dirpath) / filename


def _relative(filename: str, root: Path) -> str:
    try:
        return str(Path(filename).resolve().relative_to(root))
    except ValueError:                       # different drive / unrelated path
        return filename


def _prettify(test_name: str) -> str:
    cleaned = test_name.replace("_", " ").strip()
    return cleaned[:1].upper() + cleaned[1:] if cleaned else "Unknown issue"


def _vulnerability_type(test_id: str, test_name: str) -> str:
    if test_id in _BANDIT_TYPES:
        return _BANDIT_TYPES[test_id]
    lowered = test_name.lower()
    if "xml" in lowered:
        return "XML parsing without XXE hardening"
    if "hashlib" in lowered or "md5" in lowered or "sha1" in lowered:
        return "Weak hash algorithm"
    return _prettify(test_name)


def _parse_json(text: str) -> Optional[dict]:
    text = text.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                parsed = json.loads(text[start:end + 1])
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
        return None


class CodeScannerBase(BaseScanner):
    """Shared implementation: Bandit over Python, patterns over JS/TS."""

    def _count_scannable(self, root: Path) -> Tuple[int, int]:
        py = js = 0
        for path in _walk_files(root):
            suffix = path.suffix.lower()
            if suffix in _PY_EXTENSIONS:
                py += 1
            elif suffix in _JS_EXTENSIONS:
                js += 1
        return py, js

    def scan_directory(self, root: Path) -> List[Finding]:
        root = root.resolve()
        if not root.is_dir():
            raise ScannerError(f"Codebase directory disappeared: {root}")
        py_count, js_count = self._count_scannable(root)
        if py_count == 0 and js_count == 0:
            self.add_note("No Python or JavaScript/TypeScript source files were found — "
                          "nothing to scan.")
            return []
        self.add_note(f"Scanned {py_count} Python file(s) and "
                      f"{js_count} JavaScript/TypeScript file(s).")

        findings: List[Finding] = []
        if py_count:
            self.report_progress(f"Running Bandit over {py_count} Python file(s)", 20)
            findings.extend(self._run_bandit(root))
        if js_count:
            self.report_progress(f"Checking {js_count} JavaScript/TypeScript file(s)", 65)
            findings.extend(self._scan_javascript(root))
        self.report_progress("Code scan complete", 95)
        return findings

    # -- bandit ---------------------------------------------------------------

    def _run_bandit(self, root: Path) -> List[Finding]:
        command = [
            sys.executable, "-m", "bandit",
            "-r", str(root),
            "-f", "json",
            "-q",
            "--exit-zero",
            "-x", ",".join(_EXCLUDED_DIRS),
        ]
        try:
            completed = subprocess.run(
                command, capture_output=True, timeout=settings.bandit_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(
                f"Bandit scan exceeded {settings.bandit_timeout}s — "
                "the codebase may be too large."
            ) from exc
        stdout = completed.stdout.decode("utf-8", errors="replace")
        data = _parse_json(stdout)
        if data is None:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            detail = f": {stderr[:300]}" if stderr else f" (exit code {completed.returncode})."
            raise ScannerError("Bandit output could not be parsed" + detail)

        findings: List[Finding] = []
        for item in data.get("results", []) or []:
            finding = self._bandit_finding(item, root)
            if finding is not None:
                findings.append(finding)
        errors = data.get("errors", []) or []
        if errors:
            sample = errors[0]
            if isinstance(sample, dict):
                sample = sample.get("filename") or sample.get("reason") or str(sample)
            self.add_note(f"Bandit could not parse {len(errors)} file(s) "
                          f"(e.g., {str(sample)[:120]}).")
        return findings

    def _bandit_finding(self, item: dict, root: Path) -> Optional[Finding]:
        try:
            filename = str(item.get("filename", ""))
            rel = _relative(filename, root)
            test_id = str(item.get("test_id", ""))
            test_name = str(item.get("test_name", "unknown"))
            severity = _BANDIT_SEVERITY.get(
                str(item.get("issue_severity", "")).upper(), Severity.LOW)
            confidence = _BANDIT_CONFIDENCE.get(
                str(item.get("issue_confidence", "")).upper(), 0.4)
            if test_id == "B404":  # importing subprocess is a consideration,
                severity = Severity.INFO  # not a flaw — stops noise findings
            line = item.get("line_number", "?")
            code = str(item.get("code", "")).strip()
            issue_text = str(item.get("issue_text", "")).strip()
            cwe = (item.get("issue_cwe") or {}).get("id")
            cwe_part = f" · CWE-{cwe}" if cwe else ""
            evidence = f"[Bandit {test_id}{cwe_part}] {issue_text}\n{code}"[:_EVIDENCE_MAX]
            return Finding(
                vulnerability_type=_vulnerability_type(test_id, test_name),
                location=f"{rel} · line {line}",
                severity=severity,
                confidence=confidence,
                evidence=evidence,
            )
        except Exception:
            logger.exception("Skipping malformed Bandit result")
            return None

    # -- javascript ---------------------------------------------------------------

    def _scan_javascript(self, root: Path) -> List[Finding]:
        findings: List[Finding] = []
        for path in _walk_files(root):
            if path.suffix.lower() not in _JS_EXTENSIONS:
                continue
            rel = _relative(str(path), root)
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if len(raw) > 1_000_000 or b"\x00" in raw[:8192]:
                continue                       # binary or oversized — skip
            if ".min." in path.name:
                continue                       # minified bundles — noise only
            text = raw.decode("utf-8", errors="replace")
            lines = text.splitlines()
            if any(len(line) > 500 for line in lines[:50]):
                continue                       # looks minified — skip

            file_findings = 0
            for lineno, line in enumerate(lines, start=1):
                if file_findings >= 10:
                    self.add_note(f"JavaScript findings for {rel} truncated at 10.")
                    break
                stripped = line.strip()
                if not stripped or len(stripped) > 2000:
                    continue
                for pattern, name, severity, confidence, why in _JS_PATTERNS:
                    if pattern.search(line):
                        findings.append(Finding(
                            vulnerability_type=name,
                            location=f"{rel} · line {lineno}",
                            severity=severity,
                            confidence=confidence,
                            evidence=f"{stripped[:500]}\n{why}",
                        ))
                        file_findings += 1
                        break                  # one pattern finding per line
                secret = _JS_SECRET_RE.search(line)
                if secret:
                    value = secret.group(2)
                    lowered = value.lower()
                    if not any(lowered == p or lowered.startswith(p)
                               for p in _JS_SECRET_PLACEHOLDERS):
                        findings.append(Finding(
                            vulnerability_type="Hardcoded secret in JavaScript",
                            location=f"{rel} · line {lineno}",
                            severity=Severity.MEDIUM,
                            confidence=0.5,
                            evidence=(f"{stripped[:500]}\nA credential-like name is "
                                      "assigned a literal string. If this is a real "
                                      "secret, rotate it and move it to environment "
                                      "configuration."),
                        ))
                        file_findings += 1
        return findings


@registry.register(TargetType.LOCAL_PATH)
class LocalCodeScanner(CodeScannerBase):
    """Scans a folder on this machine."""
    target_type = TargetType.LOCAL_PATH
    name = "local-code"

    def scan(self) -> List[Finding]:
        self.report_progress(f"Preparing to scan {self.target}", 5)
        return self.scan_directory(Path(self.target))


@registry.register(TargetType.GITHUB_REPO)
class GitHubRepoScanner(CodeScannerBase):
    """Shallow-clones a public GitHub repository and scans it."""
    target_type = TargetType.GITHUB_REPO
    name = "github-code"

    def scan(self) -> List[Finding]:
        settings.workspace_dir.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix="vw_repo_", dir=str(settings.workspace_dir)))
        try:
            self.report_progress("Cloning repository (shallow copy)", 5)
            clone_repository(self.target, workdir, timeout=settings.git_clone_timeout)
            self.report_progress("Repository cloned — scanning code", 20)
            return self.scan_directory(workdir)
        finally:
            remove_tree(workdir)               # Windows-safe (read-only packfiles)
