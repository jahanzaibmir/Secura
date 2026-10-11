#!/usr/bin/env python3
"""Secura build verifier — structure, version markers, syntax, imports, env.

Usage: python scripts/verify_build.py [path-to-project-root]
Exit code 0 = assembly verified. Read-only.
"""
import importlib
import importlib.util
import py_compile
import shutil
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()

FILES = """\
.streamlit/config.toml
.gitignore
README.md
requirements.txt
run_secura.py
backend/__init__.py
backend/config.py
backend/exceptions.py
backend/main.py
backend/ai/__init__.py
backend/ai/analyzer.py
backend/ai/knowledge.py
backend/ai/prompts.py
backend/api/__init__.py
backend/api/schemas.py
backend/api/routes/__init__.py
backend/api/routes/health.py
backend/api/routes/reports.py
backend/api/routes/scan.py
backend/core/__init__.py
backend/core/context.py
backend/core/jobs.py
backend/core/logger.py
backend/core/pipeline.py
backend/core/registry.py
backend/core/validators.py
backend/scanners/__init__.py
backend/scanners/base.py
backend/scanners/code_scanner.py
backend/scanners/domain_scanner.py
backend/scanners/ip_scanner.py
backend/scanners/url_scanner.py
backend/scanners/utils/__init__.py
backend/scanners/utils/cve_lookup.py
backend/scanners/utils/git_handler.py
backend/scanners/utils/http_client.py
backend/scanners/utils/port_scanner.py
backend/scanners/utils/ssl_checker.py
backend/storage/__init__.py
backend/storage/report_export.py
backend/storage/report_store.py
scripts/setup.sh
tests/__init__.py
tests/test_analyzer.py
tests/test_pipeline.py
tests/test_scanners.py
tests/test_validators.py
ui/__init__.py
ui/api_client.py
ui/secura_app.py
ui/assets/secura_style.css
ui/theme.py
ui/components/__init__.py
ui/components/secura_hero.py
ui/components/secura_history.py
ui/components/secura_report_view.py
ui/components/secura_target_input.py
""".split()

MARKERS = [
    ("backend/config.py", "max_ai_findings"),
    ("backend/api/schemas.py", "analysis_source"),
    ("backend/core/pipeline.py", "fallback_explanation"),
    ("backend/ai/analyzer.py", "_parse_sections"),
    ("backend/api/routes/health.py", "ai_ready"),
    ("backend/api/routes/reports.py", "report_export"),
    ("backend/storage/report_store.py", "critical=report.summary.critical"),
    ("ui/api_client.py", "fetch_report_file"),
    ("ui/components/secura_report_view.py", "_source_tag"),
    ("ui/secura_app.py", "render_history"),
    ("ui/assets/secura_style.css", ".vw-hero"),
    ("ui/assets/secura_style.css", ".vw-src"),
    ("backend/scanners/__init__.py", "importlib"),
    ("backend/scanners/base.py", "add_note"),
    ("backend/scanners/url_scanner.py", "_SQL_SIGNATURES"),
    ("backend/scanners/utils/port_scanner.py", "_DANGEROUS_PORTS"),
    ("backend/scanners/utils/cve_lookup.py", "vsftpd"),
]

PACKAGES = ("fastapi", "uvicorn", "pydantic", "requests", "git", "nmap",
            "dns", "cryptography", "streamlit", "bandit", "pytest")

problems = []

if not (ROOT / "backend").is_dir():
    print("This is not a Secura project root (no backend/).")
    sys.exit(2)

missing = [p for p in FILES if not (ROOT / p).is_file()]
print(f"[1] STRUCTURE — {len(FILES) - len(missing)}/{len(FILES)} expected files present")
for p in missing:
    print(f"    [MISS] {p}")
    problems.append(f"missing file: {p}")

print("[2] VERSION MARKERS — stale-copy detector")
for path, snippet in MARKERS:
    file = ROOT / path
    if not file.is_file():
        continue  # already reported missing
    try:
        text = file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        print(f"    [FAIL] {path}: unreadable")
        problems.append(f"unreadable: {path}")
        continue
    if snippet in text:
        print(f"    [ OK ] {path}")
    else:
        print(f"    [STALE] {path} — old version (missing '{snippet}'), re-paste final")
        problems.append(f"stale file: {path}")

print("[3] SYNTAX")
bad = []
for p in [f for f in FILES if f.endswith(".py")]:
    try:
        py_compile.compile(str(ROOT / p), doraise=True)
    except py_compile.PyCompileError as exc:
        print(f"    [FAIL] {p}: {exc}")
        bad.append(p)
if not bad:
    print("    [ OK ] every Python file compiles")
else:
    problems.extend(f"syntax error: {p}" for p in bad)

print("[4] IMPORT SMOKE TEST")
sys.path.insert(0, str(ROOT))
for module in ("backend.main", "ui.app"):
    try:
        importlib.import_module(module)
        print(f"    [ OK ] import {module}")
    except ModuleNotFoundError as exc:
        print(f"    [SKIP] {module} — dependency missing: {exc.name}")
        problems.append(f"dependency missing: {exc.name}")
    except Exception as exc:
        print(f"    [FAIL] {module} — {type(exc).__name__}: {exc}")
        problems.append(f"import error in {module}")

print("[5] ENVIRONMENT")
pkgs = [p for p in PACKAGES if importlib.util.find_spec(p) is None]
if pkgs:
    print(f"    [PIP ] missing: {', '.join(pkgs)}")
    print("           fix: pip install -r requirements.txt")
else:
    print("    [ OK ] all Python dependencies installed")
for tool, why in (("git", "GitHub repo scans"), ("nmap", "Domain/IP scans"),
                  ("ollama", "Mistral 7B analysis")):
    found = shutil.which(tool)
    state = "OK " if found else "OFF"
    note = "" if found else "  (optional — degrades gracefully)"
    print(f"    [{state}] {tool:<7} {why}{note}")

print()
if problems:
    print(f"RESULT: {len(problems)} problem(s):")
    for p in problems:
        print(f"    - {p}")
    sys.exit(1)
print("RESULT: Assembly verified — complete and current.")
print("        pytest -q   then   python run_secura.py")
