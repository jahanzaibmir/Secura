#!/usr/bin/env bash
# Prepares a development environment: Python 3.12 virtualenv, dependencies, tool check.
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v uv >/dev/null 2>&1; then
    echo "Creating .venv with uv (Python 3.12)"
    uv venv --python 3.12 .venv
    VIRTUAL_ENV=.venv uv pip install -r requirements-dev.txt
else
    PY="${PYTHON:-python3}"
    version="$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    case "$version" in
        3.11|3.12|3.13) ;;
        *) echo "Python $version found; Secura needs 3.11 or newer. Install uv or set PYTHON." >&2; exit 1 ;;
    esac
    echo "Creating .venv with $PY ($version)"
    "$PY" -m venv .venv
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install -r requirements-dev.txt
fi

echo
for tool in git ollama; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "  found    $tool"
    else
        echo "  missing  $tool (optional: git enables GitHub scans, ollama enables local AI)"
    fi
done

echo
echo "Ready. Start Secura with:  .venv/bin/python run_secura.py"
