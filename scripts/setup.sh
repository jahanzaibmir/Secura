#!/usr/bin/env bash
# Secura — one-shot environment setup (fresh machine or fresh clone).
# Handles: Python 3.12 via uv when available, dependencies, runtime dirs,
# and a report on optional tools. See PREREQUISITES.md for the full manifest.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Python environment"
PY="python3"
if command -v uv >/dev/null 2>&1; then
    echo "    uv found — creating venv on managed Python 3.12"
    uv venv --python 3.12 .venv
    source .venv/bin/activate
    echo "==> Installing Python dependencies (uv)"
    uv pip install -r requirements.txt
else
    VER="$($PY -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    if [ "$VER" != "3.12" ]; then
        echo "!! System Python is $VER, but the pinned stack expects 3.12"
        echo "!!   Install uv and re-run this script:  sudo pacman -S uv"
        echo "!!   Or install Python 3.12 and create the venv with it."
        echo "!! Continuing anyway — pip may compile from source (slow) or fail."
    fi
    $PY -m venv .venv
    source .venv/bin/activate
    echo "==> Installing Python dependencies (pip)"
    pip install --upgrade pip
    pip install -r requirements.txt
fi

echo "==> Preparing runtime directories"
mkdir -p reports workspace logs

echo "==> Optional tools"
for tool in git nmap ollama; do
    if command -v $tool >/dev/null 2>&1; then
        echo "    [OK ] $tool"
    else
        echo "    [OFF] $tool  (app runs without it — see PREREQUISITES.md)"
    fi
done
if command -v ollama >/dev/null 2>&1; then
    if ! ollama list >/dev/null 2>&1; then
        echo "         ollama installed but not running — start with:  ollama serve"
    elif ollama list 2>/dev/null | grep -q "mistral"; then
        echo "         mistral:7b already present"
    else
        echo "         pulling mistral:7b (~4.1 GB, one time)"
        ollama pull mistral:7b
    fi
fi

echo "==> Done. Launch:"
echo "    source .venv/bin/activate && python run_secura.py"
