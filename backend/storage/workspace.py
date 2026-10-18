"""Temporary working directories for clones and uploads."""
from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path


def create_workdir(root: Path, prefix: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(root)))


def _force_remove(func, path, _exc) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def remove_tree(path: Path) -> None:
    """Deletes a directory tree, tolerating read-only files such as git packfiles."""
    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_force_remove)
    else:
        shutil.rmtree(path, onerror=_force_remove)
