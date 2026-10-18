"""Public GitHub repositories, shallow-cloned into a disposable workspace."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from backend.schemas import TargetType
from backend.sources.base import Source, SourceContext
from backend.sources.git import clone_repository
from backend.storage.workspace import create_workdir, remove_tree


class GitHubSource(Source):
    target_types = (TargetType.GITHUB_REPO,)
    label = "GitHub repository"

    @contextmanager
    def open(self, target: str, context: SourceContext) -> Iterator[Path]:
        workdir = create_workdir(context.settings.workspace_dir, "repo_")
        destination = workdir / "src"
        try:
            context.progress("Cloning repository", 0.0)
            clone_repository(
                target,
                destination,
                timeout=context.settings.git_clone_timeout,
                token=context.token,
                progress=lambda label, fraction: context.progress(label, fraction),
            )
            context.progress("Repository cloned", 1.0)
            yield destination
        finally:
            remove_tree(workdir)
