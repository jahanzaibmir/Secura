import shutil
import subprocess

import pytest

from backend.core.cancellation import CancelToken
from backend.exceptions import SourceError
from backend.schemas import TargetType
from backend.sources import SourceContext, build_source_registry
from backend.sources import github as github_module
from backend.sources.git import _parse_progress, clone_repository, friendly_git_error


def test_progress_parsing_maps_phases_to_fractions():
    label, fraction = _parse_progress("Receiving objects:  50% (10/20), 1.2 MiB | 2 MiB/s")
    assert label == "Receiving objects" and fraction == pytest.approx(0.45)
    assert _parse_progress("Resolving deltas: 100% (5/5), done.")[1] == pytest.approx(0.95)
    assert _parse_progress("Cloning into 'x'...") is None


@pytest.mark.parametrize("stderr, expected", [
    ("fatal: could not read Username for 'https://github.com': terminal prompts disabled", "authentication"),
    ("remote: Repository not found.\nfatal: repository not found", "not found"),
    ("fatal: unable to access 'https://github.com/x/y/': Could not resolve host: github.com", "Cannot reach GitHub"),
    ("fatal: something unusual happened", "git clone failed: fatal: something unusual happened"),
])
def test_git_errors_are_translated(stderr, expected):
    assert expected in friendly_git_error(stderr)


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_local_transport_is_refused(tmp_path):
    origin = tmp_path / "origin"
    origin.mkdir()
    subprocess.run(["git", "init", "-q", str(origin)], check=True)
    (origin / "a.py").write_text("x = 1")
    subprocess.run(["git", "-C", str(origin), "add", "."], check=True)
    subprocess.run(["git", "-C", str(origin), "-c", "user.email=a@b", "-c", "user.name=t",
                    "commit", "-qm", "init"], check=True)
    with pytest.raises(SourceError):
        clone_repository(str(origin), tmp_path / "dest", timeout=30, token=CancelToken())


def test_github_source_always_removes_its_workspace(settings, monkeypatch):
    def failing_clone(url, destination, **kwargs):
        destination.mkdir(parents=True)
        (destination / "partial.py").write_text("x")
        raise SourceError("network down")

    monkeypatch.setattr(github_module, "clone_repository", failing_clone)
    source = build_source_registry().get(TargetType.GITHUB_REPO)
    context = SourceContext(settings=settings, token=CancelToken(), progress=lambda *a: None)
    with pytest.raises(SourceError):
        with source.open("https://github.com/a/b", context):
            pass
    assert list(settings.workspace_dir.iterdir()) == []


def test_github_source_yields_the_clone(settings, monkeypatch):
    def fake_clone(url, destination, **kwargs):
        destination.mkdir(parents=True)
        (destination / "app.py").write_text("x = 1")
        return destination

    monkeypatch.setattr(github_module, "clone_repository", fake_clone)
    source = build_source_registry().get(TargetType.GITHUB_REPO)
    context = SourceContext(settings=settings, token=CancelToken(), progress=lambda *a: None)
    with source.open("https://github.com/a/b", context) as root:
        assert (root / "app.py").exists()
    assert list(settings.workspace_dir.iterdir()) == []
