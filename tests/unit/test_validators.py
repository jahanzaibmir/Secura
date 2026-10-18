import pytest

from backend.core.validators import validate_directory, validate_github_repo, validate_target
from backend.exceptions import ValidationError
from backend.schemas import TargetType

CANONICAL = "https://github.com/psf/requests"


@pytest.mark.parametrize("raw", [
    "https://github.com/psf/requests",
    "https://github.com/psf/requests/",
    "https://github.com/psf/requests.git",
    "http://www.github.com/psf/requests",
    "github.com/psf/requests",
    "psf/requests",
    "git@github.com:psf/requests.git",
    "https://github.com/psf/requests/tree/main/src",
    "  https://github.com/psf/requests  ",
])
def test_github_inputs_are_normalised(raw):
    assert validate_github_repo(raw) == CANONICAL


@pytest.mark.parametrize("raw", [
    "",
    "https://gitlab.com/psf/requests",
    "https://github.com/only-owner",
    "https://user:secret@github.com/psf/requests",
    "https://github.com:8443/psf/requests",
    "ftp://github.com/psf/requests",
    "https://evilgithub.com/psf/requests",
    "https://github.com.evil.example/psf/requests",
    "https://github.com/-bad/requests",
    "https://github.com/psf/..",
    "not a repository",
])
def test_invalid_github_inputs_are_rejected(raw):
    with pytest.raises(ValidationError):
        validate_github_repo(raw)


def test_directory_validation(tmp_path):
    with pytest.raises(ValidationError, match="does not exist"):
        validate_directory(str(tmp_path / "missing"))

    file_path = tmp_path / "file.txt"
    file_path.write_text("x")
    with pytest.raises(ValidationError, match="not a folder"):
        validate_directory(str(file_path))

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValidationError, match="empty"):
        validate_directory(str(empty))

    (empty / "a.py").write_text("x = 1")
    assert validate_directory(str(empty)) == str(empty.resolve())


def test_validate_target_dispatches_by_type(tmp_path):
    assert validate_target(TargetType.GITHUB_REPO, "psf/requests") == CANONICAL
    (tmp_path / "a.py").write_text("x = 1")
    assert validate_target(TargetType.UPLOAD, str(tmp_path)) == str(tmp_path.resolve())
