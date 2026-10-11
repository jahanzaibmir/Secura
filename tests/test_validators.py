import pytest

from backend.api.schemas import TargetType
from backend.core.validators import validate_target
from backend.exceptions import ValidationError


def test_valid_github_url_is_normalized():
    assert validate_target(
        TargetType.GITHUB_REPO, "https://github.com/psf/requests/"
    ) == "https://github.com/psf/requests"


def test_invalid_github_urls_are_rejected():
    for bad in ("github.com/psf/requests", "https://gitlab.com/a/b",
                "https://github.com/only-owner", ""):
        with pytest.raises(ValidationError):
            validate_target(TargetType.GITHUB_REPO, bad)


def test_missing_local_path_is_rejected():
    with pytest.raises(ValidationError):
        validate_target(TargetType.LOCAL_PATH, "/definitely/not/a/real/path/xyz")
