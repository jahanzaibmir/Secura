import os

import pytest

from backend.engines.inventory import (
    build_inventory,
    classify,
    is_relevant_path,
    is_test_path,
    looks_minified,
)


@pytest.mark.parametrize("path, kind", [
    ("app.py", "Python"),
    ("src/index.tsx", "TypeScript"),
    ("web/app.mjs", "JavaScript"),
    ("Dockerfile", "Dockerfile"),
    ("docker/Dockerfile.prod", "Dockerfile"),
    ("api.dockerfile", "Dockerfile"),
    ("requirements-dev.txt", "Manifest"),
    ("package-lock.json", "Manifest"),
    ("go.sum", "Manifest"),
    (".env", "Credentials"),
    (".env.production", "Credentials"),
    ("config/settings.yaml", "Config"),
    ("logo.png", None),
    ("notes.txt", None),
])
def test_classify(path, kind):
    assert classify(path) == kind


def test_relevance_skips_vendored_and_hidden_directories():
    assert is_relevant_path("src/app.py")
    assert is_relevant_path(".github/workflows/ci.yml")
    assert not is_relevant_path("node_modules/lib/index.js")
    assert not is_relevant_path(".venv/lib/site.py")
    assert not is_relevant_path(".git/config.py")
    assert not is_relevant_path("assets/logo.png")


def test_is_test_path():
    assert is_test_path("tests/test_api.py")
    assert is_test_path("src/__tests__/app.test.ts")
    assert is_test_path("pkg/conftest.py")
    assert not is_test_path("src/contest.py")
    assert not is_test_path("src/app.py")


def test_build_inventory_respects_policy(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')")
    (tmp_path / "src" / "big.js").write_text("x" * 5000)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("eval(x)")
    (tmp_path / "README.md").write_text("# readme")
    secret = tmp_path.parent / "outside-secret.py"
    secret.write_text("TOKEN = 'abc'")
    os.symlink(secret, tmp_path / "src" / "linked.py")

    inventory = build_inventory(tmp_path, max_file_bytes=1000)
    rels = sorted(f.rel for f in inventory.files)
    assert rels == ["src/app.py"]
    assert inventory.skipped == 2
    assert inventory.languages == {"Python": 1}


def test_looks_minified():
    assert looks_minified("var a=1;" * 200)
    assert not looks_minified("const a = 1;\nconst b = 2;\n")
