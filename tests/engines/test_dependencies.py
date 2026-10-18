import json

import pytest

from backend.core.cancellation import CancelToken
from backend.engines.base import EngineContext
from backend.engines.dependencies import DependencyEngine
from backend.engines.dependencies.cvss import base_score
from backend.engines.dependencies.models import Dependency, version_key
from backend.engines.dependencies.osv import OSVClient, OSVError, parse_advisory
from backend.engines.dependencies.parsers import has_sibling_lock, parse_manifest
from backend.engines.inventory import build_inventory
from backend.schemas import Severity


def _pairs(deps):
    return sorted((d.name, d.version, d.ecosystem) for d in deps)


def test_requirements_parser():
    text = (
        "# pinned\nflask==0.12.2\nrequests[socks]==2.19.0 ; python_version > '3'\n"
        "Django===4.2.1\nnumpy>=1.20\n-r base.txt\n-e .\ngit+https://x/y.git\nurllib3 == 1.26.5  # comment\n"
    )
    deps = parse_manifest("requirements.txt", text)
    assert _pairs(deps) == [("Django", "4.2.1", "PyPI"), ("flask", "0.12.2", "PyPI"),
                            ("requests", "2.19.0", "PyPI"), ("urllib3", "1.26.5", "PyPI")]
    assert deps[0].line == 2


def test_python_lockfiles():
    pipfile = json.dumps({"default": {"jinja2": {"version": "==2.10"}}, "develop": {"pytest": {"version": "==7.0.0"}}})
    assert _pairs(parse_manifest("Pipfile.lock", pipfile)) == [("jinja2", "2.10", "PyPI"), ("pytest", "7.0.0", "PyPI")]

    poetry = '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n\n[[package]]\nname = "idna"\nversion = "2.8"\n'
    assert _pairs(parse_manifest("poetry.lock", poetry)) == [("idna", "2.8", "PyPI"), ("urllib3", "1.26.4", "PyPI")]

    uv = ('[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n'
          '[[package]]\nname = "pyyaml"\nversion = "5.3"\nsource = { registry = "https://pypi.org/simple" }\n')
    assert _pairs(parse_manifest("uv.lock", uv)) == [("pyyaml", "5.3", "PyPI")]


def test_node_lockfiles():
    v3 = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/lodash": {"version": "4.17.4"},
        "node_modules/@babel/core": {"version": "7.0.0"},
        "node_modules/a/node_modules/minimist": {"version": "0.0.8"},
        "node_modules/local": {"link": True},
        "node_modules/gitdep": {"version": "github:user/repo#abc"},
    }})
    assert _pairs(parse_manifest("package-lock.json", v3)) == [
        ("@babel/core", "7.0.0", "npm"), ("lodash", "4.17.4", "npm"), ("minimist", "0.0.8", "npm")]

    v1 = json.dumps({"lockfileVersion": 1, "dependencies": {
        "express": {"version": "4.16.0", "dependencies": {"qs": {"version": "6.5.1"}}}}})
    assert _pairs(parse_manifest("package-lock.json", v1)) == [("express", "4.16.0", "npm"), ("qs", "6.5.1", "npm")]

    yarn_v1 = ('# yarn lockfile v1\n\n"@types/node@^12.0.0", "@types/node@^12.1.0":\n  version "12.20.1"\n'
               '  resolved "https://x"\n\nlodash@^4.17.4:\n  version "4.17.4"\n')
    assert _pairs(parse_manifest("yarn.lock", yarn_v1)) == [("@types/node", "12.20.1", "npm"), ("lodash", "4.17.4", "npm")]

    berry = '__metadata:\n  version: 6\n\n"minimist@npm:^1.2.0":\n  version: 1.2.5\n  resolution: "minimist@npm:1.2.5"\n'
    assert _pairs(parse_manifest("yarn.lock", berry)) == [("minimist", "1.2.5", "npm")]

    pnpm = "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.20:\n    resolution: {integrity: x}\n" \
           "  '@scope/pkg@1.0.0':\n    resolution: {}\n\nsnapshots:\n\n  lodash@4.17.20: {}\n"
    assert _pairs(parse_manifest("pnpm-lock.yaml", pnpm)) == [("@scope/pkg", "1.0.0", "npm"), ("lodash", "4.17.20", "npm")]

    package = json.dumps({"dependencies": {"left-pad": "1.3.0", "react": "^18.0.0"}, "devDependencies": {"jest": "=29.0.0"}})
    assert _pairs(parse_manifest("package.json", package)) == [("jest", "29.0.0", "npm"), ("left-pad", "1.3.0", "npm")]


def test_other_ecosystems():
    go = "github.com/gin-gonic/gin v1.6.0 h1:abc\ngithub.com/gin-gonic/gin v1.6.0/go.mod h1:def\n" \
         "golang.org/x/text v0.3.0+incompatible h1:x\n"
    assert _pairs(parse_manifest("go.sum", go)) == [("github.com/gin-gonic/gin", "1.6.0", "Go"),
                                                    ("golang.org/x/text", "0.3.0", "Go")]
    cargo = ('[[package]]\nname = "smallvec"\nversion = "0.6.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
             '[[package]]\nname = "local"\nversion = "0.1.0"\n')
    assert _pairs(parse_manifest("Cargo.lock", cargo)) == [("smallvec", "0.6.9", "crates.io")]
    gems = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.0.1)\n      json (>= 1.0)\n    nokogiri (1.10.0)\n\nPLATFORMS\n"
    assert _pairs(parse_manifest("Gemfile.lock", gems)) == [("nokogiri", "1.10.0", "RubyGems"), ("rack", "2.0.1", "RubyGems")]
    composer = json.dumps({"packages": [{"name": "guzzlehttp/guzzle", "version": "v6.3.0"}], "packages-dev": []})
    assert _pairs(parse_manifest("composer.lock", composer)) == [("guzzlehttp/guzzle", "6.3.0", "Packagist")]


def test_unparseable_manifests_are_tolerated():
    assert parse_manifest("package-lock.json", "{broken") == []
    assert parse_manifest("README.md", "flask==1.0") == []


def test_sibling_lockfile_detection():
    paths = ["web/package.json", "web/package-lock.json", "api/package.json"]
    assert has_sibling_lock("web/package.json", paths)
    assert not has_sibling_lock("api/package.json", paths)


@pytest.mark.parametrize("vector, score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss_base_scores(vector, score):
    assert base_score(vector) == score


def test_cvss_rejects_other_versions():
    assert base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    assert base_score("CVSS:3.1/AV:N") is None


def test_version_ordering():
    assert version_key("1.10.0") > version_key("1.9.9")
    assert version_key("v2.0.0") == version_key("2.0.0")
    assert version_key("1.0.10") > version_key("1.0.9")
    assert sorted(["2.0", "10.1", "1.9.1"], key=version_key) == ["1.9.1", "2.0", "10.1"]


OSV_GHSA = {
    "id": "GHSA-462w-v97r-4m45",
    "summary": "Jinja2 sandbox escape via string formatting",
    "aliases": ["CVE-2019-10906", "PYSEC-2019-217"],
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-693"]},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"}],
    "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906"}],
}
OSV_PYSEC = {
    "id": "PYSEC-2019-217", "details": "Duplicate record.", "aliases": ["CVE-2019-10906", "GHSA-462w-v97r-4m45"],
    "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
}


def test_parse_advisory():
    advisory = parse_advisory(OSV_GHSA)
    assert advisory.severity == Severity.HIGH
    assert advisory.display_id == "CVE-2019-10906"
    assert advisory.cvss_score == 8.6 and advisory.cwe == "CWE-693"
    assert advisory.references[0] == "https://osv.dev/vulnerability/GHSA-462w-v97r-4m45"
    dependency = Dependency("Jinja2", "2.10", "PyPI", "requirements.txt")
    assert advisory.fixed_for(dependency) == "2.10.1"
    assert advisory.fixed_for(Dependency("jinja2", "3.0.0", "PyPI", "r.txt")) is None

    unlabeled = dict(OSV_GHSA, database_specific={})
    assert parse_advisory(unlabeled).severity == Severity.HIGH
    assert parse_advisory({"id": "X-1"}).severity == Severity.MEDIUM


def _engine_run(make_tree, settings, files):
    root = make_tree(files)
    inventory = build_inventory(root, settings.max_scan_file_bytes)
    context = EngineContext(root=root, inventory=inventory,
                            settings=settings.with_overrides(dependency_audit=True), token=CancelToken())
    return DependencyEngine().run(context)


def test_engine_reports_each_advisory_once(make_tree, settings, monkeypatch):
    queried = []

    def affected(self, deps):
        queried.extend(deps)
        return {i: ["PYSEC-2019-217", "GHSA-462w-v97r-4m45"] for i, d in enumerate(deps) if d.name == "jinja2"}

    def advisories(self, ids, limit=200):
        records = {"GHSA-462w-v97r-4m45": OSV_GHSA, "PYSEC-2019-217": OSV_PYSEC}
        return {vuln_id: parse_advisory(records[vuln_id]) for vuln_id in ids}

    monkeypatch.setattr(OSVClient, "affected", affected)
    monkeypatch.setattr(OSVClient, "advisories", advisories)
    result = _engine_run(make_tree, settings, {
        "requirements.txt": "jinja2==2.10\nrequests==2.31.0\n",
        "web/package.json": json.dumps({"dependencies": {"lodash": "4.17.4"}}),
        "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/lodash": {"version": "4.17.4"}}}),
    })
    assert len(queried) == 3
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "CVE-2019-10906" and finding.severity == Severity.HIGH
    assert finding.metadata["fixed_version"] == "2.10.1"
    assert finding.file_path == "requirements.txt" and finding.line == 1
    assert "Upgrade to 2.10.1" in finding.description
    assert result.detail == "3 package(s), 1 vulnerable"


def test_engine_degrades_gracefully(make_tree, settings, monkeypatch):
    def unreachable(self, deps):
        raise OSVError("OSV is unreachable: ConnectionError")

    monkeypatch.setattr(OSVClient, "affected", unreachable)
    result = _engine_run(make_tree, settings, {"requirements.txt": "flask==0.12.2\n"})
    assert result.findings == [] and "Dependency audit skipped" in result.notes[0]

    result = _engine_run(make_tree, settings, {"requirements.txt": "flask>=1.0\n"})
    assert "none pin exact versions" in result.notes[0]


def test_engine_is_unavailable_when_disabled(settings):
    available, reason = DependencyEngine().availability(settings)
    assert not available and "SECURA_DEPENDENCY_AUDIT" in reason
