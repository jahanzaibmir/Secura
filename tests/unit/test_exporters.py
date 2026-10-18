import json

import pytest

from backend.exceptions import ValidationError
from backend.schemas import ExplanationSource, Finding, Report, Severity, TargetType, build_summary
from backend.storage.exporters import export_report, to_html, to_markdown, to_sarif
from backend.storage.exporters.richtext import blocks
from backend.storage.exporters.richtext import to_html as rich_html


def _report() -> Report:
    findings = [
        Finding(
            engine="bandit", rule_id="B602", title="Shell injection", severity=Severity.CRITICAL,
            confidence=0.9, file_path="app.py", line=7, snippet="7  subprocess.call(cmd, shell=True)",
            cwe="CWE-78", description="subprocess call with shell=True",
            why_dangerous="Attackers run commands.", how_to_fix="Pass a list of arguments.",
            explanation_source=ExplanationSource.AI, explanation_model="mistral:7b",
            references=["https://bandit.readthedocs.io/", "javascript:alert(1)"],
        ),
        Finding(engine="secrets", rule_id="SEC003", title="GitHub token", severity=Severity.LOW,
                confidence=0.4, file_path="config.js", line=2),
    ]
    return Report(target="https://github.com/a/b", target_type=TargetType.GITHUB_REPO,
                  findings=findings, summary=build_summary(findings))


def test_markdown_contains_the_essentials():
    text = to_markdown(_report())
    assert "# Secura security report: https://github.com/a/b" in text
    assert "| Critical | 1 |" in text
    assert "### 1. Shell injection" in text
    assert "`app.py:7`" in text
    assert "AI (mistral:7b)" in text


def test_html_is_escaped_and_safe():
    report = _report()
    report.target = "<script>alert(1)</script>"
    report.findings[0].snippet = "<img src=x onerror=alert(1)>"
    report.findings[0].title = "XSS <b>bold</b>"
    output = to_html(report)
    assert output.startswith("<!doctype html>")
    assert "<script>alert" not in output and "&lt;script&gt;" in output
    assert "<img src=x" not in output
    assert "javascript:alert" not in output
    assert "https://bandit.readthedocs.io/" in output


def test_sarif_structure():
    document = json.loads(to_sarif(_report()))
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "Secura"
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {"B602", "SEC003"}
    first = run["results"][0]
    assert first["level"] == "error"
    assert first["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    assert "external/cwe/cwe-78" in run["tool"]["driver"]["rules"][0]["properties"]["tags"]


def test_export_report_dispatch():
    report = _report()
    content, filename, media_type = export_report(report, "json")
    assert json.loads(content)["report_id"] == report.report_id
    assert filename == f"secura-{report.report_id}.json"
    assert export_report(report, "sarif")[2] == "application/sarif+json"
    with pytest.raises(ValidationError):
        export_report(report, "pdf")


def test_richtext_separates_code_from_prose():
    text = (
        "Replace the call with:\n\n"
        "subprocess.run(['ls', path], check=True)\n\n"
        "This avoids the shell entirely. Use an allowlist too."
    )
    kinds = [kind for kind, _ in blocks(text)]
    assert kinds == ["prose", "code", "prose"]
    rendered = rich_html("a <b>\n\nx = '<tag>'", "empty")
    assert "<b>" not in rendered and "&lt;tag&gt;" in rendered
