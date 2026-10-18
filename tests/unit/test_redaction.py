"""Secrets must never survive in snippets or messages, whichever engine produced them."""
from backend.core.redaction import redact_finding, scrub
from backend.schemas import Finding

TOKEN = "ghp" + "_Z8xk2LmQ9pWv4RtY7uNc3HbJ6sDf1GaE5oKi"
GENERIC = "Zx9Lk2Qp8Wm4Rt7Yv3Nb6Hc1Jd5Gf0Ae"


def test_context_lines_of_unrelated_findings_are_scrubbed():
    finding = Finding(engine="javascript", rule_id="JS004", cwe="CWE-79", line=1, snippet=(
        f"1  el.innerHTML = location.hash;\n2  const token = '{TOKEN}';\n3  const apiKey = '{GENERIC}';"))
    snippet = redact_finding(finding).snippet
    assert TOKEN not in snippet and GENERIC not in snippet
    assert snippet.startswith("1  el.innerHTML = location.hash;")
    assert "ghp_" in snippet and "•" in snippet


def test_hardcoded_credential_findings_mask_their_literal():
    bandit = redact_finding(Finding(engine="bandit", rule_id="B105", cwe="CWE-798", line=13,
                                    description="Possible hardcoded password: 'MYSUPERSECRETKEY'",
                                    snippet="13  app.secret_key = 'MYSUPERSECRETKEY'"))
    assert "MYSUPERSECRETKEY" not in bandit.description + bandit.snippet
    docker = redact_finding(Finding(engine="docker", rule_id="DOCKER005", cwe="CWE-798", line=3,
                                    snippet="3  ENV DB_PASSWORD=SuperSecretValue"))
    assert "SuperSecretValue" not in docker.snippet and "DB_PASSWORD=" in docker.snippet
    jwt = redact_finding(Finding(engine="javascript", rule_id="JS016", cwe="CWE-798", line=4,
                                 snippet="4  jwt.sign(payload, 'supersecretvalue');"))
    assert "supersecretvalue" not in jwt.snippet


def test_ordinary_code_and_placeholders_are_left_alone():
    code = "5  subprocess.call(cmd, shell=True)"
    finding = redact_finding(Finding(engine="bandit", rule_id="B602", cwe="CWE-78", line=5, snippet=code,
                                     description="subprocess call with shell=True identified"))
    assert finding.snippet == code and "shell=True" in finding.description
    assert scrub("const password = 'changeme123';") == "const password = 'changeme123';"
    assert scrub("") == ""
