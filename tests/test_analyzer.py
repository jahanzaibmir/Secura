"""AI engine tests — fully mocked, speaking real NDJSON protocol.

Covers: parsing, sanitization, retries, truncation auto-retry, thin-fix
depth retry, and knowledge-base grounding of the prompt."""
import json as _json

import pytest
import requests

from backend.ai import analyzer as analyzer_module
from backend.ai.analyzer import OllamaAnalyzer, _clean_text
from backend.ai.knowledge import fallback_explanation
from backend.api.schemas import Finding, Severity
from backend.exceptions import AnalyzerError, OllamaNotAvailable


class FakeResponse:
    """Streaming-shaped fake: NDJSON lines + text for error bodies."""

    def __init__(self, status_code=200, ndjson=None, text=""):
        self.status_code = status_code
        self._ndjson = ndjson or []
        self.text = text

    def iter_lines(self):
        yield from self._ndjson

    def close(self):
        pass


GOOD = (
    "<<<WHY>>>\nThe query concatenates user input directly into the SQL "
    "statement text, so the meaning of the query can be changed by the "
    "input values.\n"
    "<<<ATTACK>>>\nAn attacker could read every table in the database.\n"
    "<<<FIX>>>\n"
    "Corrected code:\n"
    "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n"
    "This works because the placeholder is sent to the database as pure "
    "data, so input can never change the query structure. Beyond the "
    "minimum: use a least-privilege database account, and add a regression "
    "test that feeds a quote character and asserts it is stored as data.\n"
)

THIN = (
    "<<<WHY>>>\nThe code passes user input to a shell command.\n"
    "<<<ATTACK>>>\nAn attacker could run commands.\n"
    "<<<FIX>>> Use safer subprocess calls.\n"
)


def _make_analyzer():
    return OllamaAnalyzer("http://fake:11434", "mistral:7b", timeout=5, retry_backoff=0.0)


def _mock_generate(monkeypatch, body=GOOD, status=200, capture=None):
    def fake_post(url, json=None, timeout=None, **kwargs):
        if capture is not None:
            capture["prompt"] = json["prompt"]
            capture["count"] = capture.get("count", 0) + 1
        if status == 200:
            lines = [_json.dumps({"response": body, "done": True})]
            return FakeResponse(status, ndjson=lines)
        return FakeResponse(status, text=body)
    monkeypatch.setattr(analyzer_module.requests, "post", fake_post)


def _ready(monkeypatch, analyzer):
    monkeypatch.setattr(analyzer, "model_installed", lambda: True)


def test_explain_parses_merges_and_cleans(monkeypatch):
    _mock_generate(monkeypatch)
    analyzer = _make_analyzer()
    _ready(monkeypatch, analyzer)
    why, fix = analyzer.explain(Finding(vulnerability_type="SQL Injection"))
    assert "concatenates" in why
    assert "Attacker impact:" in why
    assert "placeholder" in fix


def test_explain_handles_multi_chunk_stream(monkeypatch):
    # Response split across many NDJSON lines, like a real token stream.
    def fake_post(url, json=None, timeout=None, **kwargs):
        words = GOOD.split(" ")
        lines = [_json.dumps({"response": w + " "}) for w in words]
        lines.append(_json.dumps({"response": "", "done": True}))
        return FakeResponse(200, ndjson=lines)
    monkeypatch.setattr(analyzer_module.requests, "post", fake_post)
    analyzer = _make_analyzer()
    _ready(monkeypatch, analyzer)
    why, fix = analyzer.explain(Finding(vulnerability_type="SQL Injection"))
    assert "concatenates" in why and "placeholder" in fix


def test_explain_strips_model_markdown(monkeypatch):
    body = (
        "<<<WHY>>> The **server** runs `eval` on input.\n"
        "```python\nfence line\n```\n"
        "<<<FIX>>> Use **safe** parsing with json.loads and keep the "
        "deserialized data away from exec paths, adding a test that feeds "
        "a malformed document and asserts the parser rejects it."
    )
    _mock_generate(monkeypatch, body=body)
    analyzer = _make_analyzer()
    _ready(monkeypatch, analyzer)
    why, fix = analyzer.explain(Finding(vulnerability_type="Use of eval()"))
    assert "**" not in why and "`" not in why
    assert "safe" in fix


def test_explain_missing_fix_raises(monkeypatch):
    _mock_generate(monkeypatch, body="<<<WHY>>> only why here.")
    analyzer = _make_analyzer()
    _ready(monkeypatch, analyzer)
    with pytest.raises(AnalyzerError):
        analyzer.explain(Finding(vulnerability_type="XSS"))


def test_explain_unparseable_raises(monkeypatch):
    _mock_generate(monkeypatch, body="I could not find any markers, sorry.")
    analyzer = _make_analyzer()
    _ready(monkeypatch, analyzer)
    with pytest.raises(AnalyzerError):
        analyzer.explain(Finding(vulnerability_type="XSS"))


def test_model_missing_maps_to_friendly_error(monkeypatch):
    _mock_generate(monkeypatch, status=404,
                  body="model 'mistral:7b' not found, try pulling it first")
    with pytest.raises(AnalyzerError) as excinfo:
        _make_analyzer().generate("hello")
    assert "ollama pull" in str(excinfo.value)


def test_transient_failure_retried_then_succeeds(monkeypatch):
    calls = {"count": 0}

    def fake_post(url, json=None, timeout=None, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise requests.ConnectionError("boom")
        return FakeResponse(200, ndjson=[_json.dumps({"response": "ok", "done": True})])

    monkeypatch.setattr(analyzer_module.requests, "post", fake_post)
    assert _make_analyzer().generate("x") == "ok"
    assert calls["count"] == 2


def test_transient_failure_exhausted(monkeypatch):
    def fake_post(url, **kwargs):
        raise requests.Timeout("slow")

    monkeypatch.setattr(analyzer_module.requests, "post", fake_post)
    with pytest.raises(OllamaNotAvailable):
        _make_analyzer().generate("x")


def test_clean_text_caps_length():
    text = "word " * 2000
    cleaned = _clean_text(text, max_chars=500)
    assert len(cleaned) <= 510
    assert cleaned.endswith("…")


def test_fallback_known_and_unknown():
    why, fix = fallback_explanation(
        Finding(vulnerability_type="Hardcoded password (string)", severity=Severity.HIGH))
    assert "credential" in why.lower()
    assert fix

    why2, fix2 = fallback_explanation(
        Finding(vulnerability_type="Something exotic", severity=Severity.LOW,
                location="tcp/9"))
    assert "scanner flagged" in why2.lower()
    assert fix2


# ------------------------------------------------------------- v2 tests --

def test_reference_guidance_injected_into_prompt(monkeypatch):
    capture = {}
    _mock_generate(monkeypatch, capture=capture)
    analyzer = _make_analyzer()
    _ready(monkeypatch, analyzer)
    analyzer.explain(Finding(
        vulnerability_type="Hardcoded SQL expression (SQL injection)"))
    # The prompt must carry the knowledge base's vetted SQL guidance.
    assert "Reference remediation guidance" in capture["prompt"]
    assert "parameterized" in capture["prompt"]


def test_truncation_retries_with_bigger_budget(monkeypatch):
    partial = ("<<<WHY>>> The code builds a command from input.\n"
               "<<<FIX>>> Corrected code:\n"
               "subprocess.run([\"ping\", \"-c\", \"1\", \"--\"")  # cut mid-line
    calls = {"n": 0}

    def fake_post(url, json=None, timeout=None, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            line = _json.dumps({"response": partial, "done": True,
                                "done_reason": "length"})
        else:
            line = _json.dumps({"response": GOOD, "done": True})
        return FakeResponse(200, ndjson=[line])

    monkeypatch.setattr(analyzer_module.requests, "post", fake_post)
    analyzer = _make_analyzer()
    _ready(monkeypatch, analyzer)
    why, fix = analyzer.explain(Finding(vulnerability_type="SQL Injection"))
    assert calls["n"] == 2                  # retried exactly once
    assert analyzer._num_predict == 700     # budget was raised
    assert "placeholder" in fix             # the complete answer won


def test_thin_fix_triggers_depth_retry(monkeypatch):
    bodies = [THIN, GOOD]
    calls = {"n": 0}

    def fake_post(url, json=None, timeout=None, **kwargs):
        body = bodies[min(calls["n"], 1)]
        calls["n"] += 1
        return FakeResponse(200, ndjson=[_json.dumps({"response": body, "done": True})])

    monkeypatch.setattr(analyzer_module.requests, "post", fake_post)
    analyzer = _make_analyzer()
    _ready(monkeypatch, analyzer)
    why, fix = analyzer.explain(Finding(vulnerability_type="Shell injection"))
    assert calls["n"] == 2                  # depth retry fired
    assert len(fix) > 200                   # the deeper answer won
