import json
import threading

import pytest
import requests

from backend.ai.analyzers import OllamaAnalyzer, OpenAICompatAnalyzer, resolve_model
from backend.ai.analyzers import ollama as ollama_module
from backend.ai.analyzers import openai_compat as openai_module
from backend.exceptions import AnalyzerError, AnalyzerUnavailable
from backend.schemas import Finding, Severity

GOOD = (
    "<<<WHY>>>\nThe query concatenates user input into SQL text, so input can change the query.\n"
    "<<<ATTACK>>>\nAn attacker could read every table.\n"
    "<<<FIX>>>\ncursor.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n"
    "This works because the placeholder is sent as data, so input never changes the query "
    "structure. Beyond the minimum: use a least-privilege account and add a regression test "
    "that feeds a quote character.\n"
)
THIN = "<<<WHY>>>\nInput reaches a shell.\n<<<ATTACK>>>\nCommands run.\n<<<FIX>>> Use safer calls.\n"

FINDING = Finding(title="SQL query built from strings (SQL injection)", rule_id="B608",
                  severity=Severity.MEDIUM, snippet="cursor.execute('...' + name)")


def _stream(text, done_reason="stop"):
    return [json.dumps({"response": text}), json.dumps({"response": "", "done": True, "done_reason": done_reason})]


def _ollama(**kwargs):
    analyzer = OllamaAnalyzer("http://ollama:11434", "mistral:7b", retry_backoff=0, **kwargs)
    analyzer._resolved = "mistral:7b"
    return analyzer


def test_resolve_model():
    assert resolve_model("mistral:7b", ["mistral:7b"]) == "mistral:7b"
    assert resolve_model("mistral", ["mistral:latest"]) == "mistral:latest"
    assert resolve_model("mistral:7b", ["mistral:latest"]) is None
    assert resolve_model("llama3", ["registry.example/library/llama3:latest"]) == "registry.example/library/llama3:latest"


def test_ollama_readiness(monkeypatch, fake_response):
    analyzer = OllamaAnalyzer("http://ollama:11434", "mistral", readiness_ttl=0)

    def down(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(ollama_module.requests, "get", down)
    assert not analyzer.readiness().ready

    monkeypatch.setattr(ollama_module.requests, "get",
                        lambda *a, **k: fake_response(200, {"models": [{"name": "llama3:8b"}]}))
    readiness = analyzer.readiness()
    assert not readiness.ready and "ollama pull mistral" in readiness.message

    monkeypatch.setattr(ollama_module.requests, "get",
                        lambda *a, **k: fake_response(200, {"models": [{"name": "mistral:latest"}]}))
    assert analyzer.readiness().ready
    assert analyzer._resolved == "mistral:latest"
    assert analyzer.list_models() == ["mistral:latest"]


def test_disabled_analyzer_is_never_ready():
    assert not OllamaAnalyzer("http://x", "m", enabled=False).can_analyze()


def test_explain_parses_and_merges_impact(monkeypatch, fake_response):
    calls = []

    def post(url, json=None, **kwargs):
        calls.append(json)
        return fake_response(200, lines=_stream(GOOD))

    monkeypatch.setattr(ollama_module.requests, "post", post)
    why, fix = _ollama().explain(FINDING)
    assert "concatenates" in why and "Impact: An attacker could read every table." in why
    assert "placeholder" in fix
    assert "Reference remediation guidance" in calls[0]["prompt"]
    assert "parameterised" in calls[0]["prompt"]


def test_truncation_retries_once_with_a_larger_local_budget(monkeypatch, fake_response):
    budgets = []

    def post(url, json=None, **kwargs):
        budgets.append(json["options"]["num_predict"])
        reason = "length" if len(budgets) == 1 else "stop"
        return fake_response(200, lines=_stream(GOOD, reason))

    monkeypatch.setattr(ollama_module.requests, "post", post)
    analyzer = _ollama(max_tokens=600)
    analyzer.generate("prompt")
    assert budgets == [600, 900]
    analyzer.generate("prompt again")
    assert budgets[2] == 600


def test_transient_failures_retry_then_give_up(monkeypatch, fake_response):
    attempts = {"n": 0}

    def flaky(url, **kwargs):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise requests.ConnectionError("blip")
        return fake_response(200, lines=_stream("ok"))

    monkeypatch.setattr(ollama_module.requests, "post", flaky)
    assert _ollama().generate("x") == "ok"

    def always_down(url, **kwargs):
        raise requests.Timeout("slow")

    monkeypatch.setattr(ollama_module.requests, "post", always_down)
    with pytest.raises(AnalyzerUnavailable):
        _ollama().generate("x")


def test_missing_model_maps_to_a_helpful_error(monkeypatch, fake_response):
    monkeypatch.setattr(ollama_module.requests, "post",
                        lambda *a, **k: fake_response(404, text='{"error": "model \\"mistral:7b\\" not found"}'))
    with pytest.raises(AnalyzerError, match="ollama pull"):
        _ollama().generate("x")


def test_thin_fix_triggers_a_depth_retry(monkeypatch, fake_response):
    bodies = iter([THIN, GOOD])
    monkeypatch.setattr(ollama_module.requests, "post",
                        lambda *a, **k: fake_response(200, lines=_stream(next(bodies))))
    why, fix = _ollama().explain(Finding(title="Shell injection", rule_id="B602"))
    assert len(fix) > 200


def test_explanations_are_cached(monkeypatch, fake_response):
    calls = {"n": 0}

    def post(*a, **k):
        calls["n"] += 1
        return fake_response(200, lines=_stream(GOOD))

    monkeypatch.setattr(ollama_module.requests, "post", post)
    analyzer = _ollama()
    first = analyzer.explain(FINDING)
    second = analyzer.explain(FINDING.model_copy())
    assert first == second and calls["n"] == 1


def test_concurrent_calls_do_not_share_retry_state(monkeypatch, fake_response):
    seen = []
    lock = threading.Lock()

    def post(url, json=None, **kwargs):
        with lock:
            seen.append(json["options"]["num_predict"])
        truncated = json["prompt"] == "truncate-me" and json["options"]["num_predict"] == 600
        return fake_response(200, lines=_stream("text", "length" if truncated else "stop"))

    monkeypatch.setattr(ollama_module.requests, "post", post)
    analyzer = _ollama(max_tokens=600)
    threads = [threading.Thread(target=analyzer.generate, args=("truncate-me",))]
    threads += [threading.Thread(target=analyzer.generate, args=(f"plain-{i}",)) for i in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(seen) == [600] * 6 + [900]


def _api(**kwargs):
    return OpenAICompatAnalyzer("https://api.example/v1", "secret-key-123456", "model-x",
                                label="Example", retry_backoff=0, **kwargs)


def _chat(text, finish="stop"):
    return {"choices": [{"message": {"content": text}, "finish_reason": finish}]}


def test_api_success_and_errors(monkeypatch, fake_response):
    monkeypatch.setattr(openai_module.requests, "post", lambda *a, **k: fake_response(200, _chat(GOOD)))
    why, fix = _api().explain(FINDING)
    assert "placeholder" in fix

    monkeypatch.setattr(openai_module.requests, "post", lambda *a, **k: fake_response(401, text="no"))
    with pytest.raises(AnalyzerError, match="rejected"):
        _api().generate("x")

    responses = iter([fake_response(429, text="slow down"), fake_response(200, _chat("fine"))])
    monkeypatch.setattr(openai_module.requests, "post", lambda *a, **k: next(responses))
    assert _api().generate("x") == "fine"


def test_api_truncation_retry(monkeypatch, fake_response):
    budgets = []

    def post(url, json=None, **kwargs):
        budgets.append(json["max_tokens"])
        return fake_response(200, _chat("partial" if len(budgets) == 1 else "complete",
                                        "length" if len(budgets) == 1 else "stop"))

    monkeypatch.setattr(openai_module.requests, "post", post)
    assert _api(max_tokens=600).generate("x") == "complete"
    assert budgets == [600, 900]


def test_api_readiness(monkeypatch, fake_response):
    monkeypatch.setattr(openai_module.requests, "get", lambda *a, **k: fake_response(401, text="bad"))
    assert not _api().readiness().ready
    monkeypatch.setattr(openai_module.requests, "get", lambda *a, **k: fake_response(200, {"data": []}))
    assert _api().readiness().ready
    assert not OpenAICompatAnalyzer("https://x", "", "m").readiness().ready
