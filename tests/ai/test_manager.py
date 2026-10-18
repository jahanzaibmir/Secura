import pytest

from backend.ai import manager as manager_module
from backend.ai.analyzers import OllamaAnalyzer, OpenAICompatAnalyzer
from backend.ai.manager import AnalyzerManager
from backend.ai.providers import mask_key, pick_best_chat_model
from backend.exceptions import AnalyzerError


def _chat_ok(fake_response):
    return fake_response(200, {"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]})


@pytest.fixture
def manager(settings, monkeypatch, fake_response):
    monkeypatch.setattr(OllamaAnalyzer, "list_models", lambda self: ["mistral:7b", "llama3:8b"])
    monkeypatch.setattr(manager_module.requests, "get",
                        lambda *a, **k: fake_response(200, {"data": [{"id": "mistral-small-latest"}]}))
    return AnalyzerManager(settings.with_overrides(ai_enabled=True))


def test_model_ranking():
    ranked = pick_best_chat_model(["text-embedding-3-small", "whisper-large-v3", "llama-3.1-8b-instant",
                                   "llama-3.3-70b-versatile", "openai/gpt-oss-20b"])
    assert ranked[0] == "llama-3.3-70b-versatile"
    assert "whisper-large-v3" not in ranked and "text-embedding-3-small" not in ranked
    assert pick_best_chat_model(["mistral-large-latest", "mistral-small-latest"])[0] == "mistral-small-latest"
    assert pick_best_chat_model(["unknown-model"]) == ["unknown-model"]
    assert pick_best_chat_model([]) == []


def test_mask_key():
    assert mask_key("") == ""
    assert mask_key("short") == "••••"
    assert mask_key("sk-1234567890abcdef") == "sk-1…cdef"


def test_starts_local_and_lists_models(manager):
    status = manager.status()
    assert status.provider == "ollama"
    assert status.local_models == ["mistral:7b", "llama3:8b"]
    assert isinstance(manager.current(), OllamaAnalyzer)


def test_apply_key_detects_groq_with_one_probe(manager, monkeypatch, fake_response):
    posts = []

    def post(url, json=None, **kwargs):
        posts.append(json["model"])
        return fake_response(404, text="model not found") if len(posts) == 1 else _chat_ok(fake_response)

    monkeypatch.setattr(manager_module.requests, "post", post)
    monkeypatch.setattr(manager_module.requests, "get", lambda *a, **k: fake_response(200, {"data": [
        {"id": "whisper-large-v3"}, {"id": "llama-3.3-70b-versatile"}, {"id": "llama-3.1-8b-instant"}]}))
    status = manager.apply_key("gsk_" + "a" * 40)
    assert status.provider == "api" and status.provider_label == "Groq"
    assert status.model == "llama-3.3-70b-versatile"
    assert status.ready
    assert posts == ["secura-auth-probe", "llama-3.3-70b-versatile"]


def test_apply_key_probes_providers_for_unknown_formats(manager, monkeypatch, fake_response):
    bases = []

    def post(url, json=None, **kwargs):
        bases.append(url)
        if "mistral" not in url:
            return fake_response(401, text="unauthorized")
        return fake_response(404, text="no model") if json["model"] == "secura-auth-probe" else _chat_ok(fake_response)

    monkeypatch.setattr(manager_module.requests, "post", post)
    status = manager.apply_key("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
    assert status.provider_label == "Mistral" and status.model == "mistral-small-latest"
    assert "mistral" in bases[0]


def test_apply_key_failures(manager, monkeypatch, fake_response):
    with pytest.raises(AnalyzerError, match="too short"):
        manager.apply_key("short-key")
    monkeypatch.setattr(manager_module.requests, "post", lambda *a, **k: fake_response(401, text="no"))
    with pytest.raises(AnalyzerError, match="rejected"):
        manager.apply_key("gsk_" + "b" * 40)
    with pytest.raises(AnalyzerError, match="not accepted"):
        manager.apply_key("totally-unknown-key-format-1234")
    assert manager.status().provider == "ollama"


def test_manual_apply_validates_and_keeps_previous_on_failure(manager, monkeypatch, fake_response):
    monkeypatch.setattr(manager_module.requests, "post", lambda *a, **k: _chat_ok(fake_response))
    status = manager.apply("mistral", api_key="good-key-1234567890")
    assert status.provider == "api" and status.ready
    assert isinstance(manager.current(), OpenAICompatAnalyzer)

    monkeypatch.setattr(manager_module.requests, "post", lambda *a, **k: fake_response(404, text="missing"))
    with pytest.raises(AnalyzerError, match="not found"):
        manager.apply("groq", api_key="other-key-1234567890", model="nope")
    assert manager.current().model == "mistral-small-latest"

    with pytest.raises(AnalyzerError, match="key"):
        manager.apply("mistral", api_key="   ")
    with pytest.raises(AnalyzerError, match="http"):
        manager.apply("custom", api_base="ftp://x", api_key="k" * 20, model="m")


def test_switching_back_to_a_chosen_local_model(manager, monkeypatch, fake_response):
    monkeypatch.setattr(manager_module.requests, "post", lambda *a, **k: _chat_ok(fake_response))
    manager.apply("openai", api_key="sk-test-1234567890abcdef")
    status = manager.apply("ollama", model="llama3:8b")
    assert status.provider == "ollama" and status.model == "llama3:8b"
    assert status.key_set is False


def test_raw_key_never_leaves_the_manager(manager, monkeypatch, fake_response):
    monkeypatch.setattr(manager_module.requests, "post", lambda *a, **k: _chat_ok(fake_response))
    manager.apply("mistral", api_key="supersecret-key-987654")
    dumped = manager.status().model_dump_json() + manager.ai_status().model_dump_json()
    assert "supersecret" not in dumped
    assert manager.status().key_masked == "supe…7654"
