"""AI settings tests — detection, ranking, validation, key hygiene.

All network calls mocked. Patching requests on any module patches the
shared requests module, so the mocks cover the manager's probes, model
listing, and live validation in one stroke."""
import pytest

from backend.ai.analyzer import OllamaAnalyzer
from backend.ai.remote_analyzer import OpenAICompatAnalyzer
from backend.config import Settings
from backend.core.ai_manager import (
    AnalyzerManager, _mask_key, pick_best_chat_model,
)
from backend.exceptions import AnalyzerError


class FakeResp:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def _ok_chat():
    return FakeResp(200, payload={"choices": [
        {"message": {"content": "OK"}, "finish_reason": "stop"}]})


def _ok_models(ids=None):
    ids = ids if ids is not None else ["mistral-small-latest"]
    return FakeResp(200, payload={"models": [{"name": i} for i in ids]})


def _models_payload(ids):
    return FakeResp(200, payload={"data": [{"id": i} for i in ids]})


def _patch_ok(monkeypatch):
    monkeypatch.setattr(
        "backend.core.ai_manager.requests.post",
        lambda *a, **kw: _ok_chat())
    monkeypatch.setattr(
        "backend.core.ai_manager.requests.get",
        lambda *a, **kw: _ok_models())


def _manager():
    return AnalyzerManager(Settings())


# ------------------------------------------------------- model ranking --

def test_pick_best_chat_model_ranks_and_filters():
    ids = ["text-embedding-3-small", "whisper-large-v3",
           "llama-3.3-70b-versatile", "llama-3.1-8b-instant",
           "openai/gpt-oss-20b"]
    ranked = pick_best_chat_model(ids)
    assert ranked[0] == "llama-3.3-70b-versatile"
    assert "text-embedding-3-small" not in ranked
    assert "whisper-large-v3" not in ranked
    assert "llama-3.1-8b-instant" in ranked[:3]


def test_pick_best_prefers_mistral_small():
    ranked = pick_best_chat_model(
        ["mistral-large-latest", "mistral-small-latest", "codestral-latest"])
    assert ranked[0] == "mistral-small-latest"
    assert "codestral-latest" in ranked  # not excluded, just not preferred


def test_pick_best_falls_back_to_any_chat_model():
    assert pick_best_chat_model(["some-unknown-model"]) == ["some-unknown-model"]
    assert pick_best_chat_model([]) == []


# ------------------------------------------------------ paste-a-key flow --

def test_apply_key_rejects_short_input():
    with pytest.raises(AnalyzerError, match="too short"):
        _manager().apply_key("short")


def test_apply_key_auto_detects_groq(monkeypatch):
    calls = {"post": 0, "get": 0}

    def fake_post(url, headers=None, json=None, timeout=None, **kw):
        calls["post"] += 1
        if calls["post"] == 1:
            # auth probe: bogus model name, auth passes -> 404
            return FakeResp(404, text="model not found")
        return _ok_chat()  # live validation with the chosen model

    def fake_get(url, headers=None, timeout=None, **kw):
        calls["get"] += 1
        return _models_payload(["whisper-large-v3", "text-embedding-3-small",
                                "llama-3.3-70b-versatile", "llama-3.1-8b-instant"])

    monkeypatch.setattr("backend.core.ai_manager.requests.post", fake_post)
    monkeypatch.setattr("backend.core.ai_manager.requests.get", fake_get)

    manager = _manager()
    status = manager.apply_key("gsk_" + "a" * 30)
    assert status.provider == "api"
    assert status.provider_label == "Groq"
    assert status.model == "llama-3.3-70b-versatile"
    assert status.key_masked
    # prefix hint meant exactly one provider was probed, no wasted calls
    assert calls["post"] == 2


def test_apply_key_groq_prefix_but_rejected(monkeypatch):
    monkeypatch.setattr(
        "backend.core.ai_manager.requests.post",
        lambda *a, **kw: FakeResp(401, text="unauthorized"))
    with pytest.raises(AnalyzerError, match="rejected"):
        _manager().apply_key("gsk_" + "b" * 30)


def test_apply_key_rejects_unknown_key_everywhere(monkeypatch):
    monkeypatch.setattr(
        "backend.core.ai_manager.requests.post",
        lambda *a, **kw: FakeResp(401, text="unauthorized"))
    with pytest.raises(AnalyzerError, match="not accepted"):
        _manager().apply_key("totally-not-a-real-key-1234")


def test_apply_key_probes_all_providers_for_mistral_format(monkeypatch):
    seen = {"bases": []}

    def fake_post(url, headers=None, json=None, timeout=None, **kw):
        seen["bases"].append(url)
        if "mistral" in url:
            # URL alone can't distinguish the two requests — both hit
            # api.mistral.ai. The payload can: the auth probe sends the
            # bogus model "vw-auth-probe" (404 = auth passed), the real
            # validation sends the listed model and must succeed.
            if json and json.get("model") == "vw-auth-probe":
                return FakeResp(404, text="model not found")
            return _ok_chat()
        return FakeResp(401, text="unauthorized")

    monkeypatch.setattr("backend.core.ai_manager.requests.post", fake_post)
    monkeypatch.setattr(
        "backend.core.ai_manager.requests.get",
        lambda *a, **kw: _models_payload(["mistral-small-latest"]))

    manager = _manager()
    status = manager.apply_key("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")  # 32 alnum
    assert status.provider_label == "Mistral API"
    assert status.model == "mistral-small-latest"
    # mistral was tried first thanks to the format heuristic
    assert "mistral" in seen["bases"][0]


# ------------------------------------------------------ manual flow (kept) --

def test_initial_state_is_local():
    manager = _manager()
    assert manager.status().provider == "ollama"
    assert isinstance(manager.current(), OllamaAnalyzer)
    assert not isinstance(manager.current(), OpenAICompatAnalyzer)


def test_mask_key():
    assert _mask_key("") == ""
    assert _mask_key("short") == "••••"
    assert _mask_key("sk-1234567890abcdef") == "sk-1…cdef"


def test_apply_swaps_to_api_provider(monkeypatch):
    _patch_ok(monkeypatch)
    manager = _manager()
    status = manager.apply("mistral", api_key="test-key-123456")
    assert status.provider == "api"
    assert status.provider_label == "Mistral API"
    assert status.ready is True
    current = manager.current()
    assert isinstance(current, OpenAICompatAnalyzer)
    assert current.model == "mistral-small-latest"
    assert manager.is_api() is True


def test_apply_rejects_bad_key_and_keeps_previous(monkeypatch):
    _patch_ok(monkeypatch)
    manager = _manager()
    manager.apply("mistral", api_key="good-key-123456")

    monkeypatch.setattr(
        "backend.core.ai_manager.requests.post",
        lambda *a, **kw: FakeResp(401, text="unauthorized"))
    with pytest.raises(AnalyzerError, match="rejected"):
        manager.apply("groq", api_key="bad-key-123456")

    current = manager.current()
    assert isinstance(current, OpenAICompatAnalyzer)
    assert current.model == "mistral-small-latest"


def test_apply_unknown_model_maps_to_friendly_error(monkeypatch):
    _patch_ok(monkeypatch)
    monkeypatch.setattr(
        "backend.core.ai_manager.requests.post",
        lambda *a, **kw: FakeResp(404, text="model not found"))
    with pytest.raises(AnalyzerError, match="model"):
        _manager().apply("mistral", api_key="k-123456789")


def test_apply_requires_key():
    with pytest.raises(AnalyzerError, match="key"):
        _manager().apply("mistral", api_key="   ")


def test_apply_resets_to_local(monkeypatch):
    _patch_ok(monkeypatch)
    manager = _manager()
    manager.apply("mistral", api_key="k-1234567890")
    status = manager.apply("ollama")
    assert status.provider == "ollama"
    assert status.key_set is False
    assert isinstance(manager.current(), OllamaAnalyzer)
    assert not isinstance(manager.current(), OpenAICompatAnalyzer)
    assert manager.is_api() is False


def test_raw_key_never_appears_in_status(monkeypatch):
    _patch_ok(monkeypatch)
    manager = _manager()
    manager.apply("mistral", api_key="supersecret-key-987654")
    dumped = manager.status().model_dump_json()
    assert "supersecret" not in dumped
    assert manager.status().key_set is True
    assert manager.status().key_masked == "supe…7654"
