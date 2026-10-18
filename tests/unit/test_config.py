from pathlib import Path

from backend.config import Settings


def test_defaults_are_safe(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURA_DATA_DIR")
    settings = Settings.from_env()
    assert settings.allow_local_paths is False
    assert settings.host == "127.0.0.1"
    assert settings.reports_dir == settings.data_dir / "reports"


def test_canonical_names_win_over_legacy_names(monkeypatch, tmp_path):
    monkeypatch.setenv("VW_PORT", "9000")
    monkeypatch.setenv("SECURA_PORT", "9100")
    monkeypatch.setenv("VW_MAX_AI_FINDINGS", "9")
    monkeypatch.setenv("VW_ENABLE_AI", "1")
    monkeypatch.setenv("SECURA_DATA_DIR", str(tmp_path / "custom"))
    monkeypatch.setenv("SECURA_CORS_ORIGINS", "https://a.example, https://b.example")
    settings = Settings.from_env()
    assert settings.port == 9100
    assert settings.ai_max_findings == 9
    assert settings.data_dir == Path(tmp_path / "custom")
    assert settings.cors_origins == ("https://a.example", "https://b.example")


def test_invalid_values_fall_back_to_defaults(monkeypatch):
    monkeypatch.setenv("SECURA_PORT", "not-a-number")
    monkeypatch.setenv("SECURA_MAX_CONCURRENT_SCANS", "0")
    settings = Settings.from_env()
    assert settings.port == 8642
    assert settings.max_concurrent_scans == 1
