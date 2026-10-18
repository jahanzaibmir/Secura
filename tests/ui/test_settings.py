from ui.settings import UISettings, _hostname


def test_hostname_parsing():
    assert _hostname("localhost:8501") == "localhost"
    assert _hostname("[::1]:8501") == "::1"
    assert _hostname("secura.example.com") == "secura.example.com"
    assert _hostname("") == ""


def test_printable_links_only_when_the_browser_can_reach_the_api():
    local = UISettings(api_url="http://127.0.0.1:8642")
    assert local.browser_api_url("localhost:8501") == "http://127.0.0.1:8642"
    assert local.browser_api_url("127.0.0.1:8501") == "http://127.0.0.1:8642"
    assert local.browser_api_url("secura.vercel.app") is None

    public = UISettings(api_url="http://127.0.0.1:8642", public_api_url="https://api.example.com")
    assert public.browser_api_url("secura.vercel.app") == "https://api.example.com"

    remote = UISettings(api_url="http://backend.internal:8642")
    assert remote.browser_api_url("localhost:8501") is None
