import pytest

from backend.ai.text import clean_text, fix_is_thin, parse_sections
from backend.exceptions import AnalyzerError


def test_clean_text_strips_markdown_and_markers():
    raw = "## Heading\n**bold** and `code`\n```python\nx = 1\n```\n- item\n<<<FIX>>>"
    cleaned = clean_text(raw)
    assert "**" not in cleaned and "`" not in cleaned and "##" not in cleaned
    assert "• item" in cleaned and "<<<" not in cleaned
    assert "x = 1" in cleaned


def test_clean_text_caps_length_on_a_word_boundary():
    cleaned = clean_text("word " * 2000, max_chars=500)
    assert len(cleaned) <= 505 and cleaned.endswith("…")


def test_parse_sections_keeps_the_first_occurrence():
    sections = parse_sections("<<<WHY>>> one <<< attack >>> two <<<FIX>>> three <<<WHY>>> ignored")
    assert sections == {"WHY": "one", "ATTACK": "two", "FIX": "three"}
    with pytest.raises(AnalyzerError):
        parse_sections("no markers at all")


def test_fix_is_thin():
    assert fix_is_thin("Use safer calls.")
    assert not fix_is_thin("Replace the call with subprocess.run(['ls', path], check=True). " * 5)
