import textwrap

from backend.core.cancellation import CancelToken
from backend.engines.bandit import BanditEngine, _clean_code
from backend.engines.base import EngineContext
from backend.engines.inventory import build_inventory
from backend.engines.rules.bandit import severity_for, title_for
from backend.schemas import Severity

VULNERABLE = textwrap.dedent("""
    import subprocess


    def run(user_input):
        subprocess.call(user_input, shell=True)


    def get_user(cursor, name):
        return cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


    password = "hunter2-secret-value"
""")


def _run(root, settings):
    inventory = build_inventory(root, settings.max_scan_file_bytes)
    return BanditEngine().run(EngineContext(root=root, inventory=inventory, settings=settings,
                                            token=CancelToken()))


def test_bandit_reports_real_issues(make_tree, settings):
    root = make_tree({"app.py": VULNERABLE, "tests/test_app.py": "assert 1 == 1\n"})
    result = _run(root, settings)
    by_rule = {f.rule_id: f for f in result.findings}

    assert by_rule["B602"].severity == Severity.CRITICAL
    assert by_rule["B602"].cwe == "CWE-78"
    assert by_rule["B602"].file_path == "app.py"
    assert "shell=True" in by_rule["B602"].snippet
    assert "B608" in by_rule
    assert by_rule["B105"].severity == Severity.MEDIUM
    assert by_rule["B404"].severity == Severity.INFO
    assert "B101" not in by_rule
    assert result.detail == "2 Python file(s)"


def test_severity_policy():
    assert severity_for("B602", "HIGH", "HIGH") == Severity.CRITICAL
    assert severity_for("B602", "HIGH", "MEDIUM") == Severity.HIGH
    assert severity_for("B404", "LOW", "HIGH") == Severity.INFO
    assert severity_for("B106", "LOW", "MEDIUM") == Severity.MEDIUM
    assert severity_for("B999", "MEDIUM", "LOW") == Severity.MEDIUM
    assert title_for("B999", "some_new_check") == "Some new check"


def test_clean_code_normalises_numbering():
    assert _clean_code("9 \n10 x = eval(y)\n11 \n") == "10  x = eval(y)"
