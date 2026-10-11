"""Code scanner tests — offline: real Bandit subprocess + JS pattern engine."""
import textwrap

from backend.api.schemas import Severity, TargetType
from backend.scanners.code_scanner import LocalCodeScanner


def test_local_code_scan_bandit(tmp_path):
    (tmp_path / "app.py").write_text(textwrap.dedent("""
        import subprocess


        def run_command(user_input):
            subprocess.call(user_input, shell=True)


        password = "hunter2-secret-value"


        def get_user(cursor, name):
            return cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


        result = eval("2 + 2")
    """), encoding="utf-8")
    scanner = LocalCodeScanner(str(tmp_path))
    findings = scanner.scan()
    assert findings, "Bandit should report findings for vulnerable code"
    assert any("SQL" in f.vulnerability_type for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)
    assert all("line" in f.location for f in findings)


def test_local_code_scan_javascript(tmp_path):
    (tmp_path / "widget.js").write_text(
        'eval(userInput);\n'
        'el.innerHTML = data;\n'
        'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n',
        encoding="utf-8")
    scanner = LocalCodeScanner(str(tmp_path))
    findings = scanner.scan()
    types = " | ".join(f.vulnerability_type for f in findings)
    assert "eval" in types
    assert "innerHTML" in types
    assert "AWS" in types


def test_local_code_scan_empty(tmp_path):
    scanner = LocalCodeScanner(str(tmp_path))
    assert scanner.scan() == []
    assert any("No Python or JavaScript" in note for note in scanner.notes)


def test_all_scanners_import_and_register():
    """Every scanner must import cleanly and register for its target type."""
    import backend.scanners  # noqa: F401
    from backend.core.registry import registry
    for target_type in TargetType:
        assert registry.has(target_type), (
            f"no scanner registered for '{target_type.value}'")
