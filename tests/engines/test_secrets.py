"""Fake credentials are assembled at runtime so no literal secret is ever committed."""
from backend.core.cancellation import CancelToken
from backend.engines.base import EngineContext
from backend.engines.inventory import build_inventory
from backend.engines.rules.secrets import is_placeholder, redact, shannon_entropy
from backend.engines.secrets import SecretsEngine
from backend.schemas import Severity

GITHUB_TOKEN = "ghp" + "_Z8xk2LmQ9pWv4RtY7uNc3HbJ6sDf1GaE5oKi"
STRIPE_KEY = "sk" + "_live_51HxQk2LmQ9pWv4RtY7uNc3Hb"
PRIVATE_KEY_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"
AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
DB_PASSWORD = "Pr0d" + "Passw0rd9"


def _scan(make_tree, settings, files):
    root = make_tree(files)
    inventory = build_inventory(root, settings.max_scan_file_bytes)
    return SecretsEngine().run(EngineContext(root=root, inventory=inventory, settings=settings,
                                             token=CancelToken())).findings


def test_provider_tokens_are_detected_and_redacted(make_tree, settings):
    findings = _scan(make_tree, settings, {
        "config.py": f'GITHUB = "{GITHUB_TOKEN}"\n',
        "web/pay.js": f"const stripe = require('stripe')('{STRIPE_KEY}');\n",
        "deploy/key.pem": f"{PRIVATE_KEY_HEADER}\nMIIEow\n-----END RSA KEY-----\n",
    })
    rules = {f.rule_id: f for f in findings}
    assert rules["SEC003"].severity == Severity.CRITICAL
    assert rules["SEC008"].file_path == "web/pay.js"
    assert "SEC019" in rules
    for finding in findings:
        dumped = finding.model_dump_json()
        assert GITHUB_TOKEN not in dumped and STRIPE_KEY not in dumped


def test_placeholders_and_documentation_values_are_ignored(make_tree, settings):
    findings = _scan(make_tree, settings, {
        "settings.js": "\n".join([
            f"const AWS_KEY = '{AWS_EXAMPLE_KEY}';",
            "const password = 'changeme123';",
            "const apiKey = process.env.API_KEY;",
            "const secret = '${SECRET_VALUE}';",
            "const token = 'your_token_here';",
        ]),
        ".env.example": "API_TOKEN=abcd1234efgh5678\n",
    })
    assert findings == []


def test_generic_credentials_and_env_files(make_tree, settings):
    findings = _scan(make_tree, settings, {
        "src/client.ts": "const apiKey = 'Zx9Lk2Qp8Wm4Rt7Yv3Nb6Hc1Jd5Gf0Ae';\n",
        ".env": f"DATABASE_URL=postgres://admin:{DB_PASSWORD}@db:5432/app\nSTRIPE_SECRET={STRIPE_KEY}\n"
                "SESSION_SECRET=q8Wz2Lk9Vb4Nm7Xc1Rt6\n",
        "app.py": "API_KEY = 'Zx9Lk2Qp8Wm4Rt7Yv3Nb6Hc1Jd5Gf0Ae'\n",
    })
    by_file = {}
    for finding in findings:
        by_file.setdefault(finding.file_path, []).append(finding.rule_id)
    assert by_file["src/client.ts"] == ["SEC100"]
    assert sorted(by_file[".env"]) == ["SEC008", "SEC021", "SEC101"]
    assert "app.py" not in by_file


def test_findings_in_tests_are_downgraded(make_tree, settings):
    findings = _scan(make_tree, settings, {"tests/fixtures.py": f"TOKEN = '{GITHUB_TOKEN}'\n"})
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence < 0.95


def test_helpers():
    assert redact("abcdefghijklmnopqrstuvwxyz").startswith("abcd")
    assert "mnop" not in redact("abcdefghijklmnopqrstuvwxyz")
    assert redact("short") == "•••••"
    assert is_placeholder("xxxxxxxxxxxx") and is_placeholder("<your-key>")
    assert not is_placeholder("q8Wz2Lk9Vb4Nm7Xc1Rt6")
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("q8Wz2Lk9Vb4Nm7Xc1Rt6") > 4
