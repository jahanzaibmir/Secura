"""Secret detection rules: provider-specific token formats plus generic credentials."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from re import Pattern

from backend.schemas import Severity

ROTATE = ("https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",)


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    title: str
    pattern: Pattern[str]
    severity: Severity
    confidence: float
    secret_group: int = 1
    min_entropy: float = 0.0


def _rx(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


RULES: tuple[SecretRule, ...] = (
    SecretRule("SEC001", "AWS access key ID",
               _rx(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), Severity.HIGH, 0.85),
    SecretRule("SEC002", "AWS secret access key",
               _rx(r"(?i)aws.{0,24}?(?:secret|private).{0,24}?[\"'`]([A-Za-z0-9/+=]{40})[\"'`]"),
               Severity.CRITICAL, 0.75, min_entropy=3.5),
    SecretRule("SEC003", "GitHub token",
               _rx(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"), Severity.CRITICAL, 0.95),
    SecretRule("SEC004", "GitHub fine-grained token",
               _rx(r"\b(github_pat_[A-Za-z0-9_]{82})\b"), Severity.CRITICAL, 0.95),
    SecretRule("SEC005", "GitLab personal access token",
               _rx(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"), Severity.CRITICAL, 0.9),
    SecretRule("SEC006", "Slack token",
               _rx(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"), Severity.HIGH, 0.9),
    SecretRule("SEC007", "Slack incoming webhook",
               _rx(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"),
               Severity.HIGH, 0.9),
    SecretRule("SEC008", "Stripe live secret key",
               _rx(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"), Severity.CRITICAL, 0.95),
    SecretRule("SEC009", "Google API key",
               _rx(r"\b(AIza[0-9A-Za-z_-]{35})\b"), Severity.HIGH, 0.85),
    SecretRule("SEC010", "OpenAI API key",
               _rx(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,})\b"),
               Severity.CRITICAL, 0.95),
    SecretRule("SEC011", "OpenAI project key",
               _rx(r"\b(sk-proj-[A-Za-z0-9_-]{40,})\b"), Severity.CRITICAL, 0.9),
    SecretRule("SEC012", "Anthropic API key",
               _rx(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})\b"), Severity.CRITICAL, 0.95),
    SecretRule("SEC013", "Groq API key",
               _rx(r"\b(gsk_[A-Za-z0-9]{48,})\b"), Severity.HIGH, 0.9),
    SecretRule("SEC014", "Hugging Face token",
               _rx(r"\b(hf_[A-Za-z0-9]{34,})\b"), Severity.HIGH, 0.85),
    SecretRule("SEC015", "SendGrid API key",
               _rx(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"), Severity.HIGH, 0.95),
    SecretRule("SEC016", "Twilio API key",
               _rx(r"\b(SK[0-9a-fA-F]{32})\b"), Severity.HIGH, 0.6, min_entropy=3.0),
    SecretRule("SEC017", "npm access token",
               _rx(r"\b(npm_[A-Za-z0-9]{36})\b"), Severity.HIGH, 0.9),
    SecretRule("SEC018", "PyPI upload token",
               _rx(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b"), Severity.HIGH, 0.95),
    SecretRule("SEC019", "Private key",
               _rx(r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
               Severity.CRITICAL, 0.95),
    SecretRule("SEC020", "JSON Web Token",
               _rx(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
               Severity.MEDIUM, 0.6),
    SecretRule("SEC021", "Database connection string with password",
               _rx(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)"
                   r"://[^\s:/@'\"`]+:([^\s@'\"`/]{3,})@[^\s'\"`]+"),
               Severity.HIGH, 0.8),
    SecretRule("SEC022", "Telegram bot token",
               _rx(r"\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b"), Severity.HIGH, 0.8),
    SecretRule("SEC023", "Discord bot token",
               _rx(r"\b([MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38})\b"),
               Severity.HIGH, 0.7, min_entropy=4.0),
    SecretRule("SEC024", "Mailgun API key",
               _rx(r"\b(key-[0-9a-f]{32})\b"), Severity.HIGH, 0.75),
    SecretRule("SEC025", "Shopify access token",
               _rx(r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"), Severity.HIGH, 0.95),
)

GENERIC_ASSIGNMENT = SecretRule(
    "SEC100", "Hardcoded credential",
    _rx(r"(?i)[\"']?\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
        r"auth[_-]?token|client[_-]?secret|private[_-]?key|signing[_-]?key)[A-Za-z0-9_.-]*)[\"']?"
        r"\s*(?::=|=>|=|:)\s*[\"'`]([^\"'`\s]{8,})[\"'`]"),
    Severity.MEDIUM, 0.5, secret_group=2, min_entropy=3.0,
)

ENV_ASSIGNMENT = SecretRule(
    "SEC101", "Credential in environment file",
    _rx(r"^\s*(?:export\s+)?([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|"
        r"CREDENTIALS?)[A-Z0-9_]*)\s*=\s*[\"']?([^\s\"'#]{8,})"),
    Severity.HIGH, 0.7, secret_group=2, min_entropy=2.8,
)

_PLACEHOLDER_MARKERS = (
    "example", "xxxx", "your_", "your-", "yourkey", "changeme", "change_me", "change-me",
    "placeholder", "dummy", "sample", "fake", "redacted", "<", ">", "${", "{{", "%s", "%(",
    "process.env", "os.environ", "getenv", "****", "....", "1234567890", "abcdef", "insert",
    "replace", "todo", "fixme", "secret_here", "not_a_real", "notreal", "none", "null",
    "undefined", "password", "env(", "settings.", "config.", "vault:",
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    if len(set(lowered)) <= 3:
        return True
    return lowered.startswith(("test", "demo", "local"))


def is_plausible(rule: SecretRule, value: str) -> bool:
    if is_placeholder(value):
        return False
    return shannon_entropy(value) >= rule.min_entropy


def redact(value: str) -> str:
    if len(value) <= 8:
        return "•" * len(value)
    keep = 4 if len(value) >= 16 else 2
    return f"{value[:keep]}{'•' * min(12, len(value) - keep - 2)}{value[-2:]}"


def secret_value(rule: SecretRule, match: re.Match) -> str | None:
    try:
        return match.group(rule.secret_group)
    except IndexError:
        return match.group(0)
