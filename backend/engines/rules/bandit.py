"""Bandit test catalogue: readable titles and severity policy per test id."""
from __future__ import annotations

from backend.schemas import Severity

TITLES: dict[str, str] = {
    "B101": "Assertion used for a runtime check",
    "B102": "Use of exec()",
    "B103": "Overly permissive file permissions",
    "B104": "Service bound to all network interfaces",
    "B105": "Hardcoded password in a string",
    "B106": "Hardcoded password passed as an argument",
    "B107": "Hardcoded password as a default value",
    "B108": "Insecure temporary file path",
    "B110": "Exception silently ignored (try/except/pass)",
    "B112": "Exception silently ignored (try/except/continue)",
    "B113": "HTTP request without a timeout",
    "B201": "Flask debug mode enabled",
    "B202": "Unsafe tar archive extraction",
    "B301": "Insecure deserialization with pickle",
    "B302": "Insecure deserialization with marshal",
    "B303": "Weak hash algorithm",
    "B304": "Weak cipher",
    "B305": "Weak cipher mode",
    "B306": "Insecure temporary file (mktemp)",
    "B307": "Use of eval()",
    "B308": "Use of mark_safe()",
    "B310": "URL opened without scheme validation",
    "B311": "Non-cryptographic random generator",
    "B312": "Telnet client usage",
    "B313": "XML parsing vulnerable to XXE",
    "B314": "XML parsing vulnerable to XXE",
    "B315": "XML parsing vulnerable to XXE",
    "B316": "XML parsing vulnerable to XXE",
    "B317": "XML parsing vulnerable to XXE",
    "B318": "XML parsing vulnerable to XXE",
    "B319": "XML parsing vulnerable to XXE",
    "B320": "XML parsing vulnerable to XXE",
    "B321": "FTP client usage",
    "B323": "Unverified TLS context",
    "B324": "Weak hash algorithm in hashlib",
    "B401": "Telnet module imported",
    "B402": "FTP module imported",
    "B403": "Pickle module imported",
    "B404": "Subprocess module imported",
    "B405": "XML module imported",
    "B406": "XML module imported",
    "B407": "XML module imported",
    "B408": "XML module imported",
    "B409": "XML module imported",
    "B410": "lxml imported",
    "B411": "XML-RPC module imported",
    "B412": "httpoxy-vulnerable import",
    "B413": "Deprecated pyCrypto imported",
    "B415": "Deprecated pyghmi imported",
    "B501": "TLS certificate verification disabled",
    "B502": "Weak SSL/TLS protocol version",
    "B503": "Weak SSL/TLS protocol default",
    "B504": "SSL/TLS without an explicit protocol version",
    "B505": "Weak cryptographic key size",
    "B506": "Unsafe YAML load",
    "B507": "SSH host key verification disabled",
    "B508": "Insecure SNMP version",
    "B509": "Weak SNMP cryptography",
    "B601": "Paramiko shell command execution",
    "B602": "Shell injection (subprocess with shell=True)",
    "B603": "Subprocess call: validate untrusted input",
    "B604": "Function call with shell=True",
    "B605": "Process started with a shell",
    "B606": "Process started without a shell",
    "B607": "Process started with a partial executable path",
    "B608": "SQL query built from strings (SQL injection)",
    "B609": "Wildcard injection in a shell command",
    "B610": "Django extra() with untrusted input",
    "B611": "Django RawSQL with untrusted input",
    "B612": "logging.config.listen() code execution",
    "B613": "Trojan Source bidirectional characters",
    "B614": "Unsafe torch.load",
    "B615": "Unpinned Hugging Face model download",
    "B701": "Jinja2 autoescape disabled",
    "B702": "Mako templates without escaping",
    "B703": "Django mark_safe with untrusted input",
    "B704": "markupsafe.Markup with untrusted input",
}

ESCALATE_TO_CRITICAL: frozenset[str] = frozenset({
    "B102", "B301", "B307", "B506", "B602", "B604", "B605", "B608", "B614",
})

DEMOTE_TO_INFO: frozenset[str] = frozenset({
    "B401", "B402", "B403", "B404", "B405", "B406", "B407", "B408", "B409",
    "B410", "B411", "B412",
})

RAISE_TO_MEDIUM: frozenset[str] = frozenset({"B105", "B106", "B107"})

SKIP_IN_TESTS: frozenset[str] = frozenset({
    "B101", "B105", "B106", "B107", "B108", "B110", "B112", "B311", "B404", "B603",
})

SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.65, "LOW": 0.4}


def title_for(test_id: str, test_name: str) -> str:
    if test_id in TITLES:
        return TITLES[test_id]
    cleaned = test_name.replace("_", " ").strip()
    return cleaned[:1].upper() + cleaned[1:] if cleaned else "Unknown issue"


def severity_for(test_id: str, raw_severity: str, raw_confidence: str) -> Severity:
    severity = SEVERITY.get(raw_severity.upper(), Severity.LOW)
    if test_id in DEMOTE_TO_INFO:
        return Severity.INFO
    if test_id in RAISE_TO_MEDIUM and severity == Severity.LOW:
        return Severity.MEDIUM
    if (test_id in ESCALATE_TO_CRITICAL and severity == Severity.HIGH
            and raw_confidence.upper() == "HIGH"):
        return Severity.CRITICAL
    return severity
