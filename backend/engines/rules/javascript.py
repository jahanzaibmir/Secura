"""JavaScript and TypeScript security rules."""
from __future__ import annotations

import re

from backend.engines.rules.model import PatternRule, rx
from backend.schemas import Severity

_I = re.IGNORECASE
_SQL = r"(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE)\b"
_REQ = r"req(?:uest)?\.(?:query|body|params|headers|cookies)"

OWASP_XSS = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
OWASP_INJECTION = "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
OWASP_SQL = "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"

RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "JS001", "Use of eval()", rx(r"(?<![\w$.])eval\s*\("),
        Severity.HIGH, 0.6, "CWE-95",
        "eval() executes a string as code; any attacker influence on that string is code execution.",
        masked=True,
    ),
    PatternRule(
        "JS002", "Dynamic code construction with new Function()", rx(r"\bnew\s+Function\s*\("),
        Severity.MEDIUM, 0.6, "CWE-95",
        "new Function() compiles strings at runtime and carries the same risk as eval().",
        masked=True,
    ),
    PatternRule(
        "JS003", "String passed to setTimeout/setInterval",
        rx(r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]"),
        Severity.MEDIUM, 0.6, "CWE-95",
        "A string argument to setTimeout or setInterval is evaluated as code.",
    ),
    PatternRule(
        "JS004", "Assignment to innerHTML/outerHTML (DOM XSS sink)",
        rx(r"\.(?:inner|outer)HTML\s*\+?=(?!=)"),
        Severity.MEDIUM, 0.5, "CWE-79",
        "Raw strings assigned to innerHTML are parsed as HTML and can execute injected script.",
        unless=rx(r"\.(?:inner|outer)HTML\s*=\s*(?:[\"'`]\s*[\"'`]|DOMPurify\.sanitize)"),
        references=(OWASP_XSS,),
        masked=True,
    ),
    PatternRule(
        "JS005", "insertAdjacentHTML with dynamic content (DOM XSS sink)",
        rx(r"\.insertAdjacentHTML\s*\("),
        Severity.MEDIUM, 0.5, "CWE-79",
        "insertAdjacentHTML parses its argument as HTML, which is a DOM XSS vector.",
        references=(OWASP_XSS,),
        masked=True,
    ),
    PatternRule(
        "JS006", "document.write usage (DOM XSS sink)", rx(r"\bdocument\.write(?:ln)?\s*\("),
        Severity.MEDIUM, 0.5, "CWE-79",
        "document.write parses strings as HTML, which is a DOM XSS vector.",
        references=(OWASP_XSS,),
        masked=True,
    ),
    PatternRule(
        "JS007", "React dangerouslySetInnerHTML", rx(r"dangerouslySetInnerHTML"),
        Severity.MEDIUM, 0.5, "CWE-79",
        "A deliberate raw-HTML injection point in React that must only receive sanitised input.",
        unless=rx(r"DOMPurify\.sanitize"),
        references=(OWASP_XSS,),
        masked=True,
    ),
    PatternRule(
        "JS008", "Command injection through child_process",
        rx(r"(?:(?<![\w$.])|(?:child_process|childProcess|cp|shell)\.)(?:exec|execSync)\s*\(\s*"
           r"(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|[A-Za-z_$][\w$.]*\s*(?:\+|,|\)))"),
        Severity.HIGH, 0.65, "CWE-78",
        "A shell command is built from dynamic values; shell metacharacters in them run extra commands.",
        references=(OWASP_INJECTION,),
    ),
    PatternRule(
        "JS009", "Process spawned with shell: true", rx(r"\bshell\s*:\s*true\b"),
        Severity.MEDIUM, 0.55, "CWE-78",
        "Spawning through a shell re-enables shell metacharacters in every argument.",
        references=(OWASP_INJECTION,),
        masked=True,
    ),
    PatternRule(
        "JS010", "SQL query built from strings (SQL injection)",
        rx(r"\b(?:query|execute|raw|unsafe)\s*\(\s*(?:`[^`]*\b" + _SQL + r"[^`]*\$\{|"
           r"[\"'][^\"']*\b" + _SQL + r"[^\"']*[\"']\s*\+)", _I),
        Severity.HIGH, 0.7, "CWE-89",
        "The SQL text is assembled from variables, so input can change the query's structure.",
        references=(OWASP_SQL,),
    ),
    PatternRule(
        "JS011", "TLS certificate verification disabled",
        rx(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"'\]]*\s*=\s*[\"']?0"),
        Severity.HIGH, 0.8, "CWE-295",
        "Disabling certificate verification lets anyone on the network path impersonate the server.",
    ),
    PatternRule(
        "JS012", "Weak hash algorithm",
        rx(r"createHash\s*\(\s*[\"'](?:md4|md5|sha1|ripemd160)[\"']", _I),
        Severity.MEDIUM, 0.6, "CWE-328",
        "MD5 and SHA-1 are collision-broken and unfit for integrity checks or password storage.",
    ),
    PatternRule(
        "JS013", "Predictable random value used for a secret",
        rx(r"(?:token|secret|password|passwd|nonce|salt|session|otp|apikey|api_key)\w*"
           r"\s*[:=][^;\n]*Math\.random\s*\(", _I),
        Severity.MEDIUM, 0.55, "CWE-338",
        "Math.random() is predictable; tokens derived from it can be guessed.",
    ),
    PatternRule(
        "JS014", "JWT accepts the 'none' algorithm",
        rx(r"algorithms\s*:\s*\[[^\]]*[\"']none[\"']", _I),
        Severity.HIGH, 0.75, "CWE-347",
        "Accepting alg 'none' lets anyone forge tokens without a signature.",
    ),
    PatternRule(
        "JS015", "JWT expiry checks disabled", rx(r"ignoreExpiration\s*:\s*true"),
        Severity.MEDIUM, 0.7, "CWE-613",
        "Expired tokens remain valid forever, so a leaked token never stops working.",
    ),
    PatternRule(
        "JS016", "Hardcoded JWT signing secret",
        rx(r"jwt\.sign\s*\([^)]*,\s*[\"'][^\"']{4,}[\"']"),
        Severity.HIGH, 0.65, "CWE-798",
        "A signing secret in source code lets anyone with repository access mint valid tokens.",
    ),
    PatternRule(
        "JS017", "Permissive CORS policy",
        rx(r"cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|[\"']\*[\"'])|"
           r"Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*", _I),
        Severity.LOW, 0.5, "CWE-942",
        "Any website can read responses from this API from a victim's browser.",
    ),
    PatternRule(
        "JS018", "Prototype pollution sink",
        rx(r"\[\s*[\"']__proto__[\"']\s*\]|\.__proto__\s*=|Object\.prototype\.\w+\s*="),
        Severity.MEDIUM, 0.5, "CWE-1321",
        "Writing to the object prototype changes the behaviour of every object in the process.",
    ),
    PatternRule(
        "JS019", "Unsafe deserialization", rx(r"\b(?:serialize\.)?unserialize\s*\("),
        Severity.HIGH, 0.6, "CWE-502",
        "node-serialize style unserialize() can execute functions embedded in the payload.",
        masked=True,
    ),
    PatternRule(
        "JS020", "Code executed through the vm module",
        rx(r"\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\("),
        Severity.MEDIUM, 0.55, "CWE-95",
        "The vm module is not a security sandbox; untrusted code can escape it.",
        masked=True,
    ),
    PatternRule(
        "JS021", "Open redirect from request data",
        rx(r"\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?" + _REQ),
        Severity.MEDIUM, 0.65, "CWE-601",
        "Redirecting to a user-supplied URL lets attackers bounce victims to phishing pages.",
    ),
    PatternRule(
        "JS022", "Reflected XSS from request data",
        rx(r"\bres\.(?:send|write|end)\s*\(\s*(?:[\"'`][^\"'`]*[\"'`]\s*\+\s*)?" + _REQ),
        Severity.HIGH, 0.6, "CWE-79",
        "Request input is written straight into the response body without encoding.",
        references=(OWASP_XSS,),
    ),
    PatternRule(
        "JS023", "Path traversal from request data",
        rx(r"\b(?:readFile|readFileSync|createReadStream|sendFile|unlink|unlinkSync|writeFile|writeFileSync)"
           r"\s*\([^)]*" + _REQ),
        Severity.HIGH, 0.6, "CWE-22",
        "A file path is built from request input, so ../ sequences can reach any file.",
    ),
    PatternRule(
        "JS024", "Auth token stored in localStorage",
        rx(r"localStorage\.setItem\s*\(\s*[\"'][^\"']*(?:token|jwt|session|auth)", _I),
        Severity.LOW, 0.5, "CWE-922",
        "localStorage is readable by any script on the page, so one XSS leaks the session.",
    ),
    PatternRule(
        "JS025", "postMessage to any origin", rx(r"\.postMessage\s*\([^)]*,\s*[\"']\*[\"']\s*\)"),
        Severity.LOW, 0.5, "CWE-345",
        "Messages posted with target origin '*' can be read by any embedding page.",
    ),
)
