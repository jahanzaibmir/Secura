"""Curated remediation guidance, keyed by rule id with keyword fallbacks.

The text is deterministic and reviewed by hand. It is the floor every finding
receives when no AI provider is available, and the grounding material injected
into AI prompts when one is.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Entry:
    rule_ids: tuple[str, ...]
    keywords: tuple[str, ...]
    why: str
    fix: str


ENTRIES: tuple[Entry, ...] = (
    Entry(
        ("B608", "B610", "B611", "JS010"), ("sql injection", "sql query"),
        "The query text is assembled from strings, so anything that reaches it can change the "
        "query's meaning. Crafted input can read other tables, dump the database, or modify data.",
        "Use parameterised queries everywhere: cursor.execute('SELECT * FROM users WHERE name = %s', "
        "(name,)) in Python, or db.query('SELECT * FROM users WHERE name = $1', [name]) in Node. Keep "
        "ORM filters parameterised and never format values into raw SQL. Give the application a "
        "least-privilege database account so a successful injection cannot reach unrelated data.",
    ),
    Entry(
        ("B602", "B604", "B605", "B601", "B609", "JS008", "JS009"), ("shell injection", "command injection"),
        "Untrusted input reaches an operating-system shell, so an attacker can append their own "
        "commands and they run with the application's privileges.",
        "Do not invoke a shell. Pass the program and its arguments as a list, for example "
        "subprocess.run(['convert', src, dst], check=True) or execFile('convert', [src, dst]). If "
        "only a few values are legitimate, validate against an allowlist. Run the service as a "
        "dedicated low-privilege user.",
    ),
    Entry(
        ("B603", "B606", "B607"), ("partial executable path", "subprocess call"),
        "A process is launched from code. This is safe only if every argument is trusted and the "
        "executable is resolved from a fixed location rather than the caller's PATH.",
        "Invoke binaries by absolute path, pass arguments as a list, and validate any value that "
        "originates outside the program. Prefer a library over shelling out when one exists.",
    ),
    Entry(
        ("B102", "B307", "JS001", "JS002", "JS003", "JS020"), ("eval", "exec(", "new function"),
        "The code executes a string as program code. If any part of that string can be influenced "
        "by input or data files, an attacker can run arbitrary code inside the process.",
        "Remove the dynamic execution. Parse data with json.loads or ast.literal_eval in Python and "
        "JSON.parse in JavaScript. Pass functions, not strings, to setTimeout. If expressions must "
        "be evaluated, use a purpose-built sandboxed evaluator with an allowlist of operations.",
    ),
    Entry(
        ("B301", "B302", "B403", "B614", "JS019"), ("pickle", "deserializ", "marshal"),
        "Deserialising untrusted bytes can construct arbitrary objects, which effectively runs "
        "attacker-chosen code during loading.",
        "Use a data-only format such as JSON. If pickle is unavoidable, only load data you produced "
        "and verify an HMAC signature before unpickling. For PyTorch use torch.load(path, "
        "weights_only=True). Never accept serialised objects across a trust boundary.",
    ),
    Entry(
        ("B506",), ("yaml",),
        "Unsafe YAML loaders construct arbitrary Python objects while parsing, which gives code "
        "execution from a crafted document.",
        "Use yaml.safe_load (and yaml.safe_dump). If custom tags are required, register only "
        "explicitly allowed constructors on a SafeLoader subclass.",
    ),
    Entry(
        ("B313", "B314", "B315", "B316", "B317", "B318", "B319", "B320",
         "B405", "B406", "B407", "B408", "B409", "B410", "B411"), ("xml", "xxe"),
        "The XML parser may resolve external entities, which can read local files, reach internal "
        "systems, or exhaust memory with entity expansion.",
        "Parse untrusted XML with defusedxml (defusedxml.ElementTree.fromstring) or disable DTDs "
        "and external entities in your parser's configuration.",
    ),
    Entry(
        ("SEC019",), ("private key",),
        "A private key is committed to the repository. Anyone who can read the code, a fork, or a "
        "build artifact can impersonate the key's owner or decrypt its traffic.",
        "Revoke and reissue the key pair now; assume it is compromised. Remove the file from version "
        "history with git filter-repo or BFG, add it to .gitignore, and load keys at runtime from a "
        "secrets manager or a mounted file outside the repository.",
    ),
    Entry(
        ("SEC101",), ("environment file",),
        "An environment file with real credentials is part of the source tree, so every clone, fork, "
        "and backup carries working secrets.",
        "Rotate every credential in the file, delete it from version history, and add .env to "
        ".gitignore. Commit a .env.example with placeholder values instead, and inject real values "
        "through the deployment platform's secret store.",
    ),
    Entry(
        ("B105", "B106", "B107", "JS016", "DOCKER005") + tuple(f"SEC{n:03d}" for n in range(1, 26)) + ("SEC100",),
        ("hardcoded", "secret", "token", "api key", "credential", "password"),
        "A credential is embedded in the source. Anyone who can read the repository or a built "
        "artifact obtains a working secret, and it cannot be rotated without shipping new code.",
        "Revoke and rotate the credential immediately; assume it is compromised. Load the new value "
        "from an environment variable or a secrets manager (os.environ['API_KEY'], "
        "process.env.API_KEY). Purge the old value from git history with git filter-repo and add a "
        "secret scanner to CI so it cannot happen again.",
    ),
    Entry(
        ("B303", "B324", "JS012"), ("weak hash", "md5", "sha1"),
        "The code relies on a collision-broken hash. Where hashes protect integrity or signatures, "
        "an attacker can craft different content with the same hash.",
        "Use SHA-256 or stronger (hashlib.sha256, crypto.createHash('sha256')). For passwords use a "
        "dedicated password hash: argon2, bcrypt, or scrypt. If MD5 is used only for non-security "
        "checksums, pass usedforsecurity=False to document that.",
    ),
    Entry(
        ("B304", "B305", "B502", "B503", "B504", "B505"), ("weak cipher", "weak ssl", "tls protocol", "key size"),
        "The code permits cryptography considered broken or too weak, undermining the "
        "confidentiality the system claims to provide.",
        "Use authenticated encryption (AES-GCM or ChaCha20-Poly1305 via the cryptography package), "
        "RSA keys of at least 3072 bits or elliptic curves, and require TLS 1.2 or newer "
        "(ssl.create_default_context() sets safe defaults).",
    ),
    Entry(
        ("B501", "B323", "B507", "JS011", "DOCKER008"), ("verification disabled", "unverified tls", "host key"),
        "Certificate or host-key verification is disabled, so the connection can be silently "
        "intercepted; encryption protects nothing against an active attacker.",
        "Restore verification (requests' default verify=True, the default SSL context, "
        "rejectUnauthorized left at true). For internal services, add the internal CA to the trust "
        "store instead of disabling checks. For SSH, load known host keys and use RejectPolicy.",
    ),
    Entry(
        ("B311", "JS013"), ("random",),
        "The random generator in use is predictable; tokens, passwords, or identifiers produced by "
        "it can be reconstructed by an attacker.",
        "Use a cryptographically secure source: secrets.token_urlsafe() or secrets.randbelow() in "
        "Python, crypto.randomBytes() or crypto.randomUUID() in Node.",
    ),
    Entry(
        ("B101",), ("assert",),
        "Assertions are stripped when Python runs with optimisation (-O), so any check implemented "
        "as an assert silently disappears in production.",
        "Replace security-relevant assertions with explicit checks that raise real exceptions, for "
        "example: if not user.is_admin: raise PermissionError('admin required').",
    ),
    Entry(
        ("B201",), ("debug mode",),
        "Debug mode exposes interactive tracebacks and, in Flask and Werkzeug, a console that "
        "executes arbitrary code for anyone who can reach it.",
        "Never pass debug=True in production. Drive it from configuration, for example "
        "app.run(debug=os.environ.get('FLASK_DEBUG') == '1'), and serve production traffic through "
        "a WSGI server such as gunicorn.",
    ),
    Entry(
        ("B104",), ("all network interfaces", "0.0.0.0"),
        "The service listens on every network interface, exposing it to every network the machine "
        "is attached to rather than only the intended one.",
        "Bind to 127.0.0.1 for local-only services or to the specific interface that must serve "
        "traffic, preferably from configuration, and enforce the same restriction with a firewall.",
    ),
    Entry(
        ("B110", "B112"), ("silently ignored", "try/except"),
        "Exceptions are caught and discarded, hiding failures, including security-relevant ones, "
        "and leaving the program in an inconsistent state.",
        "Catch only the specific exceptions you can handle, log them with context "
        "(logger.exception), and let unexpected errors propagate.",
    ),
    Entry(
        ("B701", "B702", "B703", "B308", "B704"), ("autoescape", "mark_safe", "markup"),
        "Templates render variables without HTML escaping, enabling cross-site scripting through any "
        "value an attacker can influence.",
        "Enable autoescaping (Environment(autoescape=select_autoescape())) and reserve mark_safe or "
        "Markup for strings you built entirely yourself. Sanitise user-supplied rich HTML with a "
        "library such as bleach or nh3.",
    ),
    Entry(
        ("JS004", "JS005", "JS006", "JS007", "JS022"), ("xss", "innerhtml", "document.write"),
        "Content that may come from users is rendered as HTML without escaping, so injected script "
        "runs in every visitor's browser, enabling session theft and actions on their behalf.",
        "Write text with textContent or framework bindings instead of innerHTML. When HTML is "
        "required, sanitise it with DOMPurify.sanitize(). Encode output on the server, and add a "
        "Content-Security-Policy as defence in depth.",
    ),
    Entry(
        ("B108", "B306"), ("temporary file",),
        "A predictable temporary path lets another local user pre-create or swap the file, leading "
        "to data leaks or overwriting files through symlinks.",
        "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp(), which create files atomically with "
        "unique names and safe permissions.",
    ),
    Entry(
        ("B103", "DOCKER006"), ("permissions", "world-writable"),
        "Files are given permissions broader than needed, so other users or processes can read or "
        "modify them.",
        "Grant the minimum: 0o600 for secrets, 0o644 for readable files, 0o755 for executables. "
        "In Dockerfiles, use COPY --chown and chmod with specific modes instead of 777.",
    ),
    Entry(
        ("B113",), ("without a timeout",),
        "An HTTP request without a timeout can hang forever, letting a slow or malicious server "
        "exhaust the application's workers.",
        "Always pass a timeout, for example requests.get(url, timeout=(5, 30)), and handle "
        "requests.Timeout explicitly.",
    ),
    Entry(
        ("B202",), ("tar archive", "tarfile"),
        "Extracting an archive without validating member paths lets entries such as ../../etc/cron.d "
        "write anywhere the process can.",
        "On Python 3.12+ use tar.extractall(path, filter='data'). Otherwise validate each member's "
        "resolved path stays inside the destination before extracting.",
    ),
    Entry(
        ("B310",), ("scheme validation",),
        "urlopen accepts file:// and custom schemes, so a user-controlled URL can read local files.",
        "Validate that the URL scheme is http or https before opening it, or use requests, which "
        "does not support file:// URLs.",
    ),
    Entry(
        ("B312", "B321", "B401", "B402"), ("telnet", "ftp"),
        "The protocol transmits everything, including credentials, in cleartext.",
        "Replace Telnet with SSH (paramiko) and FTP with SFTP or FTPS.",
    ),
    Entry(
        ("JS014", "JS015"), ("jwt ",),
        "Token validation is weakened, so forged or expired tokens are accepted as genuine.",
        "Pin the expected algorithm, for example jwt.verify(token, key, { algorithms: ['HS256'] }), "
        "never allow 'none', and keep expiry checks enabled with short-lived tokens.",
    ),
    Entry(
        ("JS017",), ("cors policy", "allow-origin"),
        "A wildcard CORS policy lets any website read responses from this API in a victim's browser.",
        "Allow an explicit list of trusted origins, for example cors({ origin: ['https://app.example.com'] }), "
        "and never combine wildcards with credentials.",
    ),
    Entry(
        ("JS018",), ("prototype",),
        "Writing to an object's prototype changes the behaviour of every object in the process and "
        "can bypass security checks or lead to code execution.",
        "Reject __proto__, constructor and prototype keys when merging user input, create lookup "
        "maps with Object.create(null) or Map, and freeze Object.prototype in sensitive services.",
    ),
    Entry(
        ("JS021",), ("redirect",),
        "Redirecting to a user-supplied URL lets attackers use your trusted domain to send victims "
        "to phishing pages.",
        "Redirect only to relative paths or an allowlist of known destinations, and reject absolute "
        "URLs from request data.",
    ),
    Entry(
        ("JS023",), ("path traversal",),
        "A file path is built from request input, so sequences such as ../ can reach files outside "
        "the intended directory.",
        "Resolve the path with path.resolve(base, input) and verify it starts with the base "
        "directory plus a separator before any file operation. Prefer looking files up by id.",
    ),
    Entry(
        ("JS024",), ("localstorage",),
        "Tokens in localStorage are readable by any script on the page, so a single XSS bug leaks "
        "every user's session.",
        "Keep session tokens in HttpOnly, Secure, SameSite cookies set by the server.",
    ),
    Entry(
        ("JS025",), ("postmessage",),
        "Messages sent with target origin '*' can be received by any page that embeds or opens this "
        "window.",
        "Pass the exact expected origin to postMessage, and check event.origin in message handlers.",
    ),
    Entry(
        ("DOCKER001",), ("runs as root",),
        "The container process runs as root, so any compromise of the application is root inside "
        "the container and one kernel or runtime bug away from the host.",
        "Create and switch to an unprivileged user in the final stage: RUN useradd --system --uid "
        "10001 app, then USER app. Also run with a read-only root filesystem and dropped "
        "capabilities where possible.",
    ),
    Entry(
        ("DOCKER002",), ("not pinned",),
        "Unpinned base images change underneath you, so builds are not reproducible and can pull in "
        "unreviewed or compromised software.",
        "Pin a specific version tag, and for production pin the digest: FROM python:3.12.4-slim@sha256:<digest>. "
        "Update deliberately with a tool such as Renovate or Dependabot.",
    ),
    Entry(
        ("DOCKER003", "DOCKER004"), ("remote url", "piped into a shell"),
        "Remote content is fetched and used without integrity verification, so whoever controls the "
        "server or the network path controls what runs in your build.",
        "Download with curl, verify a published checksum or signature (sha256sum -c), then execute. "
        "Prefer distribution packages or COPY of vendored, reviewed files.",
    ),
    Entry(
        ("DOCKER007",), ("sudo",),
        "sudo inside an image usually means the runtime user can escalate to root.",
        "Run privileged build steps before switching USER, and do not install sudo in runtime images.",
    ),
    Entry(
        ("DOCKER009",), ("ssh port", "ssh server"),
        "An SSH daemon inside a container adds credentials to manage and a network service to attack.",
        "Remove the SSH server; use docker exec or kubectl exec for access.",
    ),
    Entry(
        ("B612", "B613", "B615"), ("trojan source", "logging.config", "hugging face"),
        "The code uses a construct that can execute or load untrusted content in a non-obvious way.",
        "Follow the Bandit guidance linked in the references, pin remote artefacts to exact "
        "revisions, and review the flagged line carefully.",
    ),
)
