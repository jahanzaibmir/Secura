"""Rule-based guidance — the deterministic fallback when Mistral is unavailable
or when a scan exceeds the AI budget.

Every rule maps keywords in the vulnerability type to a concrete why/fix pair.
This is intentionally conservative, plain-English, and never generated — the
same input always produces the same guidance, so it can be trusted as a floor
even when the AI layer is completely offline.
"""
from typing import List, Tuple

from backend.api.schemas import Finding

# (keywords matched against the lowercase vulnerability type, why, fix)
# Order matters: specific rules first, generic catch-alls last.
_RULES: List[Tuple[Tuple[str, ...], str, str]] = [
    (("sql injection", "hardcoded sql"),
     "The application builds SQL by joining strings, so anything that reaches the "
     "query can change its meaning. A crafted input can alter the query to read "
     "other tables, dump the entire database, or in some configurations write "
     "files and reach code execution.",
     "Replace every string-built query with a parameterized query or prepared "
     "statement (e.g. cursor.execute('... WHERE name = ?', (name,))). If you use "
     "an ORM, keep filters parameterized. Give the application a least-privilege "
     "database account so a successful injection cannot read unrelated data."),
    (("command injection", "shell injection"),
     "Untrusted input is passed to an operating-system command, so an attacker "
     "can append their own commands and they will run with the privileges of "
     "the application.",
     "Avoid invoking a shell: pass commands as an argument list "
     "(subprocess.run([...]), never with shell=True. If a fixed set of values is "
     "legitimate, validate against an allowlist. Run the service under a "
     "dedicated low-privilege account."),
    (("partial path", "wildcard injection"),
     "The code launches a process using a partial or wildcard path, so which "
     "binary actually runs depends on the caller's environment and PATH — a "
     "substitution risk.",
     "Invoke binaries by absolute path, and avoid unquoted wildcards in shell "
     "commands."),
    (("eval", "exec(", "code injection", "new function"),
     "The code executes a string as program code. If any part of that string can "
     "be influenced by input or data files, an attacker can execute arbitrary "
     "code inside the application process.",
     "Remove the dynamic execution. Parse data with json.loads or "
     "ast.literal_eval instead. If you must evaluate expressions, use a "
     "purpose-built sandboxed evaluator. Never pass user-controlled strings to "
     "eval, exec, or Function()."),
    (("hardcoded password", "hardcoded secret", "api key", "private key", "aws"),
     "A credential is embedded in the source code. Anyone who can read the "
     "repository or a built artifact obtains a working credential, and it cannot "
     "be rotated without shipping new code.",
     "Move the value to an environment variable or a secrets manager and load it "
     "at startup. Rotate the exposed credential immediately — assume it is "
     "compromised. Remove it from version history (git filter-repo or BFG) and "
     "add the file to .gitignore."),
    (("pickle", "marshal", "insecure deserialization"),
     "Deserializing untrusted bytes with pickle or marshal can construct "
     "arbitrary objects, which effectively executes attacker-chosen code during "
     "deserialization.",
     "Use a safe data format such as JSON. If pickle is unavoidable, only "
     "deserialize data you produced and signed, and verify an HMAC before "
     "unpickling. Never accept pickled data across a network boundary."),
    (("yaml",),
     "Loading YAML with unsafe loaders allows arbitrary Python objects to be "
     "constructed during parsing, which gives code execution from a crafted "
     "document.",
     "Switch to yaml.safe_load (and safe_dump). If custom tags are truly "
     "required, validate the input first and register only explicitly allowed "
     "constructors."),
    (("xml", "xxe"),
     "XML is parsed with external entities enabled, which can read local files "
     "or make the server issue requests to internal systems.",
     "Disable DTD processing and external entities (defusedxml, or the hardening "
     "flags of your parser). Never accept XML from untrusted sources without "
     "these settings."),
    (("path traversal", "directory traversal"),
     "File paths are built from input without confining them to a base "
     "directory, so sequences like ../ can escape the intended folder and read "
     "or overwrite arbitrary files the process can access.",
     "Reject any input containing path separators or '..'. Resolve the final "
     "path with os.path.realpath and verify it is still inside the allowed base "
     "directory before opening. Prefer referencing files by database ID rather "
     "than by name."),
    (("signed with a weak hash",),
     "The TLS certificate is signed with a collision-broken hash (MD5 or SHA-1), "
     "which undermines the binding between the certificate and the issuer's "
     "signature.",
     "Reissue the certificate with SHA-256 or stronger. Any modern CA does this "
     "by default, so the underlying cause is usually an outdated private CA or "
     "an ancient server configuration."),
    (("weak hash", "md5", "sha1"),
     "The code relies on a hash that is collision-broken. Where hashes are used "
     "for integrity or signatures, an attacker can craft a second file with the "
     "same hash.",
     "Use SHA-256 or stronger for integrity checks. If the hash protects "
     "passwords, switch to a dedicated password hash: argon2, bcrypt, or scrypt "
     "with sensible cost parameters."),
    (("outdated tls", "weak tls", "tls protocol", "tls cipher", "ssl version",
      "tls version", "weak ssl"),
     "The server still negotiates deprecated protocols or weak ciphers that lack "
     "modern protections and have known attacks.",
     "Disable SSLv3, TLS 1.0 and 1.1. Require TLS 1.2 as the minimum and enable "
     "TLS 1.3. Restrict the cipher list to modern AEAD suites and enable OCSP "
     "stapling."),
    (("weak cipher", "weak crypto", "insecure cipher", "weak cryptographic"),
     "The configuration or code permits cryptography that is considered broken, "
     "which undermines the confidentiality and integrity the system claims to "
     "provide.",
     "Use modern authenticated encryption: AES-GCM or ChaCha20-Poly1305. For "
     "transport security require TLS 1.2+ (prefer 1.3) and remove legacy "
     "ciphers from the allowed list."),
    (("random", "non-cryptographic"),
     "The random module is predictable: its output can be reconstructed from "
     "observed values. Tokens, passwords, or session ids produced this way can "
     "be guessed.",
     "Use the secrets module (or os.urandom) for anything security-relevant. "
     "Reserve the random module for simulations and games."),
    (("assert",),
     "Assertions are removed when Python runs with optimization (-O), so any "
     "check implemented as assert silently disappears in production. If an "
     "assertion guards a security condition, that guard is not really there.",
     "Replace security-relevant assertions with explicit checks that raise real "
     "exceptions. Keep assertions for internal sanity checks only."),
    (("debug mode",),
     "Debug mode exposes interactive tracebacks and, for many frameworks, a "
     "code-execution console. An attacker who can reach a debug page can often "
     "execute arbitrary code on the server.",
     "Disable debug mode in production configuration and make it impossible to "
     "enable through user input. Ensure production settings are selected by "
     "environment, not by request parameters."),
    (("binding to all", "0.0.0.0"),
     "The service listens on every network interface, which exposes it to every "
     "network the machine is attached to, not just the intended one.",
     "Bind to the specific interface the service must serve, or 127.0.0.1 if it "
     "is only consumed locally. Enforce the same restriction with a host "
     "firewall."),
    (("silent exception", "try/except/pass", "blind except"),
     "Exceptions are caught and discarded, which hides failures — including the "
     "security-relevant ones — and leaves the system in an inconsistent state.",
     "Catch only the specific exceptions you can meaningfully handle, log them "
     "with context, and let unexpected ones propagate. Never use a bare "
     "except: pass around security checks."),
    (("jinja", "mako", "autoescape", "mark_safe"),
     "Templating is used with escaping disabled, so template variables render "
     "as raw HTML and enable server-side or cross-site scripting.",
     "Enable autoescaping for the template engine, or use mark_safe only on "
     "strings you constructed and fully control. Validate or sanitize anything "
     "that reaches templates as HTML."),
    (("xss", "innerhtml", "document.write", "dangerouslysetinnerhtml", "reflected"),
     "Content that originates from users or other sources is rendered as HTML "
     "without escaping, so injected script runs in the browsers of anyone who "
     "views the page — session theft and unauthorized account actions follow.",
     "Escape output according to context: prefer textContent over innerHTML, "
     "use your template engine's autoescaping, and sanitize rich HTML with an "
     "established library such as DOMPurify. Add a Content-Security-Policy as a "
     "second line of defense."),
    (("csrf",),
     "State-changing requests carry no token, so a page on another site can "
     "silently trigger actions in a logged-in user's session.",
     "Add per-session anti-CSRF tokens to every state-changing form and verify "
     "them server-side. Set SameSite=Lax or Strict on session cookies, and "
     "verify the Origin header for sensitive operations."),
    (("strict-transport", "hsts"),
     "Without HSTS, the first request — or any forced downgrade to http — can "
     "be intercepted and rewritten by an attacker on the same network.",
     "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once "
     "you are confident HTTPS works everywhere, and consider submitting the "
     "domain to the HSTS preload list."),
    (("content-security-policy",),
     "No CSP restricts where scripts and other resources may load from, so any "
     "injected script runs with full page privileges.",
     "Deploy a restrictive Content-Security-Policy. Start from default-src "
     "'self' and add only what the application needs; prefer nonce- or "
     "hash-based script rules over unsafe-inline."),
    (("nosniff", "x-content-type"),
     "Without nosniff, browsers may guess a content type different from the "
     "declared one and execute uploads as active content.",
     "Send X-Content-Type-Options: nosniff on every response, and always "
     "declare accurate Content-Type headers."),
    (("clickjacking", "x-frame-options", "frame-ancestors"),
     "The page can be embedded in an attacker's iframe and overlaid with "
     "invisible elements, tricking users into clicking actions they cannot see.",
     "Send X-Frame-Options: DENY (or SAMEORIGIN), or a modern CSP with "
     "frame-ancestors. Do this for every page with buttons or forms."),
    (("cookie",),
     "Cookies are set without the standard protective attributes, which exposes "
     "them to theft over cleartext, to JavaScript (and therefore XSS), and to "
     "cross-site sending.",
     "Append the attributes: Secure (HTTPS only), HttpOnly (invisible to "
     "JavaScript) for session cookies, and an explicit SameSite policy (Lax or "
     "Strict). Configure these centrally in the framework, not per call site."),
    (("invalid tls", "verification failed", "chain does not resolve",
      "certificate verification failed"),
     "The server's certificate failed verification, so clients cannot "
     "authenticate it; browsers warn users and the connection is open to "
     "interception.",
     "Diagnose the failure — expired, wrong hostname, or incomplete chain — "
     "then fix it: renew or reissue the certificate and serve the full chain "
     "including intermediates."),
    (("has expired", "expired", "expiring soon", "not yet valid"),
     "The TLS certificate is outside its validity window or not yet active, so "
     "clients cannot establish trust; users see warnings, and connections are "
     "open to interception.",
     "Renew the certificate before it expires and automate renewal with ACME "
     "(for example, certbot). Verify the system clock, and make sure the "
     "certificate covers every hostname the service answers on."),
    (("hostname", "certificate does not match"),
     "The certificate presented does not cover the name the client asked for, "
     "so the client cannot authenticate the server and the connection can be "
     "intercepted.",
     "Reissue the certificate with the correct name in the SAN list, or route "
     "clients by the name the certificate actually covers. Do not disable "
     "hostname verification to make the warning disappear."),
    (("self-signed",),
     "The certificate vouches for itself, so clients have no way to distinguish "
     "the real server from an impostor performing a man-in-the-middle attack.",
     "Issue a certificate from a CA your clients trust — Let's Encrypt for "
     "public names, or an internal CA whose root is distributed to clients. If "
     "a self-signed certificate must stay, pin it explicitly in the clients."),
    (("version disclosure", "stack disclosure", "banner"),
     "The service advertises its exact software and version, letting attackers "
     "match it to known exploits before sending a single probe.",
     "Suppress version information: server_tokens off (nginx), ServerTokens "
     "Prod (Apache), and remove X-Powered-By. This is defense in depth, not a "
     "fix on its own — keep the software patched regardless."),
    (("docker",),
     "The Docker API is reachable over the network. It typically has no "
     "authentication, and anyone who can reach it can start containers, mount "
     "the host filesystem, and effectively become root on the machine.",
     "Do not expose the Docker daemon over TCP. Keep it on the unix socket, "
     "restrict access to the docker group, and put a firewall in front. If "
     "remote access is truly required, use TLS with client-certificate "
     "authentication on port 2376."),
    (("redis", "memcached"),
     "An in-memory data store is exposed to the network, commonly without "
     "authentication. Attackers can read or corrupt cached data, and in default "
     "configurations abuse features to write files toward code execution or "
     "amplification attacks.",
     "Bind the service to 127.0.0.1 or an internal interface, enable "
     "authentication (requirepass / SASL), disable dangerous commands where "
     "possible, and block the port at the firewall."),
    (("mongodb", "elasticsearch", "etcd"),
     "A data store that usually ships without authentication is reachable from "
     "the network, so its entire contents — and often administrative "
     "operations — are available to anyone.",
     "Enable authentication and TLS, bind the service to an internal interface, "
     "and restrict access with a firewall. Assume the stored data is exposed "
     "until you have verified the configuration."),
    (("kubernetes", "kubelet"),
     "The kubelet API is exposed. Depending on its flags, anonymous requests "
     "can read pod configuration or execute commands inside containers.",
     "Run with --anonymous-auth=false, require webhook or certificate "
     "authentication, restrict the API to internal networks, and enforce a "
     "NetworkPolicy so only authorized components reach it."),
    (("telnet", "rsh", "rlogin", "rexec", "cleartext"),
     "The service transmits everything — including login credentials — "
     "unencrypted, so anyone on the path can read and modify the session.",
     "Replace the service with its encrypted equivalent: SSH instead of "
     "telnet/rsh, SFTP or SCP instead of FTP. Until it is replaced, restrict "
     "source addresses with a firewall."),
    (("ftp",),
     "FTP authenticates and transfers data in cleartext, so credentials and "
     "files are readable on the network path.",
     "Replace FTP with SFTP or FTPS. If legacy clients require plain FTP, "
     "isolate it to an internal network segment and treat every credential "
     "used over it as public knowledge."),
    (("vnc",),
     "A remote desktop service is exposed. VNC is frequently deployed with weak "
     "or absent authentication, and a successful login is full interactive "
     "control of the desktop.",
     "Put VNC behind a VPN or an SSH tunnel, set a strong password, and "
     "restrict source addresses with a firewall. Prefer modern alternatives "
     "with built-in encryption."),
    (("smb", "netbios"),
     "Windows file sharing is exposed to the network. Unpatched SMB endpoints "
     "are a primary entry point for worms and ransomware, and misconfigured "
     "shares leak data.",
     "Block ports 139/445 at the perimeter, keep the host patched, require SMB "
     "signing, and disable anonymous access to shares."),
    (("rdp",),
     "Remote Desktop is exposed and is a high-value target for brute-force and "
     "credential-stuffing attacks.",
     "Place RDP behind a VPN, require Network Level Authentication, enable "
     "account lockout policies, and consider MFA for remote access."),
    (("sql server", "mysql", "postgresql", "oracle", "database"),
     "A database server is directly reachable from the network. Combined with "
     "brute-force or leaked credentials, this bypasses the application "
     "entirely and exposes all stored data.",
     "Bind the database to an internal interface and enforce firewall rules so "
     "only application servers reach it. Use strong, non-default credentials, "
     "least-privilege accounts per application, and encrypt connections with "
     "TLS."),
    (("spf", "dmarc"),
     "The domain publishes no SPF or DMARC policy, so anyone can send email "
     "that claims to be from it. Receivers have no instruction to reject or "
     "quarantine spoofed mail, which enables phishing of your users and "
     "partners.",
     "Publish an SPF record listing your legitimate mail sources, set up DKIM "
     "signing, and add a DMARC record — start at p=none with reporting, then "
     "move to quarantine or reject."),
    (("directory listing",),
     "The web server lists the contents of directories, revealing files an "
     "attacker would otherwise have to guess: backups, source, configuration.",
     "Disable automatic directory indexes (Options -Indexes on Apache, "
     "autoindex off on nginx) and remove files that should not be served "
     "at all."),
    (("trace", "cross-site tracing"),
     "The server answers HTTP TRACE requests by echoing the request back, "
     "which can be combined with cross-site scripting to read HttpOnly "
     "cookies.",
     "Disable the TRACE method in the web server configuration and reject it "
     "with a 405."),
    (("environment file",),
     "The .env file is served over the web. Environment files routinely "
     "contain database credentials, API keys, and encryption secrets — "
     "everything an attacker needs to move deeper.",
     "Block web access to dotfiles and to .env in the server configuration, "
     "move the file outside the served root, rotate every secret it contained, "
     "and remove it from version history if it was committed."),
    (("git repository",),
     "The .git directory is served over the web. It contains the full source "
     "history and often committed-then-deleted secrets, giving attackers a map "
     "of the entire application.",
     "Block access to .git in the web server configuration, deploy built "
     "artifacts instead of working copies, and rotate any secrets that appear "
     "in the history."),
    (("cleartext http",),
     "The site answers on plain HTTP without redirecting, so traffic — "
     "including credentials and session cookies — is readable and modifiable "
     "by anyone on the network path.",
     "Redirect all HTTP requests to HTTPS with a 301, serve HSTS on the HTTPS "
     "side, and set the Secure attribute on cookies."),
    (("subdomain",),
     "Additional subdomains resolve publicly. Forgotten subdomains — old "
     "staging servers, deprecated apps — are a classic breach vector because "
     "nobody patches them.",
     "Inventory every DNS record, remove entries that are no longer used, and "
     "bring the rest up to the same hardening standard as the main site."),
    (("certificate verification", "ssl context", "insecure request"),
     "The code disables TLS certificate verification, so the connection can be "
     "silently intercepted — the encryption protects nothing against an active "
     "attacker.",
     "Restore verification (verify=True / default SSL context). For internal "
     "services, add the internal CA to the trust store instead of disabling "
     "checks."),
    (("exposed", "open port"),
     "A network service is reachable that appears unnecessary or risky in this "
     "position. Every listening service is attack surface: it can be probed, "
     "exploited, or abused for amplification.",
     "Close the port if the service is unused, and bind remaining services to "
     "the interfaces they must serve. Allow only required ports through the "
     "firewall, and keep every exposed service patched and monitored."),
]


def fallback_explanation(finding: Finding) -> Tuple[str, str]:
    """Deterministic (why, fix) for a finding. Never raises, never varies."""
    vuln_type = (finding.vulnerability_type or "").lower()
    for keywords, why, fix in _RULES:
        if any(keyword in vuln_type for keyword in keywords):
            return why, fix
    return _generic(finding)


def _generic(finding: Finding) -> Tuple[str, str]:
    severity = finding.severity.value
    where = finding.location or "this target"
    why = (
        f"The scanner flagged '{finding.vulnerability_type}' at {where} with "
        f"{severity} severity. The evidence below shows the exact code or "
        "configuration of concern. Treat it as a genuine weakness until "
        "someone has reviewed and dismissed it with a reason."
    )
    fix = (
        "Read the evidence below, then check the relevant authoritative "
        "guidance — the OWASP Cheat Sheet Series for application issues, "
        "vendor hardening guides for infrastructure. Apply the remediation, "
        "note what you changed, and re-scan to confirm the finding disappears."
    )
    return why, fix
