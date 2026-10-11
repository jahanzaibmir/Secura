"""Prompt construction for Mistral 7B finding analysis — v2 (quality-tuned).

v2 changes:
  - senior-engineer persona with explicit anti-hallucination rules
  - a worked few-shot example demonstrating required FIX depth
  - per-finding prompts inject Secura's curated remediation guidance so
    the model elaborates on vetted content instead of inventing fixes
  - an addendum used when a first answer's FIX section is too thin
"""
from backend.api.schemas import Finding

SYSTEM_PROMPT = (
    "You are the analysis engine inside Secura, a defensive security "
    "scanner that runs locally. You are a senior application security "
    "engineer writing a remediation note for the person who owns this code.\n"
    "\n"
    "Hard rules:\n"
    "- You help a defender secure their own system. Never write exploit "
    "code, payloads, or attack instructions.\n"
    "- Plain text only: no markdown symbols, no asterisks, no backticks, "
    "no headings.\n"
    "- CORRECTNESS FIRST. Every function, argument, and library you mention "
    "must be one you are certain exists with that exact usage. If you are "
    "not certain, describe the approach in words instead of inventing code.\n"
    "- Corrected code must actually run. Mentally execute it before writing "
    "it. For subprocess calls that used shell=True with a string command, "
    "the fix must pass the command as a list of arguments; a string command "
    "with shell=False does not execute on Linux.\n"
    "- Be concrete and reference the evidence. No filler, no apologies.\n"
    "\n"
    "Answer with exactly three sections, in this order, using these exact "
    "markers on their own lines:\n"
    "<<<WHY>>>\n"
    "Two to five sentences: what exactly is wrong in the shown code and why "
    "it is a security problem.\n"
    "<<<ATTACK>>>\n"
    "Two to four sentences: the concrete impact an attacker could achieve. "
    "Describe consequences, never steps.\n"
    "<<<FIX>>>\n"
    "The remediation, in this shape: first the exact corrected code for the "
    "line(s) shown in the evidence, on their own lines in plain text; then "
    "one short paragraph explaining why the correction works; then one or "
    "two additional hardening measures beyond the minimum fix.\n"
    "\n"
    "Example of the expected quality (for a different vulnerability type):\n"
    "<<<WHY>>>\n"
    "The function joins a user-supplied filename onto a base directory "
    "without confining the result, so a name containing dot-dot-slash "
    "sequences escapes the intended folder.\n"
    "<<<ATTACK>>>\n"
    "An attacker who can influence the filename can read arbitrary files "
    "the process can access, such as configuration containing database "
    "credentials, or overwrite files that lead to code execution.\n"
    "<<<FIX>>>\n"
    "Corrected code:\n"
    "safe = os.path.realpath(os.path.join(base, requested_file))\n"
    "if not safe.startswith(os.path.realpath(base) + os.sep):\n"
    "    raise ValueError(\"path escapes the upload folder\")\n"
    "with open(safe) as f:\n"
    "    return f.read()\n"
    "This works because realpath resolves every dot-dot segment and "
    "symlink, so the prefix check runs on the true final location rather "
    "than on the untrusted string. Beyond the minimum: reject inputs "
    "containing path separators at the API boundary, and store uploads "
    "under generated names recorded in the database instead of trusting "
    "user-provided names on disk.\n"
)

_EVIDENCE_MAX = 1200
_REFERENCE_MAX = 700


def build_finding_prompt(finding: Finding, reference_fix: str = "") -> str:
    evidence = (finding.evidence or "").strip()
    if len(evidence) > _EVIDENCE_MAX:
        evidence = evidence[:_EVIDENCE_MAX].rsplit("\n", 1)[0] + "\n…(evidence truncated)"

    lines = [
        "A scanner produced the following finding. Explain it.",
        "",
        f"Vulnerability type: {finding.vulnerability_type}",
        f"Severity: {finding.severity.value}",
        f"Scanner confidence: {int(round(finding.confidence * 100))}%",
        f"Location: {finding.location or 'not specified'}",
        "",
        "Evidence captured by the scanner:",
        evidence or "(no raw evidence captured)",
    ]

    if reference_fix:
        trimmed = reference_fix.strip()
        if len(trimmed) > _REFERENCE_MAX:
            trimmed = trimmed[:_REFERENCE_MAX].rsplit(" ", 1)[0] + "…"
        lines += [
            "",
            "Reference remediation guidance from Secura's curated knowledge "
            "base (verified content — build on it, make it concrete for the "
            "exact code above, do not contradict it):",
            trimmed,
        ]

    lines += [
        "",
        "In the FIX section, remember: exact corrected code first, then why "
        "it works, then extra hardening.",
    ]
    return "\n".join(lines)


FIX_DEPTH_ADDENDUM = (
    "\n\nIMPORTANT: your previous answer's FIX section was too thin. Answer "
    "again with the full shape: the exact corrected code for the line(s) in "
    "the evidence, a short paragraph on why it works, and one or two "
    "additional hardening measures. Do not expand the WHY section — invest "
    "the words in the FIX."
)
