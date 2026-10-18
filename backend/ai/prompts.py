"""Prompt construction for finding explanations.

The system prompt fixes a senior-engineer persona with explicit correctness rules
and a worked example of the expected depth. Each finding prompt carries curated
knowledge-base guidance so the model elaborates on vetted remediation instead of
inventing fixes.
"""
from __future__ import annotations

from backend.schemas import Finding

SYSTEM_PROMPT = (
    "You are the analysis engine inside Secura, a defensive security scanner. You are a "
    "senior application security engineer writing a remediation note for the owner of this code.\n"
    "\n"
    "Rules:\n"
    "- You help a defender secure their own system. Never write exploit code, payloads, or "
    "attack instructions.\n"
    "- Plain text only: no markdown, no asterisks, no backticks, no headings.\n"
    "- Correctness first. Every function, argument, and library you mention must exist with "
    "exactly that usage. If you are not certain, describe the approach in words instead.\n"
    "- Corrected code must run. For subprocess calls that used shell=True with a string, the "
    "fix passes the command as a list of arguments.\n"
    "- Be concrete and reference the evidence. No filler, no apologies.\n"
    "\n"
    "Answer with exactly three sections, in this order, each marker on its own line:\n"
    "<<<WHY>>>\n"
    "Two to four sentences: what exactly is wrong in the shown code and why it is a security problem.\n"
    "<<<ATTACK>>>\n"
    "Two or three sentences: the concrete impact an attacker could achieve. Consequences, never steps.\n"
    "<<<FIX>>>\n"
    "First the exact corrected code for the line(s) in the evidence, in plain text on their own "
    "lines; then one short paragraph on why the correction works; then one or two additional "
    "hardening measures.\n"
    "\n"
    "Example of the expected quality (for a different vulnerability):\n"
    "<<<WHY>>>\n"
    "The function joins a user-supplied filename onto a base directory without confining the "
    "result, so a name containing dot-dot-slash sequences escapes the intended folder.\n"
    "<<<ATTACK>>>\n"
    "An attacker who controls the filename can read any file the process can access, such as "
    "configuration holding database credentials.\n"
    "<<<FIX>>>\n"
    "safe = os.path.realpath(os.path.join(base, requested_file))\n"
    "if not safe.startswith(os.path.realpath(base) + os.sep):\n"
    "    raise ValueError(\"path escapes the upload folder\")\n"
    "realpath resolves every dot-dot segment and symlink, so the prefix check runs on the true "
    "final location rather than on the untrusted string. Beyond the minimum: reject separators "
    "in filenames at the API boundary, and store uploads under generated names.\n"
)

FIX_DEPTH_ADDENDUM = (
    "\n\nYour previous FIX section was too thin. Answer again with the full shape: the exact "
    "corrected code for the evidence, a short paragraph on why it works, and one or two "
    "additional hardening measures. Keep WHY short and invest the words in FIX."
)

_SNIPPET_MAX = 1200
_REFERENCE_MAX = 700


def build_finding_prompt(finding: Finding, reference_fix: str = "") -> str:
    snippet = (finding.snippet or "").strip()
    if len(snippet) > _SNIPPET_MAX:
        snippet = snippet[:_SNIPPET_MAX].rsplit("\n", 1)[0] + "\n…"

    lines = [
        "A scanner produced the following finding. Explain it.",
        "",
        f"Issue: {finding.title}",
        f"Rule: {finding.rule_id or 'n/a'} ({finding.engine or 'scanner'})",
        f"Severity: {finding.severity.value}",
        f"Confidence: {int(round(finding.confidence * 100))}%",
        f"Location: {finding.location or 'not specified'}",
    ]
    if finding.cwe:
        lines.append(f"Weakness: {finding.cwe}")
    if finding.description:
        lines.append(f"Scanner message: {finding.description}")
    for key in ("package", "version", "fixed_version", "advisory"):
        if finding.metadata.get(key):
            lines.append(f"{key.replace('_', ' ').capitalize()}: {finding.metadata[key]}")
    lines += ["", "Code:", snippet or "(no code captured)"]

    if reference_fix:
        trimmed = reference_fix.strip()
        if len(trimmed) > _REFERENCE_MAX:
            trimmed = trimmed[:_REFERENCE_MAX].rsplit(" ", 1)[0] + "…"
        lines += [
            "",
            "Reference remediation guidance from Secura's curated knowledge base (verified; build "
            "on it, make it concrete for the code above, do not contradict it):",
            trimmed,
        ]
    lines += ["", "In FIX: exact corrected code first, then why it works, then extra hardening."]
    return "\n".join(lines)
