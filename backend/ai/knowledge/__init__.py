"""Deterministic fallback explanations: the same finding always gets the same guidance."""
from __future__ import annotations

from backend.ai.knowledge.entries import ENTRIES, Entry
from backend.schemas import Finding

_BY_RULE: dict[str, Entry] = {}
for _entry in ENTRIES:
    for _rule in _entry.rule_ids:
        _BY_RULE.setdefault(_rule, _entry)


def _match(finding: Finding) -> Entry | None:
    entry = _BY_RULE.get(finding.rule_id)
    if entry is not None:
        return entry
    title = finding.title.lower()
    for candidate in ENTRIES:
        if any(keyword in title for keyword in candidate.keywords):
            return candidate
    return None


def _dependency_guidance(finding: Finding) -> tuple[str, str]:
    meta = finding.metadata
    package = meta.get("package", "this package")
    version = meta.get("version", "")
    advisory = meta.get("advisory", finding.rule_id)
    fixed = meta.get("fixed_version")
    why = (
        f"{package} {version} is affected by {advisory}: {finding.description.split(' (')[0]} "
        "Known vulnerabilities in dependencies are among the most exploited weaknesses because "
        "public advisories tell attackers exactly what to target."
    ).strip()
    if fixed:
        fix = (
            f"Upgrade {package} to {fixed} or later, regenerate the lockfile, and run the test suite. "
            "If the upgrade is blocked, check the advisory for a workaround and confirm whether the "
            "vulnerable code path is reachable from your application."
        )
    else:
        fix = (
            f"No patched release of {package} is listed yet. Check the advisory for mitigations, "
            "consider an alternative package, and isolate or disable the affected functionality "
            "until a fix ships."
        )
    return why, fix


def explain_from_knowledge(finding: Finding) -> tuple[str, str]:
    """Returns (why, fix). Never raises and never varies for the same input."""
    if finding.engine == "dependencies":
        return _dependency_guidance(finding)
    entry = _match(finding)
    if entry is not None:
        return entry.why, entry.fix
    where = finding.location or "this location"
    why = (
        f"The scanner flagged '{finding.title}' at {where} with {finding.severity.value} severity. "
        f"{finding.description} Treat it as a genuine weakness until it has been reviewed and "
        "dismissed with a reason."
    ).replace("  ", " ")
    fix = (
        "Review the code shown, then apply the relevant guidance from the OWASP Cheat Sheet Series "
        "or the linked references. Record what you changed and re-scan to confirm the finding is gone."
    )
    return why, fix


__all__ = ["explain_from_knowledge"]
