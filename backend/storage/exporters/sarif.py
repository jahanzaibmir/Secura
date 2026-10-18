"""SARIF 2.1.0 export for GitHub code scanning, Azure DevOps and IDE integrations."""
from __future__ import annotations

import json

from backend.schemas import Finding, Report, Severity

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _rule_key(finding: Finding) -> str:
    return finding.rule_id or f"{finding.engine}:{finding.title}"


def _rule(finding: Finding) -> dict:
    tags = ["security", finding.engine or "secura"]
    if finding.cwe:
        tags.append(f"external/cwe/{finding.cwe.lower()}")
    rule: dict = {
        "id": _rule_key(finding),
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "precision": "high" if finding.confidence >= 0.8 else "medium" if finding.confidence >= 0.5 else "low",
        },
    }
    if finding.how_to_fix:
        rule["help"] = {"text": finding.how_to_fix}
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def to_sarif(report: Report) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for finding in report.findings:
        key = _rule_key(finding)
        rules.setdefault(key, _rule(finding))
        location: dict = {"physicalLocation": {"artifactLocation": {"uri": finding.file_path or "."}}}
        if finding.line:
            location["physicalLocation"]["region"] = {"startLine": finding.line}
        results.append({
            "ruleId": key,
            "level": _LEVEL[finding.severity],
            "message": {"text": finding.description or finding.title},
            "locations": [location],
            "partialFingerprints": {"secura/v1": finding.fingerprint or finding.finding_id},
            "properties": {
                "severity": finding.severity.value,
                "confidence": finding.confidence,
            },
        })

    document = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Secura",
                "version": report.tool_version,
                "informationUri": "https://github.com/jahanzaibmir/Secura",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"target": report.target, "reportId": report.report_id},
        }],
    }
    return json.dumps(document, indent=2)
