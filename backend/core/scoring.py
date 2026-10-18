"""Risk scoring: condenses a list of findings into a 0-100 score and a letter grade.

Each finding contributes a penalty weighted by severity and scanner confidence.
The score decays exponentially with the total penalty, so the first issues hurt
the most and the scale never goes negative. A single critical or high finding
caps the grade regardless of how clean the rest of the codebase is.
"""
from __future__ import annotations

import math
from collections.abc import Iterable

from backend.schemas import Finding, RiskScore, Severity

_WEIGHTS = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 10.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 0.5,
    Severity.INFO: 0.0,
}

_CAPS = {
    Severity.CRITICAL: 39,
    Severity.HIGH: 69,
}

_GRADES = (
    (90, "A", "Excellent"),
    (80, "B", "Good"),
    (70, "C", "Fair"),
    (40, "D", "Poor"),
    (0, "F", "Critical"),
)

_DECAY = 60.0


def compute_risk(findings: Iterable[Finding]) -> RiskScore:
    penalty = 0.0
    present = set()
    for finding in findings:
        present.add(finding.severity)
        penalty += _WEIGHTS[finding.severity] * (0.5 + 0.5 * finding.confidence)

    score = int(round(100 * math.exp(-penalty / _DECAY)))
    for severity, cap in _CAPS.items():
        if severity in present:
            score = min(score, cap)

    for threshold, grade, label in _GRADES:
        if score >= threshold:
            return RiskScore(score=score, grade=grade, label=label)
    return RiskScore(score=score, grade="F", label="Critical")
