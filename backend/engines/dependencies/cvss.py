"""CVSS v3.x base score calculation, used when an advisory carries no severity label."""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _round_up(value: float) -> float:
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def _parse(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    return metrics


def base_score(vector: str) -> float | None:
    """Returns the CVSS v3 base score for a vector string, or None if it is not v3."""
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None
    metrics = _parse(vector)
    try:
        scope_changed = metrics["S"] == "C"
        privileges = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        impact_base = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * privileges * _UI[metrics["UI"]]
    except KeyError:
        return None

    if scope_changed:
        impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
    else:
        impact = 6.42 * impact_base
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _round_up(min(1.08 * (impact + exploitability), 10))
    return _round_up(min(impact + exploitability, 10))
