from backend.core.scoring import compute_risk
from backend.schemas import Finding, Severity


def _findings(*severities, confidence=0.8):
    return [Finding(title="x", severity=s, confidence=confidence) for s in severities]


def test_clean_codebase_scores_a():
    risk = compute_risk([])
    assert (risk.score, risk.grade) == (100, "A")


def test_info_findings_do_not_cost_points():
    assert compute_risk(_findings(Severity.INFO, Severity.INFO)).score == 100


def test_single_medium_still_grades_well():
    assert compute_risk(_findings(Severity.MEDIUM)).grade == "A"


def test_critical_caps_the_grade_to_f():
    risk = compute_risk(_findings(Severity.CRITICAL, confidence=0.1))
    assert risk.score <= 39 and risk.grade == "F"


def test_high_caps_the_grade_below_c():
    risk = compute_risk(_findings(Severity.HIGH, confidence=0.1))
    assert risk.score <= 69 and risk.grade == "D"


def test_score_never_increases_when_findings_are_added():
    findings = []
    previous = 100
    for severity in [Severity.LOW, Severity.MEDIUM, Severity.LOW, Severity.HIGH, Severity.MEDIUM] * 4:
        findings += _findings(severity)
        score = compute_risk(findings).score
        assert score <= previous
        previous = score
    assert 0 <= previous < 40
