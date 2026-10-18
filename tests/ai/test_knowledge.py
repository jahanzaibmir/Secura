from backend.ai.knowledge import explain_from_knowledge
from backend.ai.knowledge.entries import ENTRIES
from backend.engines.rules.bandit import ESCALATE_TO_CRITICAL
from backend.engines.rules.docker import INSTRUCTION_RULES, ROOT_USER, UNPINNED_IMAGE
from backend.engines.rules.javascript import RULES as JS_RULES
from backend.engines.rules.secrets import ENV_ASSIGNMENT, GENERIC_ASSIGNMENT
from backend.engines.rules.secrets import RULES as SECRET_RULES
from backend.schemas import Finding


def test_every_built_in_rule_has_curated_guidance():
    covered = {rule_id for entry in ENTRIES for rule_id in entry.rule_ids}
    rule_ids = (
        {r.rule_id for r in JS_RULES}
        | {r.rule_id for r in SECRET_RULES}
        | {GENERIC_ASSIGNMENT.rule_id, ENV_ASSIGNMENT.rule_id}
        | {r.rule_id for r in INSTRUCTION_RULES}
        | {ROOT_USER.rule_id, UNPINNED_IMAGE.rule_id}
        | set(ESCALATE_TO_CRITICAL)
    )
    assert rule_ids - covered == set()


def test_rule_id_takes_priority_over_title():
    why, fix = explain_from_knowledge(Finding(rule_id="B602", title="Something unrelated"))
    assert "shell" in why.lower() and "subprocess.run([" in fix


def test_keyword_fallback_and_generic_guidance():
    why, _ = explain_from_knowledge(Finding(title="Weak hash in custom check"))
    assert "collision" in why
    why, fix = explain_from_knowledge(Finding(title="Something exotic", file_path="a.py", line=3))
    assert "a.py:3" in why and "OWASP" in fix


def test_dependency_guidance_names_the_fixed_version():
    finding = Finding(engine="dependencies", rule_id="CVE-2019-10906", title="Vulnerable dependency: jinja2 2.10",
                      description="Sandbox escape (CVE-2019-10906). Upgrade to 2.10.1 or later.",
                      metadata={"package": "jinja2", "version": "2.10", "fixed_version": "2.10.1",
                                "advisory": "CVE-2019-10906"})
    why, fix = explain_from_knowledge(finding)
    assert "jinja2 2.10" in why and "Upgrade jinja2 to 2.10.1" in fix
