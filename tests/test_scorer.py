from app.core.findings import ACTION_REDACT, Finding
from app.core.scorer import calculate_score


def finding(rule_id, tag, severity, source="prompt"):
    return Finding(
        rule_id=rule_id, tag=tag, severity=severity, start=0, end=1,
        evidence="x", source=source, action=ACTION_REDACT, replacement="[x]",
    )


def test_no_findings():
    assert calculate_score([]) == (0, [])


def test_single_rule_uses_its_severity():
    assert calculate_score([finding("a", "prompt_injection", 50)]) == (
        50, ["prompt_injection"]
    )


def test_repeating_a_rule_does_not_raise_the_score():
    many = [finding("a", "prompt_injection", 50) for _ in range(100)]

    assert calculate_score(many)[0] == 50


def test_each_distinct_rule_adds_a_bonus():
    two = [finding("a", "prompt_injection", 50), finding("b", "prompt_injection", 45)]

    assert calculate_score(two)[0] == 60


def test_bonus_is_capped():
    many = [finding(str(i), "prompt_injection", 10) for i in range(20)]

    assert calculate_score(many)[0] == 10 + 30


def test_tags_are_summed_and_capped_at_100():
    findings = [
        finding("a", "prompt_injection", 50),
        finding("b", "rag_injection", 50),
        finding("c", "pii", 40),
    ]

    score, tags = calculate_score(findings)

    assert score == 100
    assert tags == ["pii", "prompt_injection", "rag_injection"]


def test_pii_alone_stays_below_the_transform_threshold():
    assert calculate_score([finding("email", "pii", 15)])[0] == 15
