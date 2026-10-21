from app.core.policy import INJECTION_RULES, PII_RULES, POLICY


def test_policy_exists():
    assert POLICY is not None


def test_detectors_present():
    assert "prompt_injection" in POLICY["detectors"]
    assert "pii" in POLICY["detectors"]
    assert "rag_injection" in POLICY["detectors"]


def test_policy_exposes_thresholds_and_scoring():
    assert POLICY["thresholds"]["block_score"] > POLICY["thresholds"]["transform_score"]
    assert POLICY["scoring"]["extra_rule_bonus"] > 0


def test_policy_lists_every_rule():
    assert len(POLICY["injection_rules"]) == len(INJECTION_RULES)
    assert len(POLICY["pii_rules"]) == len(PII_RULES)


def test_rule_ids_are_unique():
    ids = [r.id for r in INJECTION_RULES] + list(PII_RULES)

    assert len(ids) == len(set(ids))
