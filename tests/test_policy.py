from app.core.policy import POLICY


def test_policy_exists():
    assert POLICY is not None


def test_detectors_present():
    assert "prompt_injection" in POLICY["detectors"]
    assert "pii" in POLICY["detectors"]
    assert "rag_injection" in POLICY["detectors"]