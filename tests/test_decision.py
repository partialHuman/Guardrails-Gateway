from app.core.analyzer import decide, evaluate
from app.schemas import Decision


def test_allow():

    assert decide(0) == Decision.ALLOW


def test_transform():

    assert decide(50) == Decision.TRANSFORM


def test_block():

    assert decide(90) == Decision.BLOCK


def test_threshold_edges():
    assert decide(39) == Decision.ALLOW
    assert decide(40) == Decision.TRANSFORM
    assert decide(79) == Decision.TRANSFORM
    assert decide(80) == Decision.BLOCK


def test_clean_request_is_allowed_untouched():
    result = evaluate("Hello there", [("d1", "Company handbook.")])

    assert result.decision == Decision.ALLOW
    assert result.sanitized_prompt == "Hello there"
    assert result.sanitized_docs == [("d1", "Company handbook.")]


def test_redaction_forces_transform_even_when_score_is_low():
    # Regression: an email alone scores 15 (below the transform threshold)
    # but must still be redacted and flagged as modified.
    result = evaluate("Contact me at john@gmail.com")

    assert result.risk_score < 40
    assert result.decision == Decision.TRANSFORM
    assert "john@gmail.com" not in result.sanitized_prompt
