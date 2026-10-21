import logging
import base64
import pytest
import app.core.detectors as detectors

from app.config import _int_env
from app.core.logger import configure_logger
from app.core.detectors import _decode_base64
from app.utils.validators import luhn_valid, verhoeff_valid

from app.core.detectors import (
    MAX_BASE64_CANDIDATES,
    _decode_base64,
    _trim_international,
    detect_pii,
)

from app.core.detectors import (
    BASE64_PATTERN,
    MAX_BASE64_CANDIDATES,
    _detect_encoded_injection,
    _trim_international,
)


def test_encoded_injection_stops_at_candidate_limit():
    token = "SGVsbG8="  # Base64 for "Hello"
    assert BASE64_PATTERN.search(token)

    text = " ".join([token] * (MAX_BASE64_CANDIDATES + 1))

    assert _detect_encoded_injection(
        text, "prompt", "test", "prompt_injection"
    ) == []


def test_detect_pii_skips_rejected_international_candidate():
    # A matched international candidate with too few digits is rejected.
    from app.core.detectors import detect_pii

    assert _trim_international("+12 345") is None
    assert not any(f.rule_id == "phone" for f in detect_pii("+12 345"))


def test_decode_base64_rejects_mostly_non_printable_text():
    token = base64.b64encode(b"A\x01\x02\x03\x04\x05\x06\x07\x08\x09").decode("ascii")
    assert _decode_base64(token) is None


def test_encoded_injection_stops_at_candidate_limit():
    # Include more candidates than the detector is configured to inspect.
    candidates = ["SGVsbG8="] * (MAX_BASE64_CANDIDATES + 1)
    text = " ".join(candidates)

    # The detector should safely process input containing excess candidates.
    from app.core.detectors import _detect_encoded_injection

    assert _detect_encoded_injection(
        text, "prompt", "test", "prompt_injection"
    ) == []


def test_trim_international_stops_before_exceeding_15_digits():
    assert _trim_international("+123456789012345 6789") == "+123456789012345"


def test_trim_international_rejects_too_few_digits():
    assert _trim_international("+12 345") is None


def test_international_phone_candidate_is_skipped_when_too_short():
    # Exercise the path where a matched international candidate is rejected.
    findings = detect_pii("+12 345")
    assert not any(f.rule_id == "phone" for f in findings)


def test_int_env_uses_default_for_invalid_value(monkeypatch):
    monkeypatch.setenv("TEST_INTEGER_SETTING", "not-an-integer")

    assert _int_env("TEST_INTEGER_SETTING", 42) == 42


def test_int_env_reads_valid_value(monkeypatch):
    monkeypatch.setenv("TEST_INTEGER_SETTING", "123")

    assert _int_env("TEST_INTEGER_SETTING", 42) == 123


@pytest.mark.parametrize("token", ["", "%%%", "!!!!"])
def test_decode_base64_rejects_invalid_tokens(token):
    assert _decode_base64(token) is None


def test_decode_base64_rejects_non_utf8():
    import base64

    token = base64.b64encode(b"\xff\xfe\xfd").decode("ascii")

    assert _decode_base64(token) is None


def test_luhn_rejects_too_few_digits():
    assert not luhn_valid("123456789012")


def test_verhoeff_rejects_empty_input():
    assert not verhoeff_valid("")


def test_configure_logger_does_not_duplicate_handlers():
    logger = logging.getLogger("sentraguard")
    original_handlers = list(logger.handlers)

    try:
        first = configure_logger()
        handler_count = len(first.handlers)

        second = configure_logger()

        assert first is second
        assert len(second.handlers) == handler_count
    finally:
        # Restore the existing logger state for other tests.
        logger.handlers[:] = original_handlers

def test_encoded_injection_stops_at_candidate_limit(monkeypatch):
    # Supply more matching candidates than the detector is allowed to inspect.
    monkeypatch.setattr(detectors, "MAX_BASE64_CANDIDATES", 2)
    monkeypatch.setattr(
        detectors,
        "BASE64_PATTERN",
        __import__("re").compile(r"TOKEN"),
    )
    monkeypatch.setattr(detectors, "_decode_base64", lambda token: None)

    findings = detectors._detect_encoded_injection(
        "TOKEN TOKEN TOKEN",
        "prompt",
        "test",
        "prompt_injection",
    )

    assert findings == []


def test_detect_pii_skips_invalid_international_phone(monkeypatch):
    # Force a match whose normalized candidate is rejected.
    monkeypatch.setattr(
        detectors,
        "PHONE_INTL_PATTERN",
        __import__("re").compile(r"INVALIDPHONE"),
    )
    monkeypatch.setattr(
        detectors,
        "_trim_international",
        lambda candidate: None,
    )

    findings = detectors.detect_pii("INVALIDPHONE")

    assert not any(f.rule_id == "phone" for f in findings)
