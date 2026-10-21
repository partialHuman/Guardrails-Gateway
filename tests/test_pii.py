import pytest

from app.core.detectors import detect_pii
from app.core.sanitizer import apply_findings

VALID_AADHAAR = "234567890124"
INVALID_AADHAAR = "234567890125"


def kinds(text):
    return [f.rule_id for f in detect_pii(text)]


def redact(text):
    return apply_findings(text, detect_pii(text))


def test_email_detection():
    assert kinds("Contact john@gmail.com") == ["email"]


def test_phone_detection():
    assert kinds("+91 9876543210") == ["phone"]


@pytest.mark.parametrize("text, expected", [
    ("Contact john@gmail.com", "Contact [REDACTED_EMAIL]"),
    ("+91 9876543210", "[REDACTED_PHONE]"),
    ("+919876543210", "[REDACTED_PHONE]"),
    ("9876543210", "[REDACTED_PHONE]"),
    ("98765 43210", "[REDACTED_PHONE]"),
    ("091-98765-43210", "[REDACTED_PHONE]"),
    ("Call (415) 555-2671", "Call [REDACTED_PHONE]"),
    ("415-555-2671", "[REDACTED_PHONE]"),
    ("+1 (415) 555-2671", "[REDACTED_PHONE]"),
    ("+44 20 7946 0958", "[REDACTED_PHONE]"),
    ("card 4111 1111 1111 1111", "card [REDACTED_CARD]"),
    ("card 4111-1111-1111-1111", "card [REDACTED_CARD]"),
    ("4111111111111111", "[REDACTED_CARD]"),
    ("Aadhaar " + VALID_AADHAAR, "Aadhaar [REDACTED_AADHAAR]"),
    ("Aadhaar 2345 6789 0124", "Aadhaar [REDACTED_AADHAAR]"),
    ("a@b.co and c@d.org", "[REDACTED_EMAIL] and [REDACTED_EMAIL]"),
])
def test_pii_is_fully_redacted(text, expected):
    # Whole value must go: no leftover digits or prefixes.
    assert redact(text) == expected


@pytest.mark.parametrize("text", [
    "My order id is 1234567890",
    "Aadhaar-like but invalid " + INVALID_AADHAAR,
    "SSN 123-45-6789",
    "2024-01-15 12:30:45 logged",
    "ISBN 978-3-16-148410-0",
    "ip 192.168.100.200",
    "Total: 1,234,567,890 units",
    "epoch 1700000000000",
    "order 4111 1111 1111 1112",       # fails Luhn
    "version 3.12.4.1234",
    "Invoice #20240115",
    "Hello world",
])
def test_not_pii(text):
    assert detect_pii(text) == []


def test_card_is_never_also_reported_as_phone():
    assert kinds("4111 1111 1111 1111") == ["credit_card"]


def test_pii_evidence_never_echoes_the_value():
    for finding in detect_pii("john@gmail.com 4111 1111 1111 1111"):
        assert "john" not in finding.evidence
        assert "4111" not in finding.evidence


def test_obfuscated_unicode_email_is_found():
    # full-width '@' and letters normalise to a normal address
    assert kinds("john\uff20gmail.com") == ["email"]


@pytest.mark.parametrize("text, expected", [
    ("mail john@gmail.com.", "mail [REDACTED_EMAIL]."),
    ("(john@gmail.com)", "([REDACTED_EMAIL])"),
    ("J.Doe+tag@sub.example.co.in", "[REDACTED_EMAIL]"),
    ("a@b.co,c@d.org", "[REDACTED_EMAIL],[REDACTED_EMAIL]"),
])
def test_email_boundaries(text, expected):
    assert redact(text) == expected


@pytest.mark.parametrize("text", [
    "follow @handle on social",
    "user@localhost",
    "x@y",
    "a@@b",
])
def test_not_an_email(text):
    assert kinds(text) == []


# Keyed by a short name on purpose: pytest puts the parameter into the test id,
# and a 50 000-character id overflows Windows' 32 767-character limit on the
# PYTEST_CURRENT_TEST environment variable.
HOSTILE_INPUTS = {
    "letters": "a" * 50_000,
    "digits": "1" * 50_000,
    "dotted": "a." * 25_000,
    "dashed": "4-" * 25_000,
    "many-at-signs": "a@" * 25_000,
    "long-domain": "x@" + "a" * 50_000,
    "plus-groups": "+1 " * 16_000,
    "repeated-verb": "ignore " * 7_000,
}


@pytest.mark.parametrize("name", list(HOSTILE_INPUTS))
def test_hostile_inputs_are_scanned_in_linear_time(name):
    # Regression: the old email regex was quadratic and took ~15 s on a
    # 50 000-character run of word characters.
    import time

    from app.core.detectors import detect_prompt_injection

    text = HOSTILE_INPUTS[name]

    started = time.perf_counter()
    detect_pii(text)
    detect_prompt_injection(text)

    assert time.perf_counter() - started < 2.0