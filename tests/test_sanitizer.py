from app.core.sanitizer import sanitize_prompt


def test_email_removed():

    text = sanitize_prompt(
        "john@gmail.com"
    )

    assert "[REDACTED_EMAIL]" in text


def test_phone_removed():

    text = sanitize_prompt(
        "+91 9876543210"
    )

    assert "[REDACTED_PHONE]" in text