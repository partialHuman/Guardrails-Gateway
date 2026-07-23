from app.core.detectors import detect_pii


def test_email_detection():

    reasons = detect_pii(
        "Contact john@gmail.com"
    )

    assert len(reasons) == 1


def test_phone_detection():

    reasons = detect_pii(
        "+91 9876543210"
    )

    assert len(reasons) == 1