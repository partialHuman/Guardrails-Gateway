"""Attacker-controlled values are neutralised before they reach a log line."""

import pytest
from fastapi.testclient import TestClient

import app.config as config
from app.core.logger import sanitize_for_log
from app.main import app

KEY = "log-hygiene-test-key-0123456789ab"


@pytest.mark.parametrize(
    "raw, must_not_contain",
    [
        ("/a\x1b[31mred", "\x1b"),   # terminal escape sequence
        ("/a\x0bb", "\x0b"),         # vertical tab
        ("/a\x0cb", "\x0c"),         # form feed
        ("/a\x85b", "\x85"),         # NEL
        ("/a\u2028b", "\u2028"),     # line separator
        ("/a\nb", "\n"),
        ("/a\rb", "\r"),
        ("/a\tb", "\t"),
    ],
)
def test_control_characters_are_escaped(raw, must_not_contain):
    safe = sanitize_for_log(raw)

    assert must_not_contain not in safe
    assert "\\" in safe  # rendered as a visible escape such as \x1b


def test_plain_text_is_unchanged():
    assert sanitize_for_log("/analyze") == "/analyze"


def test_long_values_are_truncated():
    safe = sanitize_for_log("x" * 5000)

    assert len(safe) < 300
    assert safe.endswith("[truncated]")


def test_non_string_values_are_accepted():
    assert sanitize_for_log(12345) == "12345"


def test_failed_auth_log_does_not_contain_raw_control_characters(monkeypatch, caplog):
    monkeypatch.setattr(config, "API_KEY", KEY)
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)

    with caplog.at_level("WARNING", logger="sentraguard"):
        # %1b is decoded by the server into a real ESC byte in the path.
        TestClient(app).get("/probe%1b%5b31mFAKE")

    assert "Authentication failed" in caplog.text
    assert "\x1b" not in caplog.text
    assert "probe" in caplog.text


def test_failed_auth_log_never_contains_the_submitted_key(monkeypatch, caplog):
    monkeypatch.setattr(config, "API_KEY", KEY)
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)
    attempt = "attacker-guess-key-9876543210"

    with caplog.at_level("WARNING", logger="sentraguard"):
        TestClient(app).get("/policy", headers={"X-API-Key": attempt})

    assert attempt not in caplog.text
    assert KEY not in caplog.text
