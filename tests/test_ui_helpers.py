"""The Streamlit UI holds the gateway key: its access decisions are tested here."""

import ast
import pathlib

import pytest

from ui.ui_helpers import (
    GATE_LOCKED,
    GATE_LOGIN,
    GATE_OPEN,
    GATE_OPEN_WARN,
    describe_http_error,
    evaluate_gate,
    format_reason_line,
    normalize_api_url,
    password_matches,
)

UI_SOURCE = pathlib.Path(__file__).resolve().parents[1] / "ui" / "streamlit_app.py"


# --- access gate ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "key, password, anonymous, expected",
    [
        ("", "", False, GATE_OPEN),          # no key: nothing to protect
        ("", "pw", False, GATE_OPEN),
        ("k", "pw", False, GATE_LOGIN),
        ("k", "pw", True, GATE_LOGIN),       # a password always wins
        ("k", "", True, GATE_OPEN_WARN),
        ("k", "", False, GATE_LOCKED),       # the safe default
    ],
)
def test_gate_decisions(key, password, anonymous, expected):
    assert evaluate_gate(key, password, anonymous) == expected


def test_a_ui_holding_a_key_is_locked_by_default():
    # The audit finding: publishing the UI port handed the gateway key to
    # anyone. With no password and no explicit opt-in the UI refuses to run.
    assert evaluate_gate("gateway-key", "", False) == GATE_LOCKED


@pytest.mark.parametrize(
    "provided, expected, ok",
    [
        ("hunter2", "hunter2", True),
        ("hunter2", "hunter3", False),
        ("", "hunter2", False),
        ("hunter2", "", False),
        ("clé", "clé", True),
        ("é", "e", False),            # non-ASCII must not raise
        ("\ud800", "x", False),
    ],
)
def test_password_matches(provided, expected, ok):
    assert password_matches(provided, expected) is ok


# --- API url ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    ["http://api:8000", "http://api:8000/", "http://api:8000/analyze", "  http://api:8000/analyze/  "],
)
def test_api_url_never_doubles_the_analyze_path(raw):
    assert normalize_api_url(raw) == ("http://api:8000", "http://api:8000/analyze")


# --- messages ---------------------------------------------------------------------------------


@pytest.mark.parametrize("status", [401, 413, 422, 429, 500, 503, 418])
def test_error_messages_never_leak_deployment_details(status):
    message = describe_http_error(status, "30")

    for secret in ("http", "api:8000", "Traceback", "localhost", "/analyze"):
        assert secret not in message


def test_rate_limit_message_includes_retry_after():
    assert "30 seconds" in describe_http_error(429, "30")
    assert "429" in describe_http_error(429)


# --- reasons --------------------------------------------------------------------------------------


def test_reason_line_is_plain_text_with_all_fields():
    line = format_reason_line(
        {
            "tag": "prompt_injection",
            "rule": "override_instructions",
            "source": "doc-2",
            "evidence": "Matched phrase: 'ignore previous instructions'",
        }
    )

    assert "prompt_injection" in line
    assert "override_instructions" in line
    assert "doc-2" in line
    assert "Matched phrase" in line


def test_reason_line_tolerates_missing_fields():
    assert format_reason_line({"tag": "pii"}).startswith("\u2022 pii")


# --- static guards on the Streamlit script (it cannot run under test) -------------------------


def _calls(tree, owner, name):
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == name
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == owner
    ]


@pytest.fixture(scope="module")
def ui_tree():
    return ast.parse(UI_SOURCE.read_text(encoding="utf-8"))


def test_ui_never_renders_exception_tracebacks(ui_tree):
    assert _calls(ui_tree, "st", "exception") == []


def test_ui_renders_reasons_as_plain_text_not_markdown():
    source = UI_SOURCE.read_text(encoding="utf-8")

    assert "st.text(format_reason_line(reason))" in source
    assert "reason['evidence']" not in source


def test_ui_reads_only_the_dedicated_api_key_variable():
    source = UI_SOURCE.read_text(encoding="utf-8")

    assert 'os.getenv("GUARDRAILS_API_KEY"' in source
    assert 'os.getenv("API_KEY"' not in source


def test_ui_stops_before_the_form_when_locked():
    source = UI_SOURCE.read_text(encoding="utf-8")

    gate = source.index("GATE_LOCKED")
    stop = source.index("st.stop()", gate)
    form = source.index('st.subheader("Metadata")')

    assert gate < stop < form
