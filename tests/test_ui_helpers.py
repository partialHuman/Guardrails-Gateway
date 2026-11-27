"""The Streamlit UI holds the gateway key: its access decisions are tested here."""

import ast
import pathlib
import subprocess
import sys
import types

import pytest

from ui.ui_helpers import (
    GATE_LOCKED,
    GATE_LOGIN,
    GATE_OPEN,
    GATE_OPEN_WARN,
    _FALSE_VALUES,
    _TRUE_VALUES,
    describe_http_error,
    evaluate_gate,
    format_reason_line,
    normalize_api_url,
    normalize_secret,
    parse_strict_bool,
    password_matches,
)

UI_HELPERS_SOURCE = pathlib.Path(__file__).resolve().parents[1] / "ui" / "ui_helpers.py"
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


# --- strict UI boolean & isolation checks (V13-002 Stage 5) ----------------------------------


@pytest.mark.parametrize(
    "token",
    ["true", "TRUE", " True ", "1", "yes", "on", "y", "t"],
)
def test_parse_strict_bool_truthy_tokens(token):
    assert parse_strict_bool(token, False, "GUARDRAILS_UI_ALLOW_ANONYMOUS") is True


@pytest.mark.parametrize(
    "token",
    ["false", "FALSE", " False ", "0", "no", "off", "n", "f"],
)
def test_parse_strict_bool_falsy_tokens(token):
    assert parse_strict_bool(token, True, "GUARDRAILS_UI_ALLOW_ANONYMOUS") is False


@pytest.mark.parametrize("raw", [None, "", "   "])
@pytest.mark.parametrize("default", [False, True])
def test_parse_strict_bool_preserves_default_when_unset_or_blank(raw, default):
    assert parse_strict_bool(raw, default, "GUARDRAILS_UI_ALLOW_ANONYMOUS") is default


@pytest.mark.parametrize(
    "invalid",
    ["enabled", "2", "tru", "maybe", "ui-bool-secret-sentinel-DO-NOT-LEAK"],
)
def test_parse_strict_bool_rejects_invalid_values_without_leaking_input(invalid):
    expected_msg = (
        "GUARDRAILS_UI_ALLOW_ANONYMOUS must be a boolean "
        "(true/false, 1/0, yes/no, on/off)"
    )
    with pytest.raises(ValueError) as exc_info:
        parse_strict_bool(invalid, False, "GUARDRAILS_UI_ALLOW_ANONYMOUS")
    assert str(exc_info.value) == expected_msg
    if len(invalid) > 5:
        assert invalid not in repr(exc_info.value)


def test_normalize_secret_and_boolean_constant_parity():
    import app.config as config

    assert _TRUE_VALUES == config._TRUE_VALUES
    assert _FALSE_VALUES == config._FALSE_VALUES
    assert normalize_secret(None) == ""
    assert normalize_secret("   ") == ""
    assert normalize_secret("  ui-secret  ") == "ui-secret"


def test_ui_modules_do_not_import_app_or_pydantic():
    for src_path in (UI_HELPERS_SOURCE, UI_SOURCE):
        tree = ast.parse(src_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in {"app", "pydantic", "pydantic_core"}
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in {"app", "pydantic", "pydantic_core"}

    res = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys\n"
                "from ui import ui_helpers\n"
                "assert ui_helpers.parse_strict_bool('yes', False, 'GUARDRAILS_UI_ALLOW_ANONYMOUS') is True\n"
                "assert 'app' not in sys.modules\n"
                "assert 'app.config' not in sys.modules\n"
                "assert 'pydantic' not in sys.modules\n"
            ),
        ],
        cwd=UI_SOURCE.parents[1],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.returncode == 0


def test_streamlit_app_stops_on_invalid_allow_anonymous_without_exposing_value(monkeypatch):
    class _StopUI(RuntimeError):
        pass

    events: list[tuple[str, str]] = []
    fake_st = types.ModuleType("streamlit")
    fake_st.session_state = {}
    fake_st.set_page_config = lambda **kw: events.append(("config", ""))
    fake_st.title = lambda txt: events.append(("title", txt))
    fake_st.caption = lambda txt: events.append(("caption", txt))
    fake_st.divider = lambda: events.append(("divider", ""))
    fake_st.error = lambda txt: events.append(("error", txt))
    fake_st.warning = lambda txt: events.append(("warning", txt))
    fake_st.subheader = lambda txt: events.append(("subheader", txt))
    fake_st.stop = lambda: (_ for _ in ()).throw(_StopUI("stopped"))

    from ui import ui_helpers

    bad_secret = "invalid-ui-bool-secret-XYZ"
    monkeypatch.setitem(sys.modules, "streamlit", fake_st)
    monkeypatch.setitem(sys.modules, "requests", types.ModuleType("requests"))
    monkeypatch.setitem(sys.modules, "ui_helpers", ui_helpers)
    monkeypatch.setenv("GUARDRAILS_API_KEY", "gw-secret-key")
    monkeypatch.delenv("GUARDRAILS_UI_PASSWORD", raising=False)
    monkeypatch.setenv("GUARDRAILS_UI_ALLOW_ANONYMOUS", bad_secret)

    ns: dict = {"__name__": "__main__", "__file__": str(UI_SOURCE)}
    with pytest.raises(_StopUI):
        exec(compile(UI_SOURCE.read_text(encoding="utf-8"), str(UI_SOURCE), "exec"), ns)

    error_msgs = [msg for kind, msg in events if kind == "error"]
    assert len(error_msgs) == 1
    assert "GUARDRAILS_UI_ALLOW_ANONYMOUS" in error_msgs[0]
    assert bad_secret not in error_msgs[0]
    assert "_gate" not in ns
    assert not any(kind in {"warning", "subheader"} for kind, _ in events)
