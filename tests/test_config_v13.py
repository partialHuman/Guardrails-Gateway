"""Comprehensive V13-002 security, compatibility, grammar, and isolation regression suite."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import traceback
import types
from collections.abc import Mapping
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

import app.config as config
import app.main as main
from app.config_specs import ALL_KNOWN_GUARDRAILS_VARS, CONFIG_SPECS
from scripts import generate_config_docs
from ui import ui_helpers

REPO_ROOT = Path(__file__).resolve().parents[1]


class _KeyOnlyMapping(Mapping[str, str]):
    """Mapping double confirming unknown variable values are never accessed."""

    def __init__(self, data: dict[str, str], allowed_read_keys: frozenset[str] = frozenset()) -> None:
        self._data = data
        self._allowed = allowed_read_keys

    def __getitem__(self, key: str) -> str:
        if key not in self._allowed:
            raise AssertionError(f"Secret value for {key!r} must not be read")
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


# ---------------------------------------------------------------------------
# A. Configuration Compatibility & Metadata Parity
# ---------------------------------------------------------------------------


def test_r3_api_specs_bijective_parity_and_compat_globals():
    api_specs = [spec for spec in CONFIG_SPECS if spec.python_attr is not None]
    assert len(api_specs) == len(config.Settings.model_fields)

    for spec in api_specs:
        assert spec.python_attr in config.Settings.model_fields
        assert config.API_SETTINGS_ENV_BY_ATTR[spec.python_attr] == spec.env_var

    # Legacy compatibility globals preserve verified v1.2.x types and defaults.
    s = config.get_settings()
    assert isinstance(s.api_key, SecretStr)
    assert isinstance(s.rate_limit_redis_url, SecretStr)
    assert isinstance(config.API_KEY, str) and config.API_KEY == ""
    assert isinstance(config.RATE_LIMIT_REDIS_URL, str) and config.RATE_LIMIT_REDIS_URL == ""
    assert isinstance(config.REQUIRE_AUTH, bool) and config.REQUIRE_AUTH is False
    assert isinstance(config.ALLOW_ANONYMOUS, bool) and config.ALLOW_ANONYMOUS is True
    assert config.PUBLIC_PATHS is None
    assert isinstance(config.TRUSTED_PROXIES, frozenset) and config.TRUSTED_PROXIES == frozenset()
    assert config.RATE_LIMIT_BACKEND == "memory"

    # Cross-field authentication and Redis backend validation remain enforced.
    with pytest.raises(config.ConfigError, match="GUARDRAILS_REQUIRE_AUTH"):
        config.Settings.from_environ({"GUARDRAILS_REQUIRE_AUTH": "true", "GUARDRAILS_API_KEY": ""})
    with pytest.raises(config.ConfigError, match="GUARDRAILS_RATE_LIMIT_REDIS_URL"):
        config.Settings.from_environ(
            {"GUARDRAILS_RATE_LIMIT_BACKEND": "redis", "GUARDRAILS_RATE_LIMIT_REDIS_URL": ""}
        )


# ---------------------------------------------------------------------------
# B. Environment-File Parser Security, Precedence & Unknown-Key Detection (R2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("SQ_DOLLAR='$'", "$"),
        ("SQ_DOLLAR_VAR='$VAR'", "$VAR"),
        ("SQ_BRACES='${VAR}'", "${VAR}"),
        ("SQ_SUB='$()'", "$()"),
        ("SQ_HASH_EQUALS='a=b#c==1' # comment", "a=b#c==1"),
        (r'DQ_DOLLAR="\$"', "$"),
        (r'DQ_DOLLAR_VAR="\$VAR"', "$VAR"),
        ('DQ_HASH_EQ="pass=w#1==" # inline', "pass=w#1=="),
        (r'DQ_ESCAPES="\"\\\$\n\r\t"', '"\\$\n\r\t'),
        ("UNQUOTED_HASH_EQ=abc#123=x", "abc#123=x"),
        ("UNQUOTED_COMMENT=val # inline", "val"),
        ("export EXPORTED_KEY = trimmed", "trimmed"),
    ],
)
def test_r2_env_file_positive_grammar(tmp_path, line, expected):
    env_file = tmp_path / "positive.env"
    env_file.write_text(f"{line}\n", encoding="utf-8")
    parsed = config.load_env_file(env_file)
    assert len(parsed) == 1
    assert next(iter(parsed.values())) == expected


@pytest.mark.parametrize(
    "line",
    [
        # Unquoted dollar & command substitution rejection
        "KEY=$",
        r"KEY=\$",
        "KEY=$VAR",
        r"KEY=\$VAR",
        "KEY=${VAR}",
        "KEY=$()",
        "KEY=`cmd`",
        # Double-quoted unescaped dollar & backtick rejection
        'KEY="$"',
        'KEY="$VAR"',
        'KEY="${VAR}"',
        'KEY="$()"',
        'KEY="`cmd`"',
        # Unknown escape and structural errors
        r'KEY="unknown\q"',
        'KEY="unterminated',
        "KEY='unterminated",
        "MISSING_EQUALS",
        "1BAD_KEY=val",
        "GUARDRAILS_ENV_FILE=/other/secret.env",
    ],
)
def test_r2_env_file_negative_grammar_and_self_reference(tmp_path, line):
    bad_file = tmp_path / "negative.env"
    bad_file.write_text(f"{line}\n", encoding="utf-8")
    with pytest.raises(config.ConfigError) as exc_info:
        config.load_env_file(bad_file)
    assert "line 1" in str(exc_info.value)
    assert "/other/secret.env" not in str(exc_info.value)


def test_r2_explicit_opt_in_precedence_empty_non_fallback_and_duplicate_keys(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("GUARDRAILS_MAX_PROMPT_CHARS=999\n", encoding="utf-8")
    assert config.Settings.from_environ({}).max_prompt_chars == 20_000

    explicit = tmp_path / "explicit.env"
    explicit.write_text(
        "GUARDRAILS_API_KEY=file-secret-key\n"
        "GUARDRAILS_MAX_PROMPT_CHARS=7777\n"
        "GUARDRAILS_RATE_LIMIT_REQUESTS=42\n",
        encoding="utf-8",
    )
    resolved = config.Settings.from_environ(
        {
            "GUARDRAILS_ENV_FILE": str(explicit),
            "GUARDRAILS_API_KEY": "",  # empty process env blocks fallback to file
            "GUARDRAILS_RATE_LIMIT_REQUESTS": "120",  # non-empty process env wins
        }
    )
    assert resolved.api_key.get_secret_value() == ""
    assert resolved.max_prompt_chars == 7777
    assert resolved.rate_limit_requests == 120

    dup = tmp_path / "dup.env"
    dup.write_text("KEY_DUP=secret-one\nKEY_DUP=secret-two\n", encoding="utf-8")
    with pytest.raises(config.ConfigError) as exc_dup:
        config.load_env_file(dup)
    assert "KEY_DUP" in str(exc_dup.value)
    assert "line 1" in str(exc_dup.value) and "line 2" in str(exc_dup.value)
    assert "secret-one" not in str(exc_dup.value)
    assert "secret-two" not in str(exc_dup.value)


def test_unknown_guardrails_vars_detection_and_lifespan_sanitization(tmp_path, monkeypatch, caplog):
    env_file = tmp_path / "unknowns.env"
    file_secret = "unknown-file-secret-sentinel-777"
    env_file.write_text(f"GUARDRAILS_FILE_TYPO={file_secret}\n", encoding="utf-8")

    # Unknown keys detected across both sources without reading process values.
    proc_secret = "unknown-proc-secret-sentinel-888"
    mapping = _KeyOnlyMapping(
        {
            "GUARDRAILS_ENV_FILE": str(env_file),
            "GUARDRAILS_PROC_TYPO": proc_secret,
            "GUARDRAILS_UI_PASSWORD": "known-ui-password",
        },
        allowed_read_keys=frozenset({"GUARDRAILS_ENV_FILE"}),
    )
    detected = config.detect_unknown_guardrails_vars(mapping)
    assert detected == ("GUARDRAILS_FILE_TYPO", "GUARDRAILS_PROC_TYPO")
    assert all(var in ALL_KNOWN_GUARDRAILS_VARS for var in ("GUARDRAILS_UI_PASSWORD", "GUARDRAILS_API_URL", "GUARDRAILS_BIND_ADDRESS"))

    # Startup lifespan logs sanitized hostile key once and never logs values.
    hostile_key = "GUARDRAILS_HOSTILE\x1b[31m\r\n" + ("A" * 260)
    monkeypatch.setenv("GUARDRAILS_ENV_FILE", str(env_file))
    monkeypatch.setenv(hostile_key, proc_secret)
    monkeypatch.setattr(config, "API_KEY", "")
    monkeypatch.setattr(config, "REQUIRE_AUTH", False)
    monkeypatch.setattr(config, "ALLOW_ANONYMOUS", True)

    with caplog.at_level("WARNING", logger="sentraguard"):
        with TestClient(main.app) as client:
            assert client.get("/health").status_code == 200

    unknown_msgs = [
        rec.getMessage()
        for rec in caplog.records
        if "Unrecognized configuration variable ignored:" in rec.getMessage()
    ]
    assert len(unknown_msgs) == 2
    assert any("GUARDRAILS_FILE_TYPO" in msg for msg in unknown_msgs)
    hostile_msgs = [msg for msg in unknown_msgs if "GUARDRAILS_HOSTILE" in msg]
    assert len(hostile_msgs) == 1
    assert "\x1b" not in hostile_msgs[0]
    assert "\r" not in hostile_msgs[0]
    assert "\n" not in hostile_msgs[0]
    assert "...[truncated]" in hostile_msgs[0]
    rendered_key = hostile_msgs[0].split("ignored: ", 1)[1]
    assert len(rendered_key) == 214
    assert file_secret not in caplog.text
    assert proc_secret not in caplog.text

    # GUARDRAILS_STRICT_ENV=true turns unknown keys into startup ConfigError cleanly.
    config.reload_settings({"GUARDRAILS_STRICT_ENV": "true"})
    try:
        with pytest.raises(config.ConfigError, match="GUARDRAILS_FILE_TYPO") as exc_strict:
            with TestClient(main.app):
                pass
        assert file_secret not in str(exc_strict.value)
        assert proc_secret not in str(exc_strict.value)
    finally:
        config.reload_settings({})


# ---------------------------------------------------------------------------
# C. Secret Handling, Two-Layer Exception Isolation & HTTP Anti-Leakage
# ---------------------------------------------------------------------------


def test_secret_sentinels_never_leak_across_all_surfaces(tmp_path, monkeypatch, caplog):
    api_secret = "sentinel-api-key-9f8e7d6c5b4a"
    redis_secret = "rediss://svc:sentinel-redis-pw-918273@redis.local:6380/0"
    ui_secret = "sentinel-ui-pw-564738"

    loaded = config.reload_settings(
        {
            "GUARDRAILS_API_KEY": api_secret,
            "GUARDRAILS_RATE_LIMIT_REDIS_URL": redis_secret,
            "GUARDRAILS_REQUIRE_AUTH": "true",
            "GUARDRAILS_ALLOW_ANONYMOUS": "false",
        }
    )
    try:
        assert api_secret not in repr(loaded)
        assert api_secret not in str(loaded)
        assert redis_secret not in repr(loaded)
        assert redis_secret not in str(loaded)
        assert config.API_KEY == api_secret
        assert config.RATE_LIMIT_REDIS_URL == redis_secret

        # Public endpoints and error responses must never expose secret sentinels or env names.
        with TestClient(main.app) as client:
            r_health = client.get("/health")
            assert r_health.status_code == 200
            r_unauth = client.get("/policy")
            assert r_unauth.status_code == 401
            r_bad_req = client.post(
                "/analyze",
                headers={"X-API-Key": api_secret},
                json={"prompt": 123},
            )
            assert r_bad_req.status_code == 422

        with monkeypatch.context() as mp:
            mp.setattr(main, "analyze_request", lambda *_: (_ for _ in ()).throw(RuntimeError("boom")))
            with TestClient(main.app, raise_server_exceptions=False) as c_err:
                r_analyze_500 = c_err.post(
                    "/analyze",
                    headers={"X-API-Key": api_secret},
                    json={
                        "prompt": "hello",
                        "context_docs": [],
                        "metadata": {"app_id": "a", "user_id": "u", "request_id": "r-1"},
                    },
                )
                assert r_analyze_500.status_code == 500

        # HTTP 500 path with bad auth / misconfigured state also exposes zero secrets.
        monkeypatch.setattr(config, "API_KEY", "")
        monkeypatch.setattr(config, "REQUIRE_AUTH", True)
        r_500 = TestClient(main.app).get("/policy")
        assert r_500.status_code == 500

        for resp in (r_health, r_unauth, r_bad_req, r_analyze_500, r_500):
            for s in (api_secret, redis_secret, ui_secret, "GUARDRAILS_", "boom"):
                assert s not in resp.text
    finally:
        config.reload_settings({})

    # Invalid Redis URL / ValidationError isolation: __cause__ is None, __context__ is None.
    with pytest.raises(config.ConfigError) as exc_iso:
        config.Settings.from_environ({"GUARDRAILS_RATE_LIMIT_REDIS_URL": f"http://u:{redis_secret}@bad/0"})
    err = exc_iso.value
    assert err.__cause__ is None
    assert err.__context__ is None
    assert "GUARDRAILS_RATE_LIMIT_REDIS_URL" in str(err)
    assert redis_secret not in str(err)
    assert redis_secret not in repr(err)
    tb = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    assert redis_secret not in tb
    assert "ValidationError" not in tb

    # Short API key warning and failed auth logs must not leak API key or UI secret.
    monkeypatch.setenv("GUARDRAILS_API_KEY", "short-secret")
    monkeypatch.setenv("GUARDRAILS_UI_PASSWORD", ui_secret)
    with caplog.at_level("WARNING", logger="sentraguard"):
        with TestClient(main.app) as client_short:
            client_short.get("/policy", headers={"X-API-Key": "wrong-attempt"})
    assert "short-secret" not in caplog.text
    assert ui_secret not in caplog.text
    assert api_secret not in caplog.text
    assert redis_secret not in caplog.text

    # Generated docs never contain live env secrets.
    docs_text = generate_config_docs.render_configuration_markdown()
    for s in (api_secret, redis_secret, ui_secret, "short-secret"):
        assert s not in docs_text


# ---------------------------------------------------------------------------
# D. API vs UI Boolean Grammar Parity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw_val", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        (" 1 ", True),
        ("yes", True),
        ("On", True),
        ("y", True),
        ("T", True),
        ("false", False),
        ("FALSE", False),
        (" 0 ", False),
        ("no", False),
        ("Off", False),
        ("n", False),
        ("F", False),
    ],
)
def test_api_ui_boolean_valid_parity(monkeypatch, raw_val, expected):
    monkeypatch.setenv("TEST_BOOL_PARITY", raw_val)
    assert config._bool_env("TEST_BOOL_PARITY", False) is expected
    assert ui_helpers.parse_strict_bool(raw_val, False, "TEST_BOOL_PARITY") is expected


def test_api_ui_boolean_invalid_and_empty_parity(monkeypatch):
    assert ui_helpers._TRUE_VALUES == config._TRUE_VALUES
    assert ui_helpers._FALSE_VALUES == config._FALSE_VALUES

    for default_val in (False, True):
        monkeypatch.delenv("TEST_BOOL_PARITY", raising=False)
        assert config._bool_env("TEST_BOOL_PARITY", default_val) is default_val
        assert ui_helpers.parse_strict_bool(None, default_val, "TEST_BOOL_PARITY") is default_val
        monkeypatch.setenv("TEST_BOOL_PARITY", "   ")
        assert config._bool_env("TEST_BOOL_PARITY", default_val) is default_val
        assert ui_helpers.parse_strict_bool("   ", default_val, "TEST_BOOL_PARITY") is default_val

    secret_bad = "secret-invalid-boolean-token"
    expected_msg = "TEST_BOOL_PARITY must be a boolean (true/false, 1/0, yes/no, on/off)"
    for bad in ("enabled", "2", "tru", "maybe", secret_bad):
        monkeypatch.setenv("TEST_BOOL_PARITY", bad)
        with pytest.raises(config.ConfigError) as exc_api:
            config._bool_env("TEST_BOOL_PARITY", False)
        with pytest.raises(ValueError) as exc_ui:
            ui_helpers.parse_strict_bool(bad, False, "TEST_BOOL_PARITY")
        assert str(exc_api.value) == expected_msg
        assert str(exc_ui.value) == expected_msg
        assert secret_bad not in repr(exc_api.value)
        assert secret_bad not in repr(exc_ui.value)


# ---------------------------------------------------------------------------
# E. Documentation Generator Process Isolation & Cleanup (Revision 6 R1)
# ---------------------------------------------------------------------------


def test_r1_subprocess_isolation_with_hostile_env_and_determinism():
    assert (REPO_ROOT / "app" / "__init__.py").read_bytes() == b""
    env = {
        **os.environ,
        "GUARDRAILS_REQUIRE_AUTH": "bad",
        "GUARDRAILS_API_KEY": "secret",
        "GUARDRAILS_ENV_FILE": "/missing",
    }
    probe = (
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path('scripts').resolve()))\n"
        "import generate_config_docs\n"
        "a = generate_config_docs.render_configuration_markdown()\n"
        "b = generate_config_docs.render_configuration_markdown()\n"
        "assert a == b\n"
        "assert 'app' not in sys.modules\n"
        "assert 'app.config' not in sys.modules\n"
        "assert generate_config_docs.SPECS_MODULE_NAME not in sys.modules\n"
        "print('R1_OK')\n"
    )
    res = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == "R1_OK"


def test_r1_loader_restores_preexisting_sys_modules_entry_on_failure(monkeypatch):
    mod_name = generate_config_docs.SPECS_MODULE_NAME
    sentinel_prior = types.ModuleType(mod_name)
    monkeypatch.setitem(sys.modules, mod_name, sentinel_prior)

    real_spec_from_file_location = importlib.util.spec_from_file_location

    def failing_spec(name, location, *args, **kwargs):
        spec = real_spec_from_file_location(name, location, *args, **kwargs)

        def fail_exec(module):
            raise RuntimeError("boom")

        spec.loader.exec_module = fail_exec
        return spec

    monkeypatch.setattr(importlib.util, "spec_from_file_location", failing_spec)
    with pytest.raises(RuntimeError, match="boom"):
        generate_config_docs.load_config_specs_module()

    assert sys.modules.get(mod_name) is sentinel_prior
