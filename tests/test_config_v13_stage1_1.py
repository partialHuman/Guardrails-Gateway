"""Permanent Stage 1.1 tests for effective-env detection, cross-field Settings validation, and metadata consistency."""

from __future__ import annotations

import importlib
import subprocess
import sys
import traceback
from collections.abc import Mapping

import pytest
from pydantic import SecretStr, ValidationError
from pydantic_core import PydanticUndefined

import app.config as config
from app.config_specs import (
    ALL_KNOWN_GUARDRAILS_VARS,
    API_SETTINGS_ENV_BY_ATTR,
    CONFIG_SPECS,
    ConfigFieldSpec,
)


class _KeyOnlyMapping(Mapping[str, str]):
    """Mapping stub whose values cannot be accessed directly via __getitem__."""

    def __init__(self, data: dict[str, str], allow_value_keys: frozenset[str] = frozenset()) -> None:
        self._data = data
        self._allow_value_keys = allow_value_keys

    def __getitem__(self, key: str) -> str:
        if key not in self._allow_value_keys:
            raise AssertionError(f"Secret/unknown value for key {key!r} must never be read")
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


# ---------------------------------------------------------------------------
# Finding F1: Environment-file-aware unknown-variable detection
# ---------------------------------------------------------------------------


def test_f1_unknown_var_only_in_explicit_env_file(tmp_path):
    env_file = tmp_path / "f1.env"
    secret_val = "f1-file-only-secret-xyz"
    env_file.write_text(
        f"GUARDRAILS_UNKNOWN_FILE_KEY={secret_val}\nGUARDRAILS_MAX_PROMPT_CHARS=100\n",
        encoding="utf-8",
    )
    unknown = config.detect_unknown_guardrails_vars({"GUARDRAILS_ENV_FILE": str(env_file)})
    assert unknown == ("GUARDRAILS_UNKNOWN_FILE_KEY",)
    assert secret_val not in repr(unknown)


def test_f1_unknown_var_only_in_process_env():
    secret_val = "f1-proc-only-secret-xyz"
    unknown = config.detect_unknown_guardrails_vars({"GUARDRAILS_UNKNOWN_PROC_KEY": secret_val})
    assert unknown == ("GUARDRAILS_UNKNOWN_PROC_KEY",)
    assert secret_val not in repr(unknown)


def test_f1_known_vars_across_sources_produce_no_warnings(tmp_path):
    env_file = tmp_path / "known.env"
    env_file.write_text(
        "GUARDRAILS_MAX_PROMPT_CHARS=25000\n"
        "GUARDRAILS_UI_PASSWORD=ui-secret\n"
        "GUARDRAILS_BIND_ADDRESS=127.0.0.1\n",
        encoding="utf-8",
    )
    unknown = config.detect_unknown_guardrails_vars(
        {
            "GUARDRAILS_ENV_FILE": str(env_file),
            "GUARDRAILS_API_KEY": "api-secret",
            "GUARDRAILS_UI_ALLOW_ANONYMOUS": "false",
            "GUARDRAILS_API_URL": "http://127.0.0.1:8000",
            "API_URL": "http://localhost:8000",
            "UNRELATED_SYSTEM_VAR": "ignored",
        }
    )
    assert unknown == ()


def test_f1_same_unknown_var_in_both_sources_and_empty_process_override(tmp_path):
    env_file = tmp_path / "both.env"
    env_file.write_text(
        "GUARDRAILS_SHARED_UNKNOWN=from-file-secret\n"
        "GUARDRAILS_EMPTY_OVERRIDE_UNKNOWN=from-file-val\n",
        encoding="utf-8",
    )
    unknown = config.detect_unknown_guardrails_vars(
        {
            "GUARDRAILS_ENV_FILE": str(env_file),
            "GUARDRAILS_SHARED_UNKNOWN": "from-process-secret",
            "GUARDRAILS_EMPTY_OVERRIDE_UNKNOWN": "",
        }
    )
    assert unknown == ("GUARDRAILS_SHARED_UNKNOWN", "GUARDRAILS_EMPTY_OVERRIDE_UNKNOWN")
    assert "from-file-secret" not in repr(unknown)
    assert "from-process-secret" not in repr(unknown)


def test_f1_no_implicit_dotenv_or_whitespace_env_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("GUARDRAILS_IMPLICIT_UNKNOWN=should_ignore\n", encoding="utf-8")

    assert config.detect_unknown_guardrails_vars({}) == ()
    assert config.detect_unknown_guardrails_vars({"GUARDRAILS_ENV_FILE": "   "}) == ()
    assert config.Settings.from_environ({}).max_prompt_chars == 20_000


def test_f1_malformed_and_duplicate_env_file_fail_closed(tmp_path):
    malformed = tmp_path / "malformed.env"
    malformed.write_text("GUARDRAILS_BAD_LINE_WITHOUT_EQUALS\n", encoding="utf-8")
    with pytest.raises(config.ConfigError, match="line 1"):
        config.detect_unknown_guardrails_vars({"GUARDRAILS_ENV_FILE": str(malformed)})

    duplicate = tmp_path / "dup.env"
    duplicate.write_text(
        "GUARDRAILS_TYPO_DUP=secret-first\nGUARDRAILS_TYPO_DUP=secret-second\n",
        encoding="utf-8",
    )
    with pytest.raises(config.ConfigError) as exc_info:
        config.detect_unknown_guardrails_vars({"GUARDRAILS_ENV_FILE": str(duplicate)})
    assert "GUARDRAILS_TYPO_DUP" in str(exc_info.value)
    assert "line 2" in str(exc_info.value)
    assert "secret-first" not in str(exc_info.value)
    assert "secret-second" not in str(exc_info.value)


def test_f1_key_only_inspection_never_reads_unknown_process_values(tmp_path):
    env_file = tmp_path / "file_ok.env"
    env_file.write_text("GUARDRAILS_FILE_TYPO=file-secret-value\n", encoding="utf-8")

    mapping = _KeyOnlyMapping(
        {
            "GUARDRAILS_ENV_FILE": str(env_file),
            "GUARDRAILS_API_KEY": "process-secret-token",
            "GUARDRAILS_PROC_TYPO": "process-secret-unknown-value",
        },
        allow_value_keys=frozenset({"GUARDRAILS_ENV_FILE"}),
    )
    unknown = config.detect_unknown_guardrails_vars(mapping)
    assert unknown == ("GUARDRAILS_FILE_TYPO", "GUARDRAILS_PROC_TYPO")
    assert "file-secret-value" not in repr(unknown)
    assert "process-secret-unknown-value" not in repr(unknown)


# ---------------------------------------------------------------------------
# Finding F2: Cross-field Settings validation & atomic reload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("require_auth", "api_key", "expected_valid"),
    [
        ("false", "", True),
        ("false", "valid-api-key-12345678", True),
        ("true", "", False),
        ("true", "   ", False),
        ("true", "valid-api-key-12345678", True),
    ],
)
def test_f2_require_auth_api_key_matrix(require_auth, api_key, expected_valid):
    env = {"GUARDRAILS_REQUIRE_AUTH": require_auth, "GUARDRAILS_API_KEY": api_key}
    if expected_valid:
        s = config.Settings.from_environ(env)
        assert s.require_auth is (require_auth == "true")
    else:
        with pytest.raises(config.ConfigError) as exc_info:
            config.Settings.from_environ(env)
        err = exc_info.value
        assert err.__cause__ is None
        assert err.__context__ is None
        assert "GUARDRAILS_REQUIRE_AUTH" in str(err)
        assert "GUARDRAILS_API_KEY" in str(err)


@pytest.mark.parametrize(
    ("backend", "redis_url", "expected_valid"),
    [
        ("memory", "", True),
        ("memory", "redis://localhost:6379/0", True),
        ("redis", "", False),
        ("redis", "   ", False),
        ("redis", "redis://localhost:6379/0", True),
    ],
)
def test_f2_redis_backend_url_matrix(backend, redis_url, expected_valid):
    env = {"GUARDRAILS_RATE_LIMIT_BACKEND": backend, "GUARDRAILS_RATE_LIMIT_REDIS_URL": redis_url}
    if expected_valid:
        s = config.Settings.from_environ(env)
        assert s.rate_limit_backend == backend
    else:
        with pytest.raises(config.ConfigError) as exc_info:
            config.Settings.from_environ(env)
        err = exc_info.value
        assert err.__cause__ is None
        assert err.__context__ is None
        assert "GUARDRAILS_RATE_LIMIT_BACKEND" in str(err)
        assert "GUARDRAILS_RATE_LIMIT_REDIS_URL" in str(err)


def test_f2_direct_settings_model_validator_immutability_and_redaction():
    s = config.Settings(require_auth=True, api_key="direct-secret-key-99999")
    assert isinstance(s.api_key, SecretStr)
    assert isinstance(s.rate_limit_redis_url, SecretStr)
    assert "direct-secret-key-99999" not in repr(s)
    assert "direct-secret-key-99999" not in str(s)
    with pytest.raises(ValidationError):
        s.require_auth = False  # type: ignore[misc]

    with pytest.raises(ValidationError, match="GUARDRAILS_REQUIRE_AUTH"):
        config.Settings(require_auth=True, api_key="   ")

    with pytest.raises(ValidationError, match="GUARDRAILS_RATE_LIMIT_REDIS_URL"):
        config.Settings(rate_limit_backend="redis", rate_limit_redis_url="   ")

    secret_bad_redis = "http://user:topsecret@bad-redis.internal/0"
    with pytest.raises(config.ConfigError) as exc_info:
        config.Settings.from_environ({"GUARDRAILS_RATE_LIMIT_REDIS_URL": secret_bad_redis})
    err = exc_info.value
    assert err.__cause__ is None
    assert err.__context__ is None
    assert "topsecret" not in str(err)
    assert "topsecret" not in repr(err)
    tb = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    assert "topsecret" not in tb
    assert "ValidationError" not in tb

    for bad_kwargs in (
        {"api_key": 123},
        {"require_auth": 123},
        {"allow_anonymous": "bad-bool"},
        {"max_prompt_chars": True},
        {"max_prompt_chars": "not-int"},
        {"max_prompt_chars": 1.5},
        {"rate_limit_redis_timeout_seconds": True},
        {"rate_limit_redis_timeout_seconds": "bad-float"},
        {"rate_limit_redis_timeout_seconds": float("nan")},
        {"rate_limit_redis_timeout_seconds": object()},
        {"rate_limit_backend": 99},
        {"public_paths": 99},
        {"trusted_proxies": 99},
        {"env_file": 99},
    ):
        with pytest.raises(ValueError):
            config.Settings(**bad_kwargs)


def test_f2_direct_env_helpers_and_empty_defaults(monkeypatch):
    monkeypatch.delenv("TEST_BOOL_S11", raising=False)
    assert config._bool_env("TEST_BOOL_S11", True) is True
    monkeypatch.setenv("TEST_BOOL_S11", "bad-bool")
    with pytest.raises(config.ConfigError, match="TEST_BOOL_S11"):
        config._bool_env("TEST_BOOL_S11", True)

    monkeypatch.delenv("TEST_FLOAT_S11", raising=False)
    assert config._float_env("TEST_FLOAT_S11", 0.5) == 0.5
    monkeypatch.setenv("TEST_FLOAT_S11", "nan")
    with pytest.raises(config.ConfigError, match="TEST_FLOAT_S11"):
        config._float_env("TEST_FLOAT_S11", 0.5)

    empty_defaults = config.Settings(
        api_key=SecretStr("  secret  "),
        require_auth="  ",
        max_prompt_chars="   ",
        rate_limit_redis_timeout_seconds="   ",
        rate_limit_backend=None,
        public_paths=["/health/", "/"],
        trusted_proxies=["10.0.0.1"],
        env_file="   ",
    )
    assert empty_defaults.api_key.get_secret_value() == "secret"
    assert empty_defaults.require_auth is False
    assert empty_defaults.max_prompt_chars == 20_000
    assert empty_defaults.rate_limit_redis_timeout_seconds == 0.25
    assert empty_defaults.rate_limit_backend == "memory"
    assert empty_defaults.public_paths == frozenset({"/health", "/"})
    assert empty_defaults.trusted_proxies == frozenset({"10.0.0.1"})
    assert empty_defaults.env_file is None


def test_f2_import_time_reload_fails_closed_on_cross_field_violation(monkeypatch):
    # Note: importlib.reload(config) instantiates a new ConfigError subclass of ValueError
    # inside config, so catching ValueError reliably captures the post-reload exception.
    monkeypatch.setenv("GUARDRAILS_REQUIRE_AUTH", "true")
    monkeypatch.delenv("GUARDRAILS_API_KEY", raising=False)
    try:
        with pytest.raises(ValueError, match="GUARDRAILS_REQUIRE_AUTH") as exc_auth:
            importlib.reload(config)
        assert type(exc_auth.value).__name__ == "ConfigError"
    finally:
        monkeypatch.delenv("GUARDRAILS_REQUIRE_AUTH", raising=False)
        importlib.reload(config)

    monkeypatch.setenv("GUARDRAILS_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.delenv("GUARDRAILS_RATE_LIMIT_REDIS_URL", raising=False)
    try:
        with pytest.raises(ValueError, match="GUARDRAILS_RATE_LIMIT_REDIS_URL") as exc_redis:
            importlib.reload(config)
        assert type(exc_redis.value).__name__ == "ConfigError"
    finally:
        monkeypatch.delenv("GUARDRAILS_RATE_LIMIT_BACKEND", raising=False)
        importlib.reload(config)


def test_f2_reload_settings_is_atomic_on_validation_failure():
    secret_api = "atomic-good-key-123456"
    secret_redis = "rediss://redis-host:6380/0"
    good = config.reload_settings(
        {
            "GUARDRAILS_REQUIRE_AUTH": "true",
            "GUARDRAILS_API_KEY": secret_api,
            "GUARDRAILS_RATE_LIMIT_BACKEND": "redis",
            "GUARDRAILS_RATE_LIMIT_REDIS_URL": secret_redis,
            "GUARDRAILS_MAX_PROMPT_CHARS": "12000",
        }
    )
    try:
        assert isinstance(config.API_KEY, str) and config.API_KEY == secret_api
        assert isinstance(config.RATE_LIMIT_REDIS_URL, str) and config.RATE_LIMIT_REDIS_URL == secret_redis
        assert config.REQUIRE_AUTH is True
        assert config.RATE_LIMIT_BACKEND == "redis"
        assert config.MAX_PROMPT_CHARS == 12000

        # Failing reload must preserve previously active settings and module globals intact.
        with pytest.raises(config.ConfigError):
            config.reload_settings(
                {
                    "GUARDRAILS_REQUIRE_AUTH": "true",
                    "GUARDRAILS_API_KEY": "",
                    "GUARDRAILS_MAX_PROMPT_CHARS": "999",
                }
            )
        assert config.get_settings() == good
        assert config.API_KEY == secret_api
        assert config.RATE_LIMIT_REDIS_URL == secret_redis
        assert config.REQUIRE_AUTH is True
        assert config.MAX_PROMPT_CHARS == 12000
    finally:
        config.reload_settings({})


# ---------------------------------------------------------------------------
# Finding F3: Configuration metadata and registry consistency
# ---------------------------------------------------------------------------


def test_f3_config_specs_pure_stdlib_in_fresh_subprocess():
    code = (
        "import sys, os, dataclasses, importlib.util\n"
        "os.environ['GUARDRAILS_REQUIRE_AUTH'] = 'invalid-bool'\n"
        "os.environ['GUARDRAILS_API_KEY'] = 'subproc-secret'\n"
        "spec = importlib.util.spec_from_file_location('_sg_f3_specs', 'app/config_specs.py')\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['_sg_f3_specs'] = mod\n"
        "try:\n"
        "    spec.loader.exec_module(mod)\n"
        "    assert 'pydantic' not in sys.modules\n"
        "    assert 'app' not in sys.modules\n"
        "    assert 'app.config' not in sys.modules\n"
        "    assert dataclasses.is_dataclass(mod.ConfigFieldSpec)\n"
        "finally:\n"
        "    sys.modules.pop('_sg_f3_specs', None)\n"
        "print('OK')\n"
    )
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert res.stdout.strip() == "OK"


_SPECIAL_DISPLAY_ANNOTATIONS: dict[str, str] = {
    # Deployment-specific or runtime-fallback notes appended to bare runtime defaults in CONFIG_SPECS.
    "allow_anonymous": " (Code) / false (Container)",
    "public_paths": " (/health, /docs, /redoc, /openapi.json)",
    "env_file": " (disabled)",
}


def _declared_field_default(field_info, spec: ConfigFieldSpec) -> object:
    """Extract declared default from Pydantic FieldInfo, invoking default_factory if used."""
    if field_info.default_factory is not None:
        return field_info.default_factory()
    if field_info.default is not PydanticUndefined:
        return field_info.default
    raise AssertionError(
        f"{spec.env_var} ({spec.python_attr}) has no declared default or default_factory on Settings"
    )


def _format_safe_value(value: object, *, sensitive: bool) -> str:
    """Format values for assertion diagnostics without ever exposing secrets."""
    if sensitive or isinstance(value, SecretStr):
        return "<redacted>"
    if isinstance(value, frozenset):
        return f"frozenset({sorted(value)!r})"
    return repr(value)


def _same_typed_value(left: object, right: object) -> bool:
    """Strict type- and order-safe equality across all Settings field default types."""
    if isinstance(left, SecretStr) or isinstance(right, SecretStr):
        return (
            isinstance(left, SecretStr)
            and isinstance(right, SecretStr)
            and left.get_secret_value() == right.get_secret_value()
        )
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left is right
    if isinstance(left, frozenset) or isinstance(right, frozenset):
        return isinstance(left, frozenset) and isinstance(right, frozenset) and left == right
    return type(left) is type(right) and left == right


def _expected_default_display_from_runtime(default_val: object, spec: ConfigFieldSpec) -> str:
    """Compute the expected CONFIG_SPECS.default_display directly from an actual runtime default."""
    if spec.sensitive and not isinstance(default_val, SecretStr):
        raise AssertionError(
            f"{spec.env_var} ({spec.python_attr}) is marked sensitive=True "
            "but uses unsupported non-SecretStr runtime default (<redacted>)"
        )

    if isinstance(default_val, SecretStr):
        if spec.sensitive is not True:
            raise AssertionError(
                f"{spec.env_var} ({spec.python_attr}) uses SecretStr but metadata sensitive=False"
            )
        if default_val.get_secret_value() != "":
            raise AssertionError(
                f"{spec.env_var} ({spec.python_attr}) has unexpected non-empty SecretStr default (<redacted>)"
            )
        base = '""'
    elif default_val is None:
        base = "None"
    elif isinstance(default_val, bool):
        base = "true" if default_val else "false"
    elif isinstance(default_val, (int, float)):
        base = str(default_val)
    elif isinstance(default_val, str):
        base = f'"{default_val}"'
    elif isinstance(default_val, frozenset):
        if len(default_val) == 0:
            base = '"" (frozenset())'
        else:
            base = ", ".join(sorted(default_val))
    else:
        raise AssertionError(
            f"Unsupported Settings default type {type(default_val).__name__} for "
            f"{spec.env_var} ({spec.python_attr})"
        )

    suffix = _SPECIAL_DISPLAY_ANNOTATIONS.get(spec.python_attr or "", "")
    return f"{base}{suffix}"


def _verify_spec_default_consistency(
    spec: ConfigFieldSpec,
    declared_default: object,
    instance_default: object,
) -> None:
    """Assert declared Pydantic default, Settings() runtime default, and metadata default_display match."""
    is_sensitive = spec.sensitive or isinstance(declared_default, SecretStr) or isinstance(instance_default, SecretStr)
    if is_sensitive and not spec.sensitive:
        raise AssertionError(
            f"{spec.env_var} ({spec.python_attr}) holds a secret default but is not marked sensitive=True"
        )

    if not _same_typed_value(declared_default, instance_default):
        raise AssertionError(
            f"{spec.env_var} ({spec.python_attr}) FieldInfo default "
            f"{_format_safe_value(declared_default, sensitive=is_sensitive)} != "
            f"Settings() instance default {_format_safe_value(instance_default, sensitive=is_sensitive)}"
        )

    expected_display = _expected_default_display_from_runtime(instance_default, spec)
    if spec.default_display != expected_display:
        metadata_repr = "<redacted>" if is_sensitive else repr(spec.default_display)
        raise AssertionError(
            f"{spec.env_var} ({spec.python_attr}) default_display mismatch: "
            f"metadata={metadata_repr} vs runtime_derived={expected_display!r} "
            f"(runtime_default={_format_safe_value(instance_default, sensitive=is_sensitive)})"
        )


def test_f3_metadata_registry_consistency_and_defaults():
    env_vars = [spec.env_var for spec in CONFIG_SPECS]
    assert len(env_vars) == len(set(env_vars))

    mapped_specs = [spec for spec in CONFIG_SPECS if spec.python_attr is not None]
    mapped_attrs = [spec.python_attr for spec in mapped_specs]
    assert len(mapped_attrs) == len(set(mapped_attrs))

    model_fields = config.Settings.model_fields
    assert set(mapped_attrs) == set(model_fields.keys())
    assert API_SETTINGS_ENV_BY_ATTR == {spec.python_attr: spec.env_var for spec in mapped_specs}

    for spec in CONFIG_SPECS:
        if spec.python_attr is None:
            assert spec.env_var not in API_SETTINGS_ENV_BY_ATTR.values()
            assert spec.component in {"UI", "CLI", "Compose"}
        else:
            assert spec.python_attr in model_fields
            assert "API" in spec.component or "Loader" in spec.component

    assert ALL_KNOWN_GUARDRAILS_VARS == frozenset(
        spec.env_var for spec in CONFIG_SPECS if spec.env_var.upper().startswith("GUARDRAILS_")
    )
    assert "API_URL" not in ALL_KNOWN_GUARDRAILS_VARS

    # Verify every mapped Settings field default (via FieldInfo + default_factory and Settings())
    # directly against CONFIG_SPECS.default_display with complete type and uniqueness coverage.
    default_settings = config.Settings()
    verified_attrs: list[str] = []
    seen_types: set[type] = set()

    for spec in mapped_specs:
        attr = spec.python_attr
        assert attr is not None
        assert attr not in verified_attrs, f"Duplicate verification attempted for {spec.env_var} ({attr})"

        declared_default = _declared_field_default(model_fields[attr], spec)
        instance_default = getattr(default_settings, attr)
        _verify_spec_default_consistency(spec, declared_default, instance_default)

        verified_attrs.append(attr)
        seen_types.add(type(instance_default))

    assert len(verified_attrs) == len(mapped_specs)
    assert set(verified_attrs) == set(model_fields.keys())
    assert seen_types == {SecretStr, bool, int, float, str, frozenset, type(None)}

    sensitive_vars = {spec.env_var for spec in CONFIG_SPECS if spec.sensitive}
    assert sensitive_vars == {
        "GUARDRAILS_API_KEY",
        "GUARDRAILS_RATE_LIMIT_REDIS_URL",
        "GUARDRAILS_UI_PASSWORD",
    }


def _dummy_spec(**overrides) -> ConfigFieldSpec:
    base = {
        "env_var": "GUARDRAILS_TEST_FIELD",
        "python_attr": "test_field",
        "component": "API",
        "section": "Test",
        "type_display": "String",
        "default_display": '"memory"',
        "required_label": "Optional",
        "validation_rules": "Test rule",
        "description": "Test description",
        "sensitive": False,
    }
    base.update(overrides)
    return ConfigFieldSpec(**base)


@pytest.mark.parametrize(
    ("spec_overrides", "declared", "instance", "expected_fragment"),
    [
        # 1. Changed string default
        (
            {"env_var": "GUARDRAILS_RATE_LIMIT_BACKEND", "python_attr": "rate_limit_backend", "default_display": '"memory"'},
            "redis",
            "redis",
            "GUARDRAILS_RATE_LIMIT_BACKEND (rate_limit_backend)",
        ),
        # 2a. Changed integer default
        (
            {"env_var": "GUARDRAILS_MAX_PROMPT_CHARS", "python_attr": "max_prompt_chars", "default_display": "20000"},
            25000,
            25000,
            "GUARDRAILS_MAX_PROMPT_CHARS (max_prompt_chars)",
        ),
        # 2b. Changed float default
        (
            {"env_var": "GUARDRAILS_RATE_LIMIT_REDIS_TIMEOUT_SECONDS", "python_attr": "rate_limit_redis_timeout_seconds", "default_display": "0.25"},
            0.5,
            0.5,
            "GUARDRAILS_RATE_LIMIT_REDIS_TIMEOUT_SECONDS (rate_limit_redis_timeout_seconds)",
        ),
        # 3. Changed frozenset default
        (
            {"env_var": "GUARDRAILS_TRUSTED_PROXIES", "python_attr": "trusted_proxies", "default_display": '"" (frozenset())'},
            frozenset({"10.0.0.1"}),
            frozenset({"10.0.0.1"}),
            "GUARDRAILS_TRUSTED_PROXIES (trusted_proxies)",
        ),
        # 4. Changed None default
        (
            {"env_var": "GUARDRAILS_PUBLIC_PATHS", "python_attr": "public_paths", "default_display": "None (/health, /docs, /redoc, /openapi.json)"},
            "/health",
            "/health",
            "GUARDRAILS_PUBLIC_PATHS (public_paths)",
        ),
        # 5. Changed boolean default
        (
            {"env_var": "GUARDRAILS_ALLOW_ANONYMOUS", "python_attr": "allow_anonymous", "default_display": "true (Code) / false (Container)"},
            False,
            False,
            "GUARDRAILS_ALLOW_ANONYMOUS (allow_anonymous)",
        ),
        # 7a. Incorrect default_display when runtime value itself is unchanged
        (
            {"env_var": "GUARDRAILS_MAX_DOC_CHARS", "python_attr": "max_doc_chars", "default_display": "99999"},
            50000,
            50000,
            "GUARDRAILS_MAX_DOC_CHARS (max_doc_chars)",
        ),
        # 7b. FieldInfo default diverges from Settings() instance default
        (
            {"env_var": "GUARDRAILS_REQUIRE_AUTH", "python_attr": "require_auth", "default_display": "false"},
            True,
            False,
            "GUARDRAILS_REQUIRE_AUTH (require_auth)",
        ),
    ],
)
def test_f3_metadata_drift_detection_negative_cases(spec_overrides, declared, instance, expected_fragment):
    spec = _dummy_spec(**spec_overrides)
    with pytest.raises(AssertionError, match=expected_fragment.replace("(", r"\(").replace(")", r"\)")):
        _verify_spec_default_consistency(spec, declared, instance)


def test_f3_metadata_drift_sensitive_and_unordered_collection_handling():
    secret_sentinel = "super-secret-drift-value-do-not-expose"

    # Sensitive field with unexpected non-empty SecretStr default fails without leaking value.
    spec_secret = _dummy_spec(
        env_var="GUARDRAILS_API_KEY",
        python_attr="api_key",
        default_display='""',
        sensitive=True,
    )
    with pytest.raises(AssertionError) as exc_secret:
        _verify_spec_default_consistency(spec_secret, SecretStr(secret_sentinel), SecretStr(secret_sentinel))
    assert "GUARDRAILS_API_KEY (api_key)" in str(exc_secret.value)
    assert secret_sentinel not in str(exc_secret.value)

    # Sensitive SecretStr field marked sensitive=False fails cleanly.
    spec_unmarked = _dummy_spec(
        env_var="GUARDRAILS_API_KEY",
        python_attr="api_key",
        default_display='""',
        sensitive=False,
    )
    with pytest.raises(AssertionError, match="sensitive=True"):
        _verify_spec_default_consistency(spec_unmarked, SecretStr(""), SecretStr(""))

    # Sensitive FieldInfo vs Settings() mismatch redacts values in diagnostics.
    with pytest.raises(AssertionError) as exc_mismatch:
        _verify_spec_default_consistency(spec_secret, SecretStr(secret_sentinel), SecretStr(""))
    assert "<redacted>" in str(exc_mismatch.value)
    assert secret_sentinel not in str(exc_mismatch.value)

    # Unordered frozenset equality ignores iteration ordering.
    assert _same_typed_value(frozenset({"10.0.0.2", "10.0.0.1"}), frozenset({"10.0.0.1", "10.0.0.2"}))
    spec_proxies = _dummy_spec(
        env_var="GUARDRAILS_TRUSTED_PROXIES",
        python_attr="trusted_proxies",
        default_display="10.0.0.1, 10.0.0.2",
    )
    _verify_spec_default_consistency(
        spec_proxies,
        frozenset({"10.0.0.2", "10.0.0.1"}),
        frozenset({"10.0.0.1", "10.0.0.2"}),
    )


def test_f3_sensitive_plain_string_default_never_leaks_and_plain_string_display_preserved():
    sentinel = "plain-string-secret-sentinel-DO-NOT-LEAK"

    spec_sensitive_plain = _dummy_spec(
        env_var="GUARDRAILS_SENSITIVE_PLAIN",
        python_attr="sensitive_plain",
        default_display='"intentionally-mismatched"',
        sensitive=True,
    )

    # Full metadata verification path must fail safely without exposing the plain-string secret.
    with pytest.raises(AssertionError) as exc_verify:
        _verify_spec_default_consistency(spec_sensitive_plain, sentinel, sentinel)
    verify_text = str(exc_verify.value)
    verify_repr = repr(exc_verify.value)
    assert "GUARDRAILS_SENSITIVE_PLAIN (sensitive_plain)" in verify_text
    assert "<redacted>" in verify_text
    assert sentinel not in verify_text
    assert sentinel not in verify_repr

    # Runtime-display helper directly also refuses to format sensitive non-SecretStr defaults.
    with pytest.raises(AssertionError) as exc_display:
        _expected_default_display_from_runtime(sentinel, spec_sensitive_plain)
    assert sentinel not in str(exc_display.value)
    assert sentinel not in repr(exc_display.value)

    # Declared-vs-instance mismatch on sensitive plain string also stays redacted.
    with pytest.raises(AssertionError) as exc_diff:
        _verify_spec_default_consistency(spec_sensitive_plain, sentinel, "other-secret-sentinel")
    assert sentinel not in str(exc_diff.value)
    assert "other-secret-sentinel" not in str(exc_diff.value)
    assert sentinel not in repr(exc_diff.value)
    assert "<redacted>" in str(exc_diff.value)

    # Non-sensitive ordinary string preserves standard quoted display convention.
    spec_ordinary = _dummy_spec(
        env_var="GUARDRAILS_ORDINARY_STR",
        python_attr="ordinary_str",
        default_display='"custom-mode"',
        sensitive=False,
    )
    assert _expected_default_display_from_runtime("custom-mode", spec_ordinary) == '"custom-mode"'
    _verify_spec_default_consistency(spec_ordinary, "custom-mode", "custom-mode")


def test_f3_sensitive_metadata_display_never_leaks_and_nonsensitive_preserved():
    sentinel = "metadata-secret-sentinel-DO-NOT-LEAK"

    spec_sensitive = _dummy_spec(
        env_var="GUARDRAILS_SENSITIVE_DISPLAY",
        python_attr="sensitive_display",
        default_display=sentinel,
        sensitive=True,
    )
    with pytest.raises(AssertionError) as exc_sensitive:
        _verify_spec_default_consistency(spec_sensitive, SecretStr(""), SecretStr(""))
    sensitive_text = str(exc_sensitive.value)
    sensitive_repr = repr(exc_sensitive.value)
    assert "GUARDRAILS_SENSITIVE_DISPLAY (sensitive_display)" in sensitive_text
    assert "<redacted>" in sensitive_text
    assert sentinel not in sensitive_text
    assert sentinel not in sensitive_repr

    # Non-sensitive metadata mismatch must keep metadata and runtime display values visible.
    spec_non_sensitive = _dummy_spec(
        env_var="GUARDRAILS_MAX_DOC_CHARS",
        python_attr="max_doc_chars",
        default_display="99999",
        sensitive=False,
    )
    with pytest.raises(AssertionError) as exc_plain:
        _verify_spec_default_consistency(spec_non_sensitive, 50000, 50000)
    plain_text = str(exc_plain.value)
    assert "GUARDRAILS_MAX_DOC_CHARS (max_doc_chars)" in plain_text
    assert "'99999'" in plain_text
    assert "'50000'" in plain_text


# ---------------------------------------------------------------------------
# Stage 1 parser grammar & loader error paths (permanent regression baseline)
# ---------------------------------------------------------------------------


def test_env_file_precedence_and_errors(tmp_path, monkeypatch):
    explicit = tmp_path / "precedence.env"
    explicit.write_text(
        "GUARDRAILS_API_KEY=file-secret\n"
        "GUARDRAILS_MAX_PROMPT_CHARS=8888\n"
        "GUARDRAILS_REQUIRE_AUTH=true\n",
        encoding="utf-8",
    )
    resolved = config.Settings.from_environ(
        {
            "GUARDRAILS_ENV_FILE": str(explicit),
            "GUARDRAILS_API_KEY": "process-secret",
            "GUARDRAILS_MAX_PROMPT_CHARS": "",
        }
    )
    assert resolved.api_key.get_secret_value() == "process-secret"
    assert resolved.max_prompt_chars == 20_000
    assert resolved.require_auth is True

    with pytest.raises(config.ConfigError, match="missing_file"):
        config.load_env_file(tmp_path / "missing.env")

    d = tmp_path / "dir"
    d.mkdir()
    with pytest.raises(config.ConfigError, match="not_a_regular_file"):
        config.load_env_file(d)

    bad_utf8 = tmp_path / "bad_utf8.env"
    bad_utf8.write_bytes(b"KEY=\xff\xfe\xfd")
    with pytest.raises(config.ConfigError, match="invalid_utf8"):
        config.load_env_file(bad_utf8)

    unreadable = tmp_path / "unreadable.env"
    unreadable.write_text("KEY=1\n", encoding="utf-8")
    monkeypatch.setattr(type(unreadable), "read_text", lambda *a, **kw: (_ for _ in ()).throw(PermissionError("no")))
    with pytest.raises(config.ConfigError, match="unreadable_file"):
        config.load_env_file(unreadable)
    monkeypatch.undo()

    self_ref = tmp_path / "self_ref.env"
    self_ref.write_text("GUARDRAILS_ENV_FILE=/other.env\n", encoding="utf-8")
    with pytest.raises(config.ConfigError, match="GUARDRAILS_ENV_FILE"):
        config.load_env_file(self_ref)


def test_env_file_positive_and_negative_literal_dollar_grammar(tmp_path):
    pos = tmp_path / "pos.env"
    pos.write_text(
        "# comment\n"
        "export EXP = one # comment\n"
        "EQ=a=b==1\n"
        "HASH=abc#123\n"
        "EMPTY= # comment\n"
        "SQ1='$'\n"
        "SQ2='$VAR'\n"
        "DQ1=\"\\$\"\n"
        "DQ2=\"\\$VAR\"\n"
        "DQ_ESC=\"\\\"\\\\\\n\\r\\t\"\n",
        encoding="utf-8",
    )
    assert config.load_env_file(pos) == {
        "EXP": "one",
        "EQ": "a=b==1",
        "HASH": "abc#123",
        "EMPTY": "",
        "SQ1": "$",
        "SQ2": "$VAR",
        "DQ1": "$",
        "DQ2": "$VAR",
        "DQ_ESC": '"\\\n\r\t',
    }

    bad_lines = [
        "NO_EQUALS",
        "export",
        "1BAD=1",
        "KEY='unterminated",
        'KEY="unterminated',
        "KEY='ok' trailing",
        'KEY="bad\\q"',
        'KEY="end\\',
        "KEY=a'b",
        "KEY=$",
        r"KEY=\$",
        "KEY=$VAR",
        r"KEY=\$VAR",
        "KEY=${VAR}",
        "KEY=$()",
        "KEY=`cmd`",
        'KEY="$"',
        'KEY="$VAR"',
        'KEY="${VAR}"',
        'KEY="$()"',
        'KEY="`cmd`"',
    ]
    for line in bad_lines:
        bad = tmp_path / "bad.env"
        bad.write_text(f"{line}\n", encoding="utf-8")
        with pytest.raises(config.ConfigError, match="line 1"):
            config.load_env_file(bad)
