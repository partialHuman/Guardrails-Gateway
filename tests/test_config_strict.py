"""SG-003: invalid configuration stops startup instead of weakening security."""

import contextlib
import importlib

import pytest


@contextlib.contextmanager
def reloaded_config(monkeypatch, **env):
    """Reload app.config under the given environment, then restore it."""
    import app.config as cfg

    for key, value in env.items():
        monkeypatch.setenv(key, value)

    try:
        yield importlib.reload(cfg)
    finally:
        for key in env:
            monkeypatch.delenv(key, raising=False)
        importlib.reload(cfg)


@pytest.mark.parametrize(
    "value", ["true", "TRUE", "True", "1", "yes", "on", "ON", "y", "t", "  on  "]
)
def test_require_auth_truthy_spellings_enable_auth(monkeypatch, value):
    with reloaded_config(monkeypatch, GUARDRAILS_REQUIRE_AUTH=value) as cfg:
        assert cfg.REQUIRE_AUTH is True


@pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "off", "n", "f", ""])
def test_require_auth_falsy_or_blank_means_default_off(monkeypatch, value):
    with reloaded_config(monkeypatch, GUARDRAILS_REQUIRE_AUTH=value) as cfg:
        assert cfg.REQUIRE_AUTH is False


@pytest.mark.parametrize("value", ["enabled", "tru", "2", "maybe", "true;", "yess"])
def test_require_auth_unrecognised_value_refuses_to_start(monkeypatch, value):
    # Previously every unrecognised spelling silently meant "false", leaving
    # the gateway unauthenticated if no API key was set.
    with pytest.raises(ValueError, match="GUARDRAILS_REQUIRE_AUTH"):
        with reloaded_config(monkeypatch, GUARDRAILS_REQUIRE_AUTH=value):
            pass


def test_allow_anonymous_defaults_to_true_for_local_development(monkeypatch):
    monkeypatch.delenv("GUARDRAILS_ALLOW_ANONYMOUS", raising=False)

    with reloaded_config(monkeypatch) as cfg:
        assert cfg.ALLOW_ANONYMOUS is True


def test_allow_anonymous_can_be_disabled(monkeypatch):
    with reloaded_config(monkeypatch, GUARDRAILS_ALLOW_ANONYMOUS="false") as cfg:
        assert cfg.ALLOW_ANONYMOUS is False


@pytest.mark.parametrize(
    "name, value",
    [
        ("GUARDRAILS_RATE_LIMIT_REQUESTS", "sixty"),
        ("GUARDRAILS_RATE_LIMIT_REQUESTS", "0"),
        ("GUARDRAILS_RATE_LIMIT_REQUESTS", "-5"),
        ("GUARDRAILS_RATE_LIMIT_REQUESTS", "60.5"),
        ("GUARDRAILS_RATE_LIMIT_WINDOW_SECONDS", "0"),
        ("GUARDRAILS_MAX_PROMPT_CHARS", "20k"),
        ("GUARDRAILS_MAX_DOC_CHARS", "-1"),
        ("GUARDRAILS_MAX_CONTEXT_DOCS", "0"),
        ("GUARDRAILS_AUTH_FAILURE_LIMIT_REQUESTS", "0"),
        ("GUARDRAILS_RATE_LIMIT_MAX_CLIENTS", "10"),
    ],
)
def test_numeric_settings_reject_typos_and_out_of_range(monkeypatch, name, value):
    with pytest.raises(ValueError, match=name):
        with reloaded_config(monkeypatch, **{name: value}):
            pass


@pytest.mark.parametrize("value", ["abc", "nan", "inf", "-1", "0"])
def test_redis_timeout_must_be_a_positive_finite_number(monkeypatch, value):
    with pytest.raises(ValueError, match="GUARDRAILS_RATE_LIMIT_REDIS_TIMEOUT_SECONDS"):
        with reloaded_config(
            monkeypatch, GUARDRAILS_RATE_LIMIT_REDIS_TIMEOUT_SECONDS=value
        ):
            pass


def test_valid_numeric_overrides_are_applied(monkeypatch):
    with reloaded_config(
        monkeypatch,
        GUARDRAILS_RATE_LIMIT_REQUESTS="120",
        GUARDRAILS_RATE_LIMIT_REDIS_TIMEOUT_SECONDS="0.5",
        GUARDRAILS_AUTH_FAILURE_LIMIT_REQUESTS="3",
    ) as cfg:
        assert cfg.RATE_LIMIT_REQUESTS == 120
        assert cfg.RATE_LIMIT_REDIS_TIMEOUT_SECONDS == 0.5
        assert cfg.AUTH_FAILURE_LIMIT_REQUESTS == 3


def test_trusted_proxies_accepts_addresses_and_cidr_networks(monkeypatch):
    with reloaded_config(
        monkeypatch,
        GUARDRAILS_TRUSTED_PROXIES="10.0.0.5, 172.18.0.0/16 ,fd00::/8",
    ) as cfg:
        assert cfg.TRUSTED_PROXIES == frozenset(
            {"10.0.0.5", "172.18.0.0/16", "fd00::/8"}
        )


@pytest.mark.parametrize("value", ["not-an-ip", "10.0.0.0/33", "10.0.0.1,proxy.local"])
def test_trusted_proxies_rejects_invalid_entries(monkeypatch, value):
    with pytest.raises(ValueError, match="GUARDRAILS_TRUSTED_PROXIES"):
        with reloaded_config(monkeypatch, GUARDRAILS_TRUSTED_PROXIES=value):
            pass


def test_public_paths_must_start_with_a_slash(monkeypatch):
    with pytest.raises(ValueError, match="GUARDRAILS_PUBLIC_PATHS"):
        with reloaded_config(monkeypatch, GUARDRAILS_PUBLIC_PATHS="health"):
            pass


def test_public_paths_override_is_parsed(monkeypatch):
    with reloaded_config(monkeypatch, GUARDRAILS_PUBLIC_PATHS="/health/, /ping") as cfg:
        assert cfg.PUBLIC_PATHS == frozenset({"/health", "/ping"})


def test_rate_limit_backend_is_normalised_and_validated(monkeypatch):
    with reloaded_config(monkeypatch, GUARDRAILS_RATE_LIMIT_BACKEND=" Redis ") as cfg:
        assert cfg.RATE_LIMIT_BACKEND == "redis"

    with pytest.raises(ValueError, match="GUARDRAILS_RATE_LIMIT_BACKEND"):
        with reloaded_config(monkeypatch, GUARDRAILS_RATE_LIMIT_BACKEND="memcached"):
            pass
