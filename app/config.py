"""
Application configuration.

Keeping configuration in one place makes it easier
to modify and extend the project.

Limits can be overridden with environment variables (and optionally loaded
from an explicit file named in ``GUARDRAILS_ENV_FILE``).

Parsing is STRICT: an unparseable or out-of-range value raises ConfigError
at import time and the application refuses to start. Silently falling back
to a default is dangerous for security settings (for example
``GUARDRAILS_REQUIRE_AUTH=on`` used to be read as "false" and leave the
gateway unauthenticated without any warning).
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from app.config_specs import ALL_KNOWN_GUARDRAILS_VARS, API_SETTINGS_ENV_BY_ATTR

API_TITLE = "SentraGuard Lite"

API_VERSION = "1.2.1"

API_DESCRIPTION = """
Offline AI Guardrails Gateway

Features
--------
\u2022 Prompt Injection Detection (with Unicode / encoding normalisation)
\u2022 PII Detection & Redaction (email, phone, payment card, Aadhaar)
\u2022 RAG Injection Detection (suspicious documents are quarantined)
\u2022 Risk Scoring
\u2022 Prompt & Context Sanitization

Runs completely offline.
"""


class ConfigError(ValueError):
    """An environment setting is invalid; the application must not start."""


_TRUE_VALUES = frozenset({"true", "1", "yes", "on", "y", "t"})

_FALSE_VALUES = frozenset({"false", "0", "no", "off", "n", "f"})

_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_DOUBLE_QUOTE_ESCAPES: dict[str, str] = {
    '"': '"',
    "\\": "\\",
    "$": "$",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}

_REDIS_SCHEMES = ("redis://", "rediss://", "unix://")


def _raw(name: str, environ: Mapping[str, str] | None = None) -> str | None:
    """Return the stripped value, or None when unset/blank (use the default)."""
    env = os.environ if environ is None else environ
    value = env.get(name)

    if value is None or not value.strip():
        return None

    return value.strip()


def _parse_bool_value(name: str, value: str) -> bool:
    """Parse an already-stripped boolean string or raise a sanitized ConfigError."""
    lowered = value.lower()

    if lowered in _TRUE_VALUES:
        return True

    if lowered in _FALSE_VALUES:
        return False

    raise ConfigError(
        f"{name} must be a boolean (true/false, 1/0, yes/no, on/off)"
    )


def _bool_env(
    name: str,
    default: bool,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Parse an optional boolean variable strictly from *environ* (or ``os.environ``)."""
    value = _raw(name, environ=environ)

    if value is None:
        return default

    return _parse_bool_value(name, value)


def _parse_int_value(
    name: str,
    value: str,
    minimum: int | None = None,
) -> int:
    """Parse an already-stripped integer string and enforce *minimum* safely."""
    try:
        number = int(value)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None

    if minimum is not None and number < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")

    return number


def _int_env(
    name: str,
    default: int,
    minimum: int | None = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Parse an optional integer variable strictly from *environ* (or ``os.environ``)."""
    value = _raw(name, environ=environ)

    if value is None:
        return default

    return _parse_int_value(name, value, minimum=minimum)


def _parse_float_value(
    name: str,
    value: str,
    minimum: float | None = None,
) -> float:
    """Parse an already-stripped finite float string and enforce *minimum* safely."""
    try:
        number = float(value)
    except ValueError:
        raise ConfigError(f"{name} must be a number") from None

    if not math.isfinite(number):
        raise ConfigError(f"{name} must be a finite number")

    if minimum is not None and number < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")

    return number


def _float_env(
    name: str,
    default: float,
    minimum: float | None = None,
    environ: Mapping[str, str] | None = None,
) -> float:
    """Parse an optional finite float variable strictly from *environ*."""
    value = _raw(name, environ=environ)

    if value is None:
        return default

    return _parse_float_value(name, value, minimum=minimum)


def _validate_trailing_comment(after_quote: str, key: str, lineno: int) -> None:
    """Ensure only horizontal whitespace or a whitespace-preceded ``#`` follows a quote."""
    if not after_quote.strip(" \t"):
        return

    if after_quote[0] in (" ", "\t") and after_quote.lstrip(" \t").startswith("#"):
        return

    raise ConfigError(
        f"Unexpected trailing characters after quoted value for key {key!r} "
        f"at line {lineno} in GUARDRAILS_ENV_FILE"
    )


def _parse_double_quoted_value(val_raw: str, key: str, lineno: int) -> str:
    """Parse a double-quoted value enforcing Revision 6 literal-dollar rules."""
    chars: list[str] = []
    idx = 1
    length = len(val_raw)
    closed = False

    while idx < length:
        ch = val_raw[idx]
        if ch == '"':
            closed = True
            idx += 1
            break

        if ch == "\\":
            if idx + 1 >= length:
                raise ConfigError(
                    f"Unterminated escape in double-quoted value for key {key!r} "
                    f"at line {lineno} in GUARDRAILS_ENV_FILE"
                )
            nxt = val_raw[idx + 1]
            if nxt not in _DOUBLE_QUOTE_ESCAPES:
                raise ConfigError(
                    f"Unsupported escape sequence in double-quoted value for key {key!r} "
                    f"at line {lineno} in GUARDRAILS_ENV_FILE"
                )
            chars.append(_DOUBLE_QUOTE_ESCAPES[nxt])
            idx += 2
            continue

        if ch == "$":
            raise ConfigError(
                f"Unsupported unescaped '$' in double-quoted value for key {key!r} "
                f"at line {lineno} in GUARDRAILS_ENV_FILE"
            )

        if ch == "`":
            raise ConfigError(
                f"Unsupported backtick substitution in double-quoted value for key {key!r} "
                f"at line {lineno} in GUARDRAILS_ENV_FILE"
            )

        chars.append(ch)
        idx += 1

    if not closed:
        raise ConfigError(
            f"Unterminated double-quoted value for key {key!r} "
            f"at line {lineno} in GUARDRAILS_ENV_FILE"
        )

    _validate_trailing_comment(val_raw[idx:], key, lineno)
    return "".join(chars)


def _parse_unquoted_value(val_part: str, val_raw: str, key: str, lineno: int) -> str:
    """Parse an unquoted value rejecting every '$', backtick, and stray quote."""
    if val_raw.startswith("#") and val_part[:1] in (" ", "\t"):
        return ""

    core = val_raw
    for idx, ch in enumerate(val_raw):
        if ch == "#" and idx > 0 and val_raw[idx - 1] in (" ", "\t"):
            core = val_raw[:idx]
            break

    value = core.rstrip(" \t")

    if "'" in value or '"' in value:
        raise ConfigError(
            f"Unexpected quote in unquoted value for key {key!r} "
            f"at line {lineno} in GUARDRAILS_ENV_FILE"
        )

    if "`" in value:
        raise ConfigError(
            f"Unsupported backtick substitution in unquoted value for key {key!r} "
            f"at line {lineno} in GUARDRAILS_ENV_FILE"
        )

    if "$" in value:
        raise ConfigError(
            f"Unsupported '$' in unquoted value for key {key!r} "
            f"at line {lineno} in GUARDRAILS_ENV_FILE"
        )

    return value


def _parse_env_line(raw_line: str, lineno: int) -> tuple[str, str] | None:
    """Parse one non-comment assignment line from an explicit environment file."""
    stripped = raw_line.lstrip(" \t")
    if not stripped or stripped.startswith("#"):
        return None

    candidate = stripped
    if candidate.startswith("export") and (
        len(candidate) == 6 or candidate[6] in (" ", "\t")
    ):
        candidate = candidate[6:].lstrip(" \t")
        if not candidate:
            raise ConfigError(
                f"Missing '=' delimiter in GUARDRAILS_ENV_FILE at line {lineno}"
            )

    key_part, sep, val_part = candidate.partition("=")
    if not sep:
        raise ConfigError(
            f"Missing '=' delimiter in GUARDRAILS_ENV_FILE at line {lineno}"
        )

    key = key_part.strip(" \t")
    if not _ENV_KEY_RE.fullmatch(key):
        raise ConfigError(
            f"Invalid configuration key at line {lineno} in GUARDRAILS_ENV_FILE"
        )

    if key == "GUARDRAILS_ENV_FILE":
        raise ConfigError(
            f"Forbidden self-referential key 'GUARDRAILS_ENV_FILE' "
            f"at line {lineno} in GUARDRAILS_ENV_FILE"
        )

    val_raw = val_part.lstrip(" \t")

    if val_raw.startswith("'"):
        end_idx = val_raw.find("'", 1)
        if end_idx == -1:
            raise ConfigError(
                f"Unterminated single-quoted value for key {key!r} "
                f"at line {lineno} in GUARDRAILS_ENV_FILE"
            )
        _validate_trailing_comment(val_raw[end_idx + 1 :], key, lineno)
        return key, val_raw[1:end_idx]

    if val_raw.startswith('"'):
        return key, _parse_double_quoted_value(val_raw, key, lineno)

    return key, _parse_unquoted_value(val_part, val_raw, key, lineno)


def load_env_file(path: Path) -> dict[str, str]:
    """Load and validate an explicit environment file using a restricted stdlib grammar."""
    try:
        if not path.exists():
            raise ConfigError("GUARDRAILS_ENV_FILE configuration error: missing_file")
        if not path.is_file():
            raise ConfigError("GUARDRAILS_ENV_FILE configuration error: not_a_regular_file")
        content = path.read_text(encoding="utf-8")
    except ConfigError:
        raise
    except UnicodeDecodeError:
        raise ConfigError("GUARDRAILS_ENV_FILE configuration error: invalid_utf8") from None
    except OSError:
        raise ConfigError("GUARDRAILS_ENV_FILE configuration error: unreadable_file") from None

    parsed: dict[str, str] = {}
    seen_keys: dict[str, int] = {}

    for lineno, raw_line in enumerate(content.splitlines(), start=1):
        entry = _parse_env_line(raw_line, lineno)
        if entry is None:
            continue
        key, value = entry
        if key in seen_keys:
            raise ConfigError(
                f"Duplicate configuration key {key!r} at line {lineno} "
                f"(previously defined at line {seen_keys[key]}) in GUARDRAILS_ENV_FILE"
            )
        seen_keys[key] = lineno
        parsed[key] = value

    return parsed


def build_effective_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Resolve effective environment with process env > explicit GUARDRAILS_ENV_FILE."""
    process_env = os.environ if environ is None else environ
    raw_env_file = process_env.get("GUARDRAILS_ENV_FILE")

    file_vars: dict[str, str] = {}
    if raw_env_file is not None and raw_env_file.strip():
        resolved = Path(raw_env_file.strip()).expanduser()
        file_vars = load_env_file(resolved)

    # Process keys — even when empty string "" — always override file keys.
    return {**file_vars, **process_env}


def detect_unknown_guardrails_vars(
    environ: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Inspect environment keys only and return any unrecognized GUARDRAILS_* names."""
    env = os.environ if environ is None else environ
    return tuple(
        key
        for key in env
        if key.upper().startswith("GUARDRAILS_") and key not in ALL_KNOWN_GUARDRAILS_VARS
    )


def _normalize_secret_input(value: object) -> str:
    if isinstance(value, SecretStr):
        return value.get_secret_value().strip()
    if isinstance(value, str):
        return value.strip()
    raise ValueError("must be a string")


def _split_csv_entries(value: object, error_msg: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, (frozenset, set, list, tuple)):
        return frozenset(str(item).strip() for item in value if str(item).strip())
    raise ValueError(error_msg)


def _parse_public_paths_value(value: object) -> frozenset[str] | None:
    raw_entries = _split_csv_entries(value, "entries must be slash-prefixed paths")
    if not raw_entries:
        return None
    paths = frozenset(entry.rstrip("/") or "/" for entry in raw_entries)
    for entry in paths:
        if not entry.startswith("/"):
            raise ValueError("entries must start with '/'")
    return paths


def _parse_trusted_proxies_value(value: object) -> frozenset[str]:
    entries = _split_csv_entries(value, "entries must be IP addresses or CIDR networks")
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise ValueError("entries must be IP addresses or CIDR networks") from None
    return entries


class Settings(BaseModel):
    """Immutable, strictly validated SentraGuard Lite configuration model."""

    model_config = ConfigDict(
        frozen=True,
        hide_input_in_errors=True,
        populate_by_name=True,
    )

    api_key: SecretStr = Field(default_factory=lambda: SecretStr(""))
    require_auth: bool = False
    allow_anonymous: bool = True
    public_paths: frozenset[str] | None = None

    max_request_body_bytes: int = Field(default=1_048_576, ge=1)
    max_prompt_chars: int = Field(default=20_000, ge=1)
    max_context_docs: int = Field(default=20, ge=1)
    max_doc_chars: int = Field(default=50_000, ge=1)
    max_normalized_prompt_chars: int = Field(default=40_000, ge=1)
    max_normalized_doc_chars: int = Field(default=100_000, ge=1)
    max_normalized_request_chars: int = Field(default=500_000, ge=1)

    rate_limit_requests: int = Field(default=60, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    rate_limit_max_clients: int = Field(default=50_000, ge=100)
    auth_failure_limit_requests: int = Field(default=10, ge=1)
    auth_failure_window_seconds: int = Field(default=60, ge=1)

    rate_limit_backend: Literal["memory", "redis"] = "memory"
    rate_limit_redis_url: SecretStr = Field(default_factory=lambda: SecretStr(""))
    rate_limit_redis_timeout_seconds: float = Field(default=0.25, ge=0.01)
    rate_limit_fail_closed: bool = False
    trusted_proxies: frozenset[str] = Field(default_factory=frozenset)

    env_file: str | None = None
    strict_env: bool = False

    @field_validator("api_key", mode="before")
    @classmethod
    def _validate_api_key(cls, value: object) -> SecretStr:
        if value is None:
            return SecretStr("")
        return SecretStr(_normalize_secret_input(value))

    @field_validator("rate_limit_redis_url", mode="before")
    @classmethod
    def _validate_redis_url(cls, value: object) -> SecretStr:
        if value is None:
            return SecretStr("")
        cleaned = _normalize_secret_input(value)
        if not cleaned:
            return SecretStr("")
        if not cleaned.lower().startswith(_REDIS_SCHEMES):
            raise ValueError("must be empty or start with redis://, rediss://, or unix://")
        return SecretStr(cleaned)

    @field_validator(
        "require_auth",
        "allow_anonymous",
        "rate_limit_fail_closed",
        "strict_env",
        mode="before",
    )
    @classmethod
    def _validate_bool_fields(cls, value: object, info) -> object:
        if isinstance(value, bool):
            return value
        if value is None or (isinstance(value, str) and not value.strip()):
            return cls.model_fields[info.field_name].default
        if isinstance(value, str):
            return _parse_bool_value(info.field_name, value.strip())
        raise ValueError("must be a boolean (true/false, 1/0, yes/no, on/off)")

    @field_validator(
        "max_request_body_bytes",
        "max_prompt_chars",
        "max_context_docs",
        "max_doc_chars",
        "max_normalized_prompt_chars",
        "max_normalized_doc_chars",
        "max_normalized_request_chars",
        "rate_limit_requests",
        "rate_limit_window_seconds",
        "rate_limit_max_clients",
        "auth_failure_limit_requests",
        "auth_failure_window_seconds",
        mode="before",
    )
    @classmethod
    def _validate_int_fields(cls, value: object, info) -> int:
        if isinstance(value, bool):
            raise ValueError("must be an integer")
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return cls.model_fields[info.field_name].default
            return _parse_int_value(info.field_name, stripped)
        raise ValueError("must be an integer")

    @field_validator("rate_limit_redis_timeout_seconds", mode="before")
    @classmethod
    def _validate_redis_timeout(cls, value: object) -> float:
        if isinstance(value, bool):
            raise ValueError("must be a finite number")
        if isinstance(value, str):
            stripped = value.strip()
            return _parse_float_value("rate_limit_redis_timeout_seconds", stripped) if stripped else 0.25
        if isinstance(value, (int, float)):
            number = float(value)
            if not math.isfinite(number):
                raise ValueError("must be a finite number")
            return number
        raise ValueError("must be a number")

    @field_validator("rate_limit_backend", mode="before")
    @classmethod
    def _validate_backend(cls, value: object) -> str:
        if value is None:
            return "memory"
        if not isinstance(value, str):
            raise ValueError("must be 'memory' or 'redis'")
        normalized = value.strip().lower() or "memory"
        if normalized not in ("memory", "redis"):
            raise ValueError("must be 'memory' or 'redis'")
        return normalized

    @field_validator("public_paths", mode="before")
    @classmethod
    def _validate_public_paths(cls, value: object) -> frozenset[str] | None:
        return _parse_public_paths_value(value)

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def _validate_trusted_proxies(cls, value: object) -> frozenset[str]:
        return _parse_trusted_proxies_value(value)

    @field_validator("env_file", mode="before")
    @classmethod
    def _validate_env_file(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("must be a file path string")
        stripped = value.strip()
        return stripped or None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> Settings:
        """Instantiate validated ``Settings`` from process env and optional ``GUARDRAILS_ENV_FILE``."""
        effective_env = build_effective_env(environ)
        payload = {
            attr: effective_env[env_var]
            for attr, env_var in API_SETTINGS_ENV_BY_ATTR.items()
            if env_var in effective_env
        }

        sanitized_details: tuple[tuple[str, str], ...] | None = None
        try:
            settings = cls.model_validate(payload)
        except ValidationError as exc:
            # Extract safe identifiers inside except so ConfigError is raised
            # outside any active exception handler (__cause__ is None and
            # __context__ is None).
            details: list[tuple[str, str]] = []
            for err in exc.errors(include_url=False, include_input=False):
                loc = err.get("loc", ())
                attr = str(loc[0]) if loc else ""
                env_name = API_SETTINGS_ENV_BY_ATTR.get(attr, attr or "CONFIGURATION")
                err_type = str(err.get("type", "validation_error"))
                details.append((env_name, err_type))
            sanitized_details = tuple(details)

        if sanitized_details is not None:
            summary = "; ".join(f"{name}: {category}" for name, category in sanitized_details)
            raise ConfigError(f"Configuration validation failed ({summary})") from None

        return settings


_CURRENT_SETTINGS: Settings


def _bind_module_globals(settings: Settings) -> None:
    """Bind v1.2 compatibility module globals from validated *settings*."""
    global _CURRENT_SETTINGS
    global MAX_PROMPT_CHARS, MAX_CONTEXT_DOCS, MAX_DOC_CHARS
    global MAX_NORMALIZED_PROMPT_CHARS, MAX_NORMALIZED_DOC_CHARS, MAX_NORMALIZED_REQUEST_CHARS
    global MAX_REQUEST_BODY_BYTES
    global RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_MAX_CLIENTS
    global AUTH_FAILURE_LIMIT_REQUESTS, AUTH_FAILURE_WINDOW_SECONDS
    global RATE_LIMIT_BACKEND, RATE_LIMIT_REDIS_URL, RATE_LIMIT_REDIS_TIMEOUT_SECONDS
    global RATE_LIMIT_FAIL_CLOSED, TRUSTED_PROXIES
    global API_KEY, REQUIRE_AUTH, ALLOW_ANONYMOUS, PUBLIC_PATHS

    _CURRENT_SETTINGS = settings

    MAX_PROMPT_CHARS = settings.max_prompt_chars
    MAX_CONTEXT_DOCS = settings.max_context_docs
    MAX_DOC_CHARS = settings.max_doc_chars
    MAX_NORMALIZED_PROMPT_CHARS = settings.max_normalized_prompt_chars
    MAX_NORMALIZED_DOC_CHARS = settings.max_normalized_doc_chars
    MAX_NORMALIZED_REQUEST_CHARS = settings.max_normalized_request_chars
    MAX_REQUEST_BODY_BYTES = settings.max_request_body_bytes

    RATE_LIMIT_REQUESTS = settings.rate_limit_requests
    RATE_LIMIT_WINDOW_SECONDS = settings.rate_limit_window_seconds
    RATE_LIMIT_MAX_CLIENTS = settings.rate_limit_max_clients
    AUTH_FAILURE_LIMIT_REQUESTS = settings.auth_failure_limit_requests
    AUTH_FAILURE_WINDOW_SECONDS = settings.auth_failure_window_seconds

    RATE_LIMIT_BACKEND = settings.rate_limit_backend
    RATE_LIMIT_REDIS_URL = settings.rate_limit_redis_url.get_secret_value()
    RATE_LIMIT_REDIS_TIMEOUT_SECONDS = settings.rate_limit_redis_timeout_seconds
    RATE_LIMIT_FAIL_CLOSED = settings.rate_limit_fail_closed
    TRUSTED_PROXIES = settings.trusted_proxies

    API_KEY = settings.api_key.get_secret_value()
    REQUIRE_AUTH = settings.require_auth
    ALLOW_ANONYMOUS = settings.allow_anonymous
    PUBLIC_PATHS = settings.public_paths


def get_settings() -> Settings:
    """Return the active validated immutable ``Settings`` instance."""
    return _CURRENT_SETTINGS


def reload_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Re-load configuration from *environ* (or ``os.environ``) and update module globals."""
    new_settings = Settings.from_environ(environ)
    _bind_module_globals(new_settings)
    return new_settings


_bind_module_globals(Settings.from_environ())
