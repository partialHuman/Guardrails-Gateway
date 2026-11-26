"""
Authoritative pure-standard-library configuration metadata registry.

This module intentionally uses only the Python standard library so static
tooling (such as configuration documentation generation) can inspect metadata
directly without triggering application initialization or reading runtime
environment state.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigFieldSpec:
    """Declarative metadata specification for one configuration variable."""

    env_var: str
    python_attr: str | None
    component: str
    section: str
    type_display: str
    default_display: str
    required_label: str
    validation_rules: str
    description: str
    sensitive: bool = False
    deprecated: bool = False


CONFIG_SPECS: tuple[ConfigFieldSpec, ...] = (
    ConfigFieldSpec(
        env_var="GUARDRAILS_API_KEY",
        python_attr="api_key",
        component="API / UI / CLI",
        section="Authentication & Ingress Safety",
        type_display="SecretStr (compat str)",
        default_display='""',
        required_label="Optional (required in hardened mode)",
        validation_rules="Stripped string; recommended length >= 16 characters",
        description="Shared API secret key verified via X-API-Key or Authorization Bearer.",
        sensitive=True,
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_REQUIRE_AUTH",
        python_attr="require_auth",
        component="API",
        section="Authentication & Ingress Safety",
        type_display="Boolean",
        default_display="false",
        required_label="Optional",
        validation_rules="Strict boolean (true/false, 1/0, yes/no, on/off, y/n, t/f)",
        description="Mandates authentication; fails startup if true while GUARDRAILS_API_KEY is empty.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_ALLOW_ANONYMOUS",
        python_attr="allow_anonymous",
        component="API",
        section="Authentication & Ingress Safety",
        type_display="Boolean",
        default_display="true (Code) / false (Container)",
        required_label="Optional",
        validation_rules="Strict boolean (true/false, 1/0, yes/no, on/off, y/n, t/f)",
        description="Permits unauthenticated startup when no API key is configured; disabled in shipped containers.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_PUBLIC_PATHS",
        python_attr="public_paths",
        component="API",
        section="Authentication & Ingress Safety",
        type_display="frozenset[str] | None",
        default_display="None (/health, /docs, /redoc, /openapi.json)",
        required_label="Optional",
        validation_rules="Comma-separated paths; every non-empty entry must start with '/'",
        description="Explicit override of route paths exempt from API-key authentication.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_MAX_REQUEST_BODY_BYTES",
        python_attr="max_request_body_bytes",
        component="API",
        section="Request Sizing & Memory Bounds",
        type_display="Integer",
        default_display="1048576",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Maximum raw HTTP request body size in bytes before returning HTTP 413.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_MAX_PROMPT_CHARS",
        python_attr="max_prompt_chars",
        component="API",
        section="Request Sizing & Memory Bounds",
        type_display="Integer",
        default_display="20000",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Maximum raw character length permitted for the input prompt.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_MAX_CONTEXT_DOCS",
        python_attr="max_context_docs",
        component="API",
        section="Request Sizing & Memory Bounds",
        type_display="Integer",
        default_display="20",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Maximum number of RAG context documents permitted per /analyze request.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_MAX_DOC_CHARS",
        python_attr="max_doc_chars",
        component="API",
        section="Request Sizing & Memory Bounds",
        type_display="Integer",
        default_display="50000",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Maximum raw character length permitted for each context document.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_MAX_NORMALIZED_PROMPT_CHARS",
        python_attr="max_normalized_prompt_chars",
        component="API",
        section="Request Sizing & Memory Bounds",
        type_display="Integer",
        default_display="40000",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Scan budget cap for normalized prompt characters.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_MAX_NORMALIZED_DOC_CHARS",
        python_attr="max_normalized_doc_chars",
        component="API",
        section="Request Sizing & Memory Bounds",
        type_display="Integer",
        default_display="100000",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Scan budget cap for normalized characters per context document.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_MAX_NORMALIZED_REQUEST_CHARS",
        python_attr="max_normalized_request_chars",
        component="API",
        section="Request Sizing & Memory Bounds",
        type_display="Integer",
        default_display="500000",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Scan budget cap for combined normalized characters across a single request.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_RATE_LIMIT_REQUESTS",
        python_attr="rate_limit_requests",
        component="API",
        section="Tiered Rate Limiting & Proxy Trust",
        type_display="Integer",
        default_display="60",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Maximum general requests per client per rate-limit window.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_RATE_LIMIT_WINDOW_SECONDS",
        python_attr="rate_limit_window_seconds",
        component="API",
        section="Tiered Rate Limiting & Proxy Trust",
        type_display="Integer",
        default_display="60",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Duration of the general rate-limit window in seconds.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_RATE_LIMIT_MAX_CLIENTS",
        python_attr="rate_limit_max_clients",
        component="API",
        section="Tiered Rate Limiting & Proxy Trust",
        type_display="Integer",
        default_display="50000",
        required_label="Optional",
        validation_rules="Integer >= 100",
        description="Maximum distinct client keys tracked in memory before overflow bucketing.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_AUTH_FAILURE_LIMIT_REQUESTS",
        python_attr="auth_failure_limit_requests",
        component="API",
        section="Tiered Rate Limiting & Proxy Trust",
        type_display="Integer",
        default_display="10",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Maximum failed authentication attempts allowed per client per failure window.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_AUTH_FAILURE_WINDOW_SECONDS",
        python_attr="auth_failure_window_seconds",
        component="API",
        section="Tiered Rate Limiting & Proxy Trust",
        type_display="Integer",
        default_display="60",
        required_label="Optional",
        validation_rules="Integer >= 1",
        description="Duration of the failed-authentication rate-limit window in seconds.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_RATE_LIMIT_BACKEND",
        python_attr="rate_limit_backend",
        component="API",
        section="Distributed Redis Rate Limiting",
        type_display='Literal["memory", "redis"]',
        default_display='"memory"',
        required_label="Optional",
        validation_rules='Case-insensitive enum: "memory" or "redis"',
        description="Rate limiter storage backend ('memory' single-process or shared 'redis').",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_RATE_LIMIT_REDIS_URL",
        python_attr="rate_limit_redis_url",
        component="API",
        section="Distributed Redis Rate Limiting",
        type_display="SecretStr (compat str)",
        default_display='""',
        required_label="Optional (required if backend is 'redis')",
        validation_rules="Empty string or URI starting with redis://, rediss://, or unix://",
        description="Redis connection URL for distributed sliding-window rate limiting.",
        sensitive=True,
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_RATE_LIMIT_REDIS_TIMEOUT_SECONDS",
        python_attr="rate_limit_redis_timeout_seconds",
        component="API",
        section="Distributed Redis Rate Limiting",
        type_display="Float",
        default_display="0.25",
        required_label="Optional",
        validation_rules="Finite float >= 0.01 (rejects NaN and +/-inf)",
        description="Socket connect and read timeout in seconds for Redis rate-limiter calls.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_RATE_LIMIT_FAIL_CLOSED",
        python_attr="rate_limit_fail_closed",
        component="API",
        section="Distributed Redis Rate Limiting",
        type_display="Boolean",
        default_display="false",
        required_label="Optional",
        validation_rules="Strict boolean (true/false, 1/0, yes/no, on/off, y/n, t/f)",
        description="If true, denies requests when Redis is unavailable; if false, fails open.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_TRUSTED_PROXIES",
        python_attr="trusted_proxies",
        component="API",
        section="Tiered Rate Limiting & Proxy Trust",
        type_display="frozenset[str]",
        default_display='"" (frozenset())',
        required_label="Optional",
        validation_rules="Comma-separated valid IPv4/IPv6 addresses or CIDR networks",
        description="Trusted reverse proxies permitted to supply X-Forwarded-For client identity.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_ENV_FILE",
        python_attr="env_file",
        component="Loader / Tooling",
        section="Loader & Runtime Control",
        type_display="str | None",
        default_display="None (disabled)",
        required_label="Optional",
        validation_rules="Explicit readable regular UTF-8 file path in process env; never auto-discovered",
        description="Opt-in path to a restricted key=value environment file evaluated below process env.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_STRICT_ENV",
        python_attr="strict_env",
        component="Loader / Tooling",
        section="Loader & Runtime Control",
        type_display="Boolean",
        default_display="false",
        required_label="Optional",
        validation_rules="Strict boolean (true/false, 1/0, yes/no, on/off, y/n, t/f)",
        description="When true, unrecognized GUARDRAILS_* variables fail startup instead of logging warnings.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_UI_PASSWORD",
        python_attr=None,
        component="UI",
        section="Web UI",
        type_display="String",
        default_display='""',
        required_label="Optional",
        validation_rules="Stripped string",
        description="Access password guarding the Streamlit web UI login gate.",
        sensitive=True,
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_UI_ALLOW_ANONYMOUS",
        python_attr=None,
        component="UI",
        section="Web UI",
        type_display="Boolean",
        default_display="false",
        required_label="Optional",
        validation_rules="Strict boolean (true/false, 1/0, yes/no, on/off, y/n, t/f)",
        description="Permits anonymous web UI usage when no UI password is set.",
    ),
    ConfigFieldSpec(
        env_var="API_URL",
        python_attr=None,
        component="UI",
        section="Web UI",
        type_display="URL String",
        default_display='"http://localhost:8000" / "http://api:8000"',
        required_label="Optional",
        validation_rules="Non-empty http:// or https:// base URL",
        description="Backend FastAPI base endpoint targeted by the Streamlit UI.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_API_URL",
        python_attr=None,
        component="CLI",
        section="CLI & Container Hosting",
        type_display="URL String",
        default_display='"http://127.0.0.1:8000"',
        required_label="Optional",
        validation_rules="Non-empty http:// or https:// base URL",
        description="Default gateway endpoint used by the CLI client.",
    ),
    ConfigFieldSpec(
        env_var="GUARDRAILS_BIND_ADDRESS",
        python_attr=None,
        component="Compose",
        section="CLI & Container Hosting",
        type_display="String",
        default_display='"127.0.0.1"',
        required_label="Optional",
        validation_rules="Host interface bind IP (e.g. 127.0.0.1 or 0.0.0.0)",
        description="Host network bind address published by Docker Compose services.",
    ),
)

ALL_KNOWN_GUARDRAILS_VARS: frozenset[str] = frozenset(
    spec.env_var
    for spec in CONFIG_SPECS
    if spec.env_var.upper().startswith("GUARDRAILS_")
)

API_SETTINGS_ENV_BY_ATTR: dict[str, str] = {
    spec.python_attr: spec.env_var
    for spec in CONFIG_SPECS
    if spec.python_attr is not None
}
