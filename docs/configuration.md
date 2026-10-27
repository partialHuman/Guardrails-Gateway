# Configuration Reference

SentraGuard Lite v1.2 enforces **strict fail-fast configuration parsing**. If an environment variable is unparseable, malformed, or violates boundary constraints, the gateway raises `app.config.ConfigError` at startup and halts execution.

> [!IMPORTANT]
> Silently falling back to defaults for invalid security configurations is dangerous. For example, in earlier versions `GUARDRAILS_REQUIRE_AUTH=on` or `GUARDRAILS_REQUIRE_AUTH=enabled` failed to match `true` and silently fell back to `false`, leaving the gateway unauthenticated without any warning. In v1.2, any invalid value halts startup immediately.

---

## Configuration Variables Overview

| Environment Variable | Default | Type | Component | Validation Rules | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GUARDRAILS_API_KEY` | `""` | String | API / UI | Freeform string (recommended $\ge 32$ chars) | Shared secret key for API authentication. |
| `GUARDRAILS_REQUIRE_AUTH` | `false` | Boolean | API | Boolean (`true/false`, `1/0`, `yes/no`, `on/off`) | Mandates authentication; fails on startup if key is missing. |
| `GUARDRAILS_ALLOW_ANONYMOUS` | `true` (Code) / `false` (Docker) | Boolean | API | Boolean | Allows unauthenticated operation. Disabled in production containers. |
| `GUARDRAILS_PUBLIC_PATHS` | `None` (`/health,/docs,...`) | String list | API | Comma-separated paths, each starting with `/` | Override of routes exempt from authentication. |
| `GUARDRAILS_MAX_REQUEST_BODY_BYTES` | `1048576` (1 MiB) | Integer | Middleware | Integer $\ge 1$ | Maximum raw HTTP request body size; rejects oversized payloads with HTTP 413. |
| `GUARDRAILS_MAX_PROMPT_CHARS` | `20000` | Integer | Schemas | Integer $\ge 1$ | Maximum character length for input prompt. |
| `GUARDRAILS_MAX_CONTEXT_DOCS` | `20` | Integer | Schemas | Integer $\ge 1$ | Maximum number of context documents accepted per request. |
| `GUARDRAILS_MAX_DOC_CHARS` | `50000` | Integer | Schemas | Integer $\ge 1$ | Maximum character length per context document. |
| `GUARDRAILS_RATE_LIMIT_REQUESTS` | `60` | Integer | Rate Limiter | Integer $\ge 1$ | General rate limit quota per client within window. |
| `GUARDRAILS_RATE_LIMIT_WINDOW_SECONDS` | `60` | Integer | Rate Limiter | Integer $\ge 1$ | Duration of general rate-limiting window in seconds. |
| `GUARDRAILS_AUTH_FAILURE_LIMIT_REQUESTS` | `10` | Integer | Rate Limiter | Integer $\ge 1$ | Maximum failed authentication attempts permitted per client before 429 lockout. |
| `GUARDRAILS_AUTH_FAILURE_WINDOW_SECONDS` | `60` | Integer | Rate Limiter | Integer $\ge 1$ | Duration of authentication failure throttling window in seconds. |
| `GUARDRAILS_RATE_LIMIT_MAX_CLIENTS` | `50000` | Integer | Rate Limiter | Integer $\ge 100$ | Maximum distinct client identities tracked in memory before overflow aggregation. |
| `GUARDRAILS_RATE_LIMIT_BACKEND` | `memory` | String | Rate Limiter | Must be either `'memory'` or `'redis'` | Backend engine for client rate limiting. |
| `GUARDRAILS_RATE_LIMIT_REDIS_URL` | `""` | String | Rate Limiter | Valid Redis URI format (e.g., `redis://redis:6379/0`) | Connection URL for shared Redis distributed limiter. |
| `GUARDRAILS_RATE_LIMIT_REDIS_TIMEOUT_SECONDS`| `0.25` | Float | Rate Limiter | Finite float $\ge 0.01$ | Socket connect/read timeout for Redis operations. |
| `GUARDRAILS_RATE_LIMIT_FAIL_CLOSED` | `false` | Boolean | Rate Limiter | Boolean | When `true`, denies requests if Redis is unreachable; when `false`, fails open. |
| `GUARDRAILS_TRUSTED_PROXIES` | `""` | String list | Middleware | Comma-separated valid IPv4/IPv6 addresses or CIDR blocks | Proxies allowed to specify client IP via `X-Forwarded-For`. |
| `GUARDRAILS_BIND_ADDRESS` | `127.0.0.1` | String | Compose | Valid IPv4/IPv6 binding address | Published host interface for Docker Compose port mapping. |
| `GUARDRAILS_UI_PASSWORD` | `""` | String | UI | Freeform string | Access password required to unlock the Streamlit web UI. |
| `GUARDRAILS_UI_ALLOW_ANONYMOUS` | `false` | Boolean | UI | Boolean | Allows unrestricted UI access without a password. |
| `API_URL` | `http://localhost:8000` | String | UI | Valid HTTP(S) URL | Base endpoint where Streamlit UI reaches the FastAPI backend. |

---

## Detailed Variable Specifications

### 1. Authentication & Ingress Safety

#### `GUARDRAILS_API_KEY`
- **Default:** `""` (Empty string)
- **Description:** The shared secret token expected by the gateway. Clients supply this key either via the `X-API-Key` HTTP header or the standard `Authorization: Bearer <key>` header.
- **Validation:** Inspected on startup by `app.core.auth.validate_auth_config`. Verified against incoming requests using constant-time byte comparison (`secrets.compare_digest`).

#### `GUARDRAILS_REQUIRE_AUTH`
- **Default:** `false`
- **Description:** When `true`, mandates that all non-public endpoints require valid credentials. If `GUARDRAILS_REQUIRE_AUTH=true` while `GUARDRAILS_API_KEY` is empty or whitespace, startup raises `RuntimeError("GUARDRAILS_REQUIRE_AUTH is true but GUARDRAILS_API_KEY is not set")`.
- **Parsing:** Accepts `true`, `1`, `yes`, `on`, `y`, `t` (case-insensitive). Invalid strings raise `ConfigError`.

#### `GUARDRAILS_ALLOW_ANONYMOUS`
- **Default:** `true` (Code default) / `false` (Shipped Dockerfile and Compose)
- **Description:** Governs whether the API is permitted to run without authentication. In local development environments, `true` avoids configuration friction. In container images, `false` ensures that a container cannot start unauthenticated unless the operator explicitly opts in.
- **Fail-Safe Startup:** If `REQUIRE_AUTH=false`, `API_KEY=""`, and `ALLOW_ANONYMOUS=false`, startup halts with `RuntimeError("No GUARDRAILS_API_KEY configured and anonymous access is not allowed")`.

#### `GUARDRAILS_PUBLIC_PATHS`
- **Default:** `None` (Internally defaults to `/health`, `/docs`, `/redoc`, `/openapi.json`)
- **Description:** Comma-separated list of paths that do not require authentication. Every specified path must begin with `/` (e.g. `/health,/metrics`).

---

### 2. Request Sizing & Memory Bounds

#### `GUARDRAILS_MAX_REQUEST_BODY_BYTES`
- **Default:** `1048576` (1 MiB)
- **Description:** Enforced by `RequestBodyLimitMiddleware` before reading the body into memory. If the `Content-Length` header or the cumulative streamed chunks exceed this limit, the gateway immediately terminates reading and returns `HTTP 413 Payload Too Large`.
- **Security Impact:** Prevents Denial-of-Service via unbounded memory allocation from huge streaming payloads.

#### `GUARDRAILS_MAX_PROMPT_CHARS`, `GUARDRAILS_MAX_CONTEXT_DOCS`, `GUARDRAILS_MAX_DOC_CHARS`
- **Defaults:** `20000` chars, `20` documents, `50000` chars per doc.
- **Description:** Validated by Pydantic schemas on the `/analyze` endpoint. Exceeding these limits produces `HTTP 422 Unprocessable Entity` with structured field errors.

---

### 3. Tiered Rate Limiting & Proxy Trust

SentraGuard Lite separates authentication verification from general rate limiting:

```
[Inbound Request]
        │
[Auth Check] ── Invalid Key ──> [Auth Failure Limiter] (Default: 10/min)
        │
   Valid / Public
        │
[General Limiter] (Default: 60/min) ── Exceeded ──> [HTTP 429 Too Many Requests]
        │
   Allowed ──> [Analysis Pipeline]
```

#### `GUARDRAILS_RATE_LIMIT_REQUESTS` & `GUARDRAILS_RATE_LIMIT_WINDOW_SECONDS`
- **Defaults:** `60` requests per `60` seconds.
- **Description:** Per-client quota for authenticated requests. `/health` is explicitly exempt.

#### `GUARDRAILS_AUTH_FAILURE_LIMIT_REQUESTS` & `GUARDRAILS_AUTH_FAILURE_WINDOW_SECONDS`
- **Defaults:** `10` attempts per `60` seconds.
- **Description:** Dedicated bucket for failed authentication attempts. Failed attempts do not consume legitimate user quotas, while brute-force credential guessing is throttled.

#### `GUARDRAILS_RATE_LIMIT_MAX_CLIENTS`
- **Default:** `50000` (Minimum: `100`)
- **Description:** Maximum number of distinct client identifiers stored by the in-memory rate limiter. If an attacker rotates millions of IP addresses (e.g., an IPv6 `/64`), clients beyond 50,000 share a single overflow bucket (`OVERFLOW_CLIENT_ID`), bounding memory consumption.

#### `GUARDRAILS_TRUSTED_PROXIES`
- **Default:** `""` (Empty string)
- **Description:** Comma-separated list of trusted reverse proxy IP addresses or CIDR blocks (e.g., `10.0.0.0/8,172.18.0.0/16,192.168.1.50`).
- **Resolution Logic:**
  - If unset: `X-Forwarded-For` is completely ignored; the direct TCP socket address (`request.client.host`) is used.
  - If set: The rightmost untrusted IP in the `X-Forwarded-For` chain is used as the client identity.
  - IPv6 addresses are automatically truncated to `/64` network prefixes for rate-limiting calculations.

---

### 4. Distributed Redis Rate Limiting

#### `GUARDRAILS_RATE_LIMIT_BACKEND`
- **Default:** `memory`
- **Accepted Values:** `memory` or `redis`.
- **Note:** Redis support requires installing `requirements.redis.txt` (`pip install -r requirements.redis.txt`).

#### `GUARDRAILS_RATE_LIMIT_REDIS_URL`
- **Default:** `""`
- **Format:** `redis://[[username]:[password]@]host[:port][/database]`

#### `GUARDRAILS_RATE_LIMIT_REDIS_TIMEOUT_SECONDS`
- **Default:** `0.25` (250 milliseconds, minimum `0.01`)
- **Description:** Connect and command timeout. Redis operations run in worker threads via `anyio.to_thread` to prevent blocking the async event loop.

#### `GUARDRAILS_RATE_LIMIT_FAIL_CLOSED`
- **Default:** `false`
- **Behavior:**
  - `false` (Fail Open): If Redis is down, requests are allowed through with a warning log.
  - `true` (Fail Closed): If Redis is down, requests return `HTTP 429 Too Many Requests`.

---

### 5. Streamlit UI Access Gate

The Streamlit UI holds the gateway API key and makes requests on behalf of whoever visits the web interface. To prevent unauthorized use, the UI implements an access gate (`evaluate_gate`):

| `GUARDRAILS_API_KEY` | `GUARDRAILS_UI_PASSWORD` | `GUARDRAILS_UI_ALLOW_ANONYMOUS` | UI Gate Decision | UI Behavior |
| :---: | :---: | :---: | :---: | :--- |
| Unset | *Any* | *Any* | `GATE_OPEN` | Unrestricted (API is unauthenticated). |
| Set | Set | *Any* | `GATE_LOGIN` | Displays password login screen. |
| Set | Unset | `true` | `GATE_OPEN_WARN` | Displays warning banner that access is anonymous. |
| Set | Unset | `false` | `GATE_LOCKED` | **Default:** Refuses service and displays locked error screen. |

---

## Configuration Template (`.env.example`)

A sanitized environment template is maintained at the repository root:

```ini
# Copy to .env and edit: cp .env.example .env
# .env is git-ignored. Never commit real secrets.

# REQUIRED in production. Generate with:
#   python -c "import secrets; print(secrets.token_urlsafe(32))"
GUARDRAILS_API_KEY=

# Interface the published ports bind to (127.0.0.1 for local, 0.0.0.0 behind reverse proxy)
GUARDRAILS_BIND_ADDRESS=127.0.0.1

# Streamlit UI password gate
GUARDRAILS_UI_PASSWORD=
GUARDRAILS_UI_ALLOW_ANONYMOUS=false

# Local development ONLY: let the API run with no authentication
GUARDRAILS_ALLOW_ANONYMOUS=false

# Reverse proxies whose X-Forwarded-For may be trusted (IPs or CIDR blocks)
GUARDRAILS_TRUSTED_PROXIES=
```
