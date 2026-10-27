# Changelog

All notable changes to SentraGuard Lite / Guardrails Gateway are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 1.2.0

### Security
- **Constant-Time Authentication**: Replaced direct string comparisons in API key verification with `hmac.compare_digest` to eliminate timing side-channel attacks.
- **Fail-Fast Startup Validation**: The API now refuses to start if `GUARDRAILS_API_KEY` is unset or empty unless anonymous operation is explicitly allowed via `GUARDRAILS_ALLOW_ANONYMOUS=true`.
- **UI Access Gating**: The Streamlit administration dashboard is locked by default unless `GUARDRAILS_UI_PASSWORD` is configured or `GUARDRAILS_UI_ALLOW_ANONYMOUS=true` is set. Form fields mask credentials and redact secrets from rendered DOM session states.
- **Fail-Closed Scan Budget**: Introduced `ScanBudget` engine (`MAX_FINDINGS_PER_REQUEST = 20_000`). If scanning budget or recursion bounds are exceeded, the analyzer halts downstream detectors, replaces prompt text with `[SCAN_BUDGET_EXCEEDED_PROMPT_NOT_PROCESSED]`, and triggers the `scan_limit_exceeded` audit rule under fail-closed semantics.
- **ReDoS Defenses**: Bounded sliding window search and capped iteration limits on PII and prompt injection regular expressions.
- **AST Traceback Suppression**: Global exception handlers intercept unhandled server errors, log tracebacks internally with correlation IDs, and return opaque `500 Internal server error` responses without leaking internal file paths or stack frames.
- **Defense-in-Depth HTTP Headers**: Injected hardened security headers (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`) on all responses, including 4xx and 5xx errors.
- **Tiered & Identity-Aware Rate Limiting**: Token bucket algorithm supporting independent limits for authenticated tokens, unauthenticated IPs, and a dedicated auth-failure bucket (`GUARDRAILS_AUTH_FAILURE_LIMIT_REQUESTS = 10`) to mitigate brute-force attempts.
- **Trusted Proxy CIDR / IPv6 Matching**: Strict validation of `GUARDRAILS_TRUSTED_PROXIES` before parsing `X-Forwarded-For`, preventing client IP spoofing behind reverse proxies.
- **Container Sandboxing**: Docker Compose and Dockerfiles now run as an unprivileged non-root user (`USER appuser`, UID/GID `10001:10001`), with read-only root filesystems (`read_only: true`), `cap_drop: [ALL]`, `no-new-privileges: true`, in-memory `tmpfs` mounts, and cgroup quotas (512MB RAM, 1.0 CPU, 128-256 PIDs).
- **CI/CD Supply Chain Hardening**: Pinned all third-party GitHub Actions to immutable 40-character commit SHAs, enforced least-privilege token permissions (`contents: read`), and added automated secret scanning (TruffleHog) and dependency auditing (pip-audit).

### Added
- **Request ID Tracking**: Generated and propagated `X-Request-ID` correlation identifiers across request pipelines and structured logs.
- **Request Body Size Limits**: Enforced maximum body payloads (`GUARDRAILS_MAX_REQUEST_BODY_BYTES`, default 1MB) returning HTTP 413.
- **Identifier Validation**: Strict regex bounds on `app_id` and `user_id` parameters (alphanumeric, underscore, hyphen, max length 64).
- **Comprehensive Documentation Suite**:
  - Architectural overview, threat model, and setup guides in `README.md`.
  - Exhaustive 22-variable configuration reference in `docs/configuration.md`.
  - Complete REST API specification and curl examples in `docs/api.md`.
  - Security disclosure process and CVSS-based response SLA in `.github/SECURITY.md`.
  - Enterprise deployment topologies, NGINX/Caddy/Traefik reverse proxy configs, and update/rollback runbooks in `docs/deployment.md`.
  - Developer contribution guidelines and commit standards in `CONTRIBUTING.md`.
  - Testing architecture, 95% coverage enforcement, and Playwright E2E automation in `docs/testing.md`.
  - Operational diagnostics and failure troubleshooting runbook in `docs/troubleshooting.md`.
  - Pre-release verification checklist in `docs/release-checklist.md`.
- **Multi-Version Python CI Matrix**: Automated testing across Python 3.11, 3.12, 3.13, and 3.14.
- **Automated Dependency Management**: Configured Dependabot for GitHub Actions, Python dependencies, and Docker base images.

### Changed
- **Default Port Bindings**: Container port mappings now bind exclusively to loopback (`127.0.0.1`) by default via `GUARDRAILS_BIND_ADDRESS`.
- **E2E Test Separation**: Pytest test suites now separate fast unit tests (`-m "not e2e"`) from dedicated browser automation tests (`-m e2e`).
- **Dynamic CI Test Credentials**: Eliminated static dummy tokens in CI workflows in favor of in-memory dynamic token generation.

### Fixed
- **Rate Limiter Concurrency & Isolation**: Fixed test state leakage across test modules via automatic rate limiter reset fixtures in `tests/conftest.py`.
- **Playwright Import Collection in CI**: Resolved test collection errors on minimal CI environments by gracefully handling missing browser dependencies when running unit tests.
- **Client Identity Behind Reverse Proxies**: Resolved incorrect IP evaluation by adding subnet-aware CIDR parser for trusted reverse proxies.

---

## 1.1.0

### Fixed
- **Denial of service in the email regex.** The original pattern rescanned every
  run of word characters from each start position (quadratic): a single
  50 000-character string such as `aaaa...` or a long run of digits stalled a
  worker for ~15 s. Emails are now found by locating each `@` and expanding a
  bounded window (linear time; worst measured input is ~90 ms). Covered by a
  timing regression test.
- **PII was detected but not redacted when it was the only finding.** An email
  alone scores below the transform threshold, and the analyzer returned the
  original text for `allow`. PII is now always redacted, and any modification
  forces at least `transform`.
- **Docker UI called `/analyze/analyze`.** `docker-compose.yml` set `API_URL`
  to the full endpoint while the UI appended `/analyze` again. Compose now sets
  the base URL, and the UI/CLI accept either form.
- **`_init_.py` -> `__init__.py`** in `app/`, `app/core/`, `app/utils/` and
  `tests/` (imports only worked through implicit namespace packages).
- **Phone detection** no longer redacts order ids, ISBNs, timestamps or Aadhaar
  numbers, no longer leaves digits behind when redacting cards, and now finds
  `(415) 555-2671` style numbers.
- **Injection phrases in context documents** (e.g. a planted "ignore previous
  instructions") were never detected, because documents only ran the RAG
  patterns. Documents now run both rule sets.
- Detection and sanitization now use the same rules (previously the sanitizer
  rewrote `system:` in ordinary prompts that the detector had not flagged).
- README: stale test count, Docker screenshot rendering as a heading, wrong
  `cd` path, Windows-only line continuation in a bash block, name mix-up.

### Added
- Normalisation before matching: NFKC, invisible/format characters (incl.
  Unicode tag block), Cyrillic/Greek look-alikes, leetspeak for injection
  phrases, flexible whitespace including newlines.
- Regex rules with synonyms, plural/singular and negation handling
  (`don't forget your instructions` is not flagged).
- Base64-encoded injection payloads (one level).
- Payment-card (Luhn + issuer prefix) and Aadhaar (Verhoeff) detection.
- Per-rule severities; score = highest severity per tag + bonus per distinct
  rule (capped), so repeating a phrase no longer matters.
- Context-document quarantine for high-severity injections;
  `quarantined_doc_ids` in the response.
- `source` and `rule` on every reason; `/policy` now lists all rules.
- Input limits (prompt length, number/size of documents, unique document ids).
- JSON log lines including `app_id`, `user_id`, matched rule ids.
- `requirements.dev.txt`, `.dockerignore`, extended `.gitignore`.
- Much larger test suite (parametrised bypass / false-positive tables).

### Changed
- `requirements.api.txt` now contains runtime dependencies only (it was a full
  `pip freeze` including Streamlit, pandas, pytest...). The UI requirements are
  pinned. Docker images copy only what they need.
- Response/behaviour changes to be aware of:
  - `sanitized_context_docs` no longer contains quarantined documents.
  - A request whose only finding is PII now returns `transform` (was `allow`).
  - `reasons[]` gained `source` and `rule`; one reason per rule per source,
    with "(+N more)" for repeats.
  - `RAG_INJECTION_SCORE` / `PII_SCORE` / `PROMPT_INJECTION_SCORE` constants
    were replaced by per-rule severities in `app/core/policy.py`.
  - `detect_*` functions return `Finding` objects (not `Reason` models).
- Removed unused `DEFAULT_HOST` / `DEFAULT_PORT` from `config.py`.
