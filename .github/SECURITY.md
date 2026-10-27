# Security Policy

SentraGuard Lite / Guardrails Gateway enforces multi-layered defense-in-depth across API request validation, detection pipelines, container runtimes, and CI/CD supply chains. This document outlines our vulnerability disclosure process, response SLA, and v1.2 architectural security model.

---

## Supported Versions

Security updates and patches are actively maintained for the latest release on the default branch:

| Version | Supported          | Security Notes |
|---------|--------------------|----------------|
| `main` (v1.2.x) | :white_check_mark: | Active security updates, automated audits, and patch releases. |
| `< 1.2.0` | :x:                | Legacy versions. Users are strongly advised to upgrade to v1.2. |

---

## Reporting a Vulnerability

We practice **Coordinated Vulnerability Disclosure (CVD)**. If you discover a security vulnerability or potential exposure in SentraGuard Lite / Guardrails Gateway, please do **not** open a public GitHub issue, discussion, or pull request.

Instead, report it responsibly via one of the following channels:

1. **GitHub Private Vulnerability Reporting (Preferred)**:
   - Navigate to the repository's [Security Advisories tab](https://github.com/partialHuman/Guardrails-Gateway/security/advisories).
   - Click the **"Report a vulnerability"** button to open a confidential advisory draft directly with maintainers.
2. **Direct Security Contact**:
   - If GitHub Private Vulnerability Reporting is unavailable, contact the project maintainers via encrypted email or repository security contacts specified in maintainer profiles.

### What to Include

To facilitate rapid triage and reproduction, please provide:
- A detailed description of the vulnerability, including attack vectors and potential blast radius.
- Step-by-step reproduction instructions or a minimal, non-destructive proof-of-concept (PoC).
- Affected endpoints, configuration flags, or components (e.g., `/analyze`, rate limiter, regex engines).
- Environment details (Python runtime, Docker deployment topology, reverse proxy setup).
- Any proposed remediation, patch, or mitigation strategy.

### Vulnerability Response SLA

Our maintainers adhere to strict response timelines:

| Stage | Target Timeline | Details |
|---|---|---|
| **Initial Acknowledgement** | Within **24 hours** | Receipt confirmation and assignment of primary triage engineer. |
| **Triage & Reproduction** | Within **48 hours** | Vulnerability validation, severity classification, and CVE assignment if applicable. |
| **Remediation & Patch** | See Severity SLA below | Implementation, automated verification, and advisory release. |
| **Coordinated Disclosure** | 90 days or by mutual agreement | Public disclosure following patch release and downstream user migration window. |

---

## Severity Classification & Remediation Targets

Vulnerabilities are evaluated against the Common Vulnerability Scoring System (CVSS v3.1) and categorized under the following operational SLAs:

| Severity | Definition & Examples | Remediation Target SLA |
|---|---|---|
| **Critical** | Remote Code Execution (RCE), unauthenticated arbitrary policy overwrite, live credential exfiltration, full denial of service across all tenants, container escape vulnerabilities. | **24 hours** |
| **High** | Detection engine bypass under realistic inputs, authentication/token validation bypass, unbounded memory exhaustion (OOM crashes) via malicious payloads, rate-limiter bypass across untrusted proxies. | **72 hours** |
| **Medium** | ReDoS in non-critical regex patterns, microsecond timing side-channels in token comparison, client identity spoofing with misconfigured reverse proxies, excessive debug log exposure. | **7 days** |
| **Low / Informational** | Informative error responses without credential leaks, documentation inaccuracies, non-exploitable edge-case anomalies, missing non-critical HTTP defense headers. | **14 days** |

---

## SentraGuard Lite v1.2 Security Architecture

SentraGuard Lite v1.2 incorporates enterprise-grade hardening across five key layers:

### 1. Fail-Closed Scan Budget & ReDoS Defenses
- **Defensive Scan Budgets**: To prevent algorithmic complexity attacks and denial-of-service via massive nested or repetitious inputs, detection pipelines enforce strict scan budgets (`MAX_FINDINGS_PER_REQUEST = 20_000`).
- **Fail-Closed Guarantee**: When a scan budget or iteration bound is exceeded, the analyzer halts downstream rule processing, flags the prompt with `[SCAN_BUDGET_EXCEEDED_PROMPT_NOT_PROCESSED]`, attaches the `scan_limit_exceeded` audit rule, and executes the configured fail-closed policy (`BLOCK` or `FLAG`).
- **ReDoS Mitigation**: Regular expressions for PII detection, credential scanning, and pattern matching are audited against catastrophic backtracking. Complex regex scans enforce linear iteration caps and safe matching bounds.

### 2. Constant-Time Authentication & Key Isolation
- **Timing-Attack Resistance**: All API key validations utilize `hmac.compare_digest` to prevent timing side-channel attacks against secret credentials.
- **Fail-Fast Startup Validation**: The gateway validates that `GUARDRAILS_API_KEY` (or UI authentication credentials) is configured and non-empty on startup. In production mode, weak defaults or empty credentials immediately abort startup with a descriptive `ConfigError`.
- **Credential Storage Hygiene**: In-memory token representations are isolated, never persisted in temporary caches, and excluded from application-level telemetry or exceptions.

### 3. Tiered & Identity-Aware Rate Limiting
- **Dual-Tier Enforcement**: Requests are metered via token bucket algorithms supporting separate throughput quotas for authenticated API tokens and unauthenticated client IPs.
- **Identity Resolution**: Client IP extraction strictly obeys `GUARDRAILS_TRUSTED_PROXIES`. `X-Forwarded-For` headers are only evaluated when the connecting peer matches a configured CIDR or IP mask, preventing spoofed IP rate-limit evasion.
- **Fail-Safe Storage Backends**: Supports local in-memory token buckets with sliding-window expiry as well as distributed Redis backends with automatic connection recovery and bounded memory usage.
- **Standardized Headers**: Rate-limited responses issue HTTP `429 Too Many Requests` accompanied by `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining` headers.

### 4. Container Runtime Hardening & Sandboxing
- **Unprivileged Execution**: Container images run under a dedicated non-root user (`USER appuser`, UID/GID `10001:10001`). Root execution is explicitly prohibited.
- **Read-Only Root Filesystem**: Production containers run with `read_only: true`. The container filesystem is immutable; writable areas are restricted to explicit in-memory `tmpfs` mounts (`/tmp`, `/run`) with `noexec`, `nosuid`, and `nodev` mount flags.
- **Capability Dropping**: All Linux kernel capabilities are dropped (`cap_drop: [ALL]`).
- **Privilege Escalation Prevention**: Containers run with `no-new-privileges: true`, preventing setuid/setgid binaries from escalating privileges.
- **Resource Constraints**: Default configurations enforce strict cgroup limits (CPU quotas, 512MB RAM bounds, PID limits between 128 and 256) to prevent container resource exhaustion.
- **Loopback Binding by Default**: API and UI services bind to loopback (`127.0.0.1`) by default, requiring intentional administrator action to expose ports externally.

### 5. AST Traceback Suppression & UI Hygiene
- **Zero Internal Leakage**: The API global exception handler catches all unhandled exceptions, logs the full stack trace internally with an associated correlation ID (`X-Request-ID`), and returns an opaque JSON response (`Internal server error`) without revealing Python tracebacks, stack frames, or internal file paths.
- **DOM & Session Hygiene**: The Streamlit administration UI redacts credentials in session state, masks secrets in form fields (`type="password"`), and strips sensitive tokens from rendered DOM elements.

### 6. Defense-in-Depth HTTP Headers
Every HTTP response returned by SentraGuard Lite (including 4xx and 5xx error states) includes hardened security headers:
- `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (when running under TLS)

---

## Automated Security Architecture in CI/CD

Our GitHub Actions workflows enforce four layers of automated security testing on every pull request and merge to `main`:

### 1. Static Application Security Testing (SAST)
- **Bandit** (`.github/workflows/security.yml`): Analyzes `app/`, `ui/`, and `cli.py` for Python AST-level security flaws, hardcoded credentials, insecure file handling, and dangerous builtins with severity filtering (`bandit -r app cli.py -ll`).
- **GitHub CodeQL** (`.github/workflows/codeql.yml`): Performs interprocedural semantic data-flow and taint-tracking analysis using the `security-extended` query suite to detect injection vulnerabilities, path traversals, insecure deserialization, and ReDoS.

### 2. Dependency Vulnerability Auditing
- **pip-audit** (`.github/workflows/security.yml`): Audits all production and development requirements (`requirements.api.txt`, `requirements.ui.txt`, `requirements.dev.txt`, `requirements.redis.txt`) against the Open Source Vulnerabilities (OSV) database and GitHub Advisory Database with zero-vulnerability tolerance.

### 3. Secret Detection & Prevention
- **TruffleHog** (`.github/workflows/security.yml`): Deep-scans full git commit history (`fetch-depth: 0`) and PR diffs with `--only-verified` to prevent active credentials, API keys, or private tokens from entering the repository.

### 4. Supply Chain Security & Least Privilege
- **Pinned Actions**: Third-party GitHub Actions are pinned to full immutable 40-character commit SHAs.
- **Restricted Permissions**: Workflow tokens use least-privilege permissions (`contents: read` for tests and audits; `security-events: write` scoped exclusively to CodeQL SARIF uploads).
- **Automated Dependency Updates**: Dependabot monitors GitHub Actions, pip dependencies, and Docker base images on scheduled cadences.

---

## False Positive & Exemption Policy

1. **Dependency Vulnerability Exceptions**:
   - If an upstream vulnerability is identified in an optional non-production dependency with no immediate upstream fix, maintainers must document the vulnerability, assess the attack surface, and define an isolated mitigation or deprecation schedule.
2. **Synthetic Test Fixtures**:
   - Automated tests must generate credentials dynamically in memory (e.g., `secrets.token_hex()`) or use synthetic dummy strings conforming to `sentraguard-test-secret-*`. Real or production credentials are strictly prohibited in the codebase and test fixtures.
3. **Static Analysis Suppressions**:
   - Suppressions (`# nosec`) in application source code require maintainer sign-off accompanied by detailed code comments explaining why the pattern is safe and verified by automated tests.
