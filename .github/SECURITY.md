# Security Policy

## Supported Versions

SentraGuard Lite / Guardrails Gateway maintains security updates for the latest release on the default branch:

| Version | Supported          | Security Notes |
|---------|--------------------|----------------|
| `main`  | :white_check_mark: | Active security updates and patch releases. |
| Legacy  | :x:                | Older tags/commits are not actively backported. |

---

## Reporting a Vulnerability

We practice Coordinated Vulnerability Disclosure (CVD). If you discover a potential security vulnerability in SentraGuard Lite / Guardrails Gateway, please do **not** open a public GitHub issue.

Instead, report it through one of the following channels:
1. **GitHub Private Vulnerability Reporting**: Use the **Report a vulnerability** button under the [Security Advisories tab](https://github.com/partialHuman/Guardrails-Gateway/security/advisories).
2. **Security Contact**: Contact repository maintainers directly via repository security contacts.

Please include:
- A clear description of the vulnerability and attack vector.
- Steps to reproduce or proof-of-concept (PoC) payload.
- Potential impact and affected endpoints or components.
- Any suggested remediations or mitigations.

### Response Time & SLA
- **Initial Acknowledgement**: Within 24 hours.
- **Triage & Severity Confirmation**: Within 48 hours.
- **Remediation & Patch Target**: Based on Severity SLA (detailed below).

---

## Severity Classification & Remediation Targets

| Severity | Definition / Examples | Target SLA |
|----------|-----------------------|------------|
| **Critical** | Remote code execution, unauthenticated arbitrary policy overwrite, live credential leakage, or full denial of service affecting all tenants. | **24 hours** |
| **High** | Injection detector bypass under realistic conditions, authentication bypass, unhandled memory exhaustion or stream hang via crafted payloads. | **72 hours** |
| **Medium** | ReDoS in non-critical regex, timing side-channels in secret verification, rate-limiter bypass behind untrusted proxies. | **7 days** |
| **Low / Informational** | Verbose error telemetry without secret leakage, documentation omissions, missing non-critical HTTP response headers. | **14 days** |

---

## Automated Security Architecture in CI/CD

The repository enforces multiple automated security checks across all pull requests and pushes to `main`:

### 1. Static Application Security Testing (SAST)
- **Bandit** (`.github/workflows/security.yml`): Analyzes `app/` and `cli.py` for Python AST-level security flaws, hardcoded credentials, and insecure function invocations with medium/high severity filtering (`-ll`).
- **GitHub CodeQL** (`.github/workflows/codeql.yml`): Performs interprocedural semantic data-flow and taint-tracking analysis using the `security-extended` query suite to catch injection vulnerabilities, path traversals, and algorithmic ReDoS. Runs on PRs and weekly schedule.

### 2. Dependency Vulnerability Auditing
- **pip-audit** (`.github/workflows/security.yml`): Audits production API dependencies (`requirements.api.txt`) and dev/test tooling (`requirements.dev.txt`) against the Open Source Vulnerabilities (OSV) database and GitHub Advisory Database.

### 3. Secret Detection
- **TruffleHog** (`.github/workflows/security.yml`): Inspects commits and PR diffs with `--only-verified` to detect active cloud keys, tokens, or credentials committed accidentally.
- Full Git history scanning (`fetch-depth: 0`) ensures historical leaks cannot enter the repository.

### 4. Supply-Chain Hardening & Workflow Security
- All third-party GitHub Actions are pinned to immutable commit SHAs with semantic tag comments.
- Workflows operate under least-privilege permissions (`contents: read` for tests and audits; `security-events: write` scoped strictly to CodeQL SARIF upload).
- Fork pull requests execute in a read-only environment without access to repository secrets or write tokens.

---

## False Positive & Exemption Policy

1. **Dependency Vulnerability Exceptions**:
   - If a vulnerability exists in an optional, non-production package (e.g., local demo UI dependencies) with no available upstream fix, the maintainers must document the issue, evaluate the isolation boundary, and specify remediation milestones.
2. **Test Fixture Placeholders**:
   - Secrets used strictly in automated test suites must follow standard dummy naming conventions (e.g., `DUMMY_SECRET = "sentraguard-test-secret-..."`) and must never resemble valid provider credentials.
3. **Static Analysis Suppressions**:
   - Suppressions (`# nosec`) in application code require code review approval with documented rationale explaining why the flagged pattern is safe.
