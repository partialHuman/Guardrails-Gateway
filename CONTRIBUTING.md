# Contributing to SentraGuard Lite

Thank you for your interest in contributing to SentraGuard Lite / Guardrails Gateway! We welcome contributions from the community—including bug fixes, performance optimizations, detection rules, and documentation improvements.

To ensure stability, security, and developer velocity, please review this guide before submitting code.

---

## 1. Code of Conduct & Security First

SentraGuard Lite is a security gateway designed to protect LLM applications from prompt injection, data exfiltration, and sensitive data leakage. Consequently:
- **Security is paramount**: Changes must never weaken detection boundaries, bypass authentication, leak credentials, or suppress error logging dangerously.
- **Fail-safe defaults**: All new configuration options must fail closed and secure by default.
- **Responsible disclosure**: If you discover a security vulnerability, please do **not** file a public issue. Follow our [Security Policy](.github/SECURITY.md) to report it confidentially.

---

## 2. Development Setup

### Prerequisites
- **Python 3.11, 3.12, 3.13, or 3.14**
- **Git**
- Optional: **Docker & Docker Compose** (for containerized testing)

### Step-by-Step Environment Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/partialHuman/Guardrails-Gateway.git
   cd Guardrails-Gateway
   ```

2. **Create and activate a virtual environment**:
   ```bash
   # Linux / macOS
   python -m venv .venv
   source .venv/bin/activate

   # Windows (PowerShell)
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.api.txt -r requirements.ui.txt -r requirements.dev.txt
   ```

4. **Initialize local environment configuration**:
   ```bash
   cp .env.example .env
   ```
   *Note: Edit `.env` to provide a strong test key (e.g. `GUARDRAILS_API_KEY=dev-secret-key-12345`). `.env` is ignored by Git.*

5. **Verify setup by running the test suite**:
   ```bash
   pytest -m "not e2e" --cov=app --cov-fail-under=95
   ```

---

## 3. Code Style & Architecture Guidelines

- **PEP 8 Compliance**: Follow standard Python conventions. Keep line lengths readable (<= 100 characters recommended).
- **Type Annotations**: Use Python type hints (`typing`) across all function signatures and public class interfaces.
- **Minimal Dependencies**: The core gateway (`requirements.api.txt`) aims to be lightweight and fast. Avoid introducing heavy third-party packages unless absolutely necessary.
- **Separation of Concerns**:
  - `app/api/`: FastAPI route definitions, request validation, response serialization.
  - `app/core/analyzer.py`: Central orchestration engine coordinating detectors and policy evaluations.
  - `app/core/detectors.py`: Individual detection modules (PII, prompt injection, custom rules).
  - `app/core/policy.py`: Action mapping (`ALLOW`, `FLAG`, `BLOCK`, `REDACT`), scan budget limits, and risk thresholds.
  - `app/core/rate_limiter.py`: Sliding window and token-bucket algorithms with CIDR IP parsing.
  - `ui/`: Streamlit dashboard and UI helpers.
- **Error Handling Hygiene**:
  - Never allow unhandled exceptions to return Python tracebacks or internal file paths to API clients.
  - Wrap internal errors in standard HTTP exceptions or use `app/main.py` exception handlers.

---

## 4. Testing & Quality Requirements

All code contributions must meet strict quality gates before being merged:

1. **Test Coverage Threshold**:
   - The test suite enforces **>= 95% line coverage** on `app/`. Pull requests that drop test coverage will fail CI.
2. **State Isolation**:
   - Tests that modify global state (such as the rate limiter singleton or environment variables) must use fixtures to restore state cleanly (see `tests/conftest.py`).
3. **Browser E2E Tests**:
   - Browser UI tests are marked with `@pytest.mark.e2e`. They require Playwright (`playwright install chromium`). In routine unit testing, use `-m "not e2e"` to skip browser automation.
4. **Security Auditing**:
   - Code must pass Bandit SAST (`bandit -r app cli.py -ll`) and dependency audits (`pip-audit`).

---

## 5. Git & Commit Guidelines

### Branch Naming Conventions
- `feat/<feature-name>`: New feature or capability.
- `fix/<bug-description>`: Bug or vulnerability fix.
- `docs/<topic>`: Documentation updates.
- `test/<scope>`: Test suite additions or enhancements.
- `hardening/<scope>`: Security or infrastructure hardening.

### Conventional Commit Messages
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short description in present tense>

[optional body providing technical context and rationale]

[optional footer(s) referencing issue numbers]
```

**Common types:**
- `feat`: A new user-facing feature.
- `fix`: A bug fix or security patch.
- `docs`: Documentation only changes.
- `test`: Adding missing tests or correcting existing tests.
- `refactor`: A code change that neither fixes a bug nor adds a feature.
- `chore`: Maintenance tasks, dependency updates, CI/CD tweaks.

*Example:*
```
fix(analyzer): enforce scan budget when processing nested prompts

Prevents memory exhaustion on deeply nested input arrays by halting
downstream detectors once MAX_FINDINGS_PER_REQUEST is reached.
```

---

## 6. Submitting a Pull Request

1. Push your branch to your fork.
2. Open a Pull Request targeting `main`.
3. Fill out the PR template with:
   - Summary of changes and architectural motivation.
   - Proof of test execution (unit tests, coverage, security scans).
   - Any deployment or configuration implications.
4. Ensure all GitHub Actions CI checks pass (Unit & Coverage, CodeQL, Bandit, pip-audit, TruffleHog).
5. Address maintainer feedback promptly.
