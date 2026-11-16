# Roadmap — SentraGuard Lite v1.3.0

| | |
|---|---|
| **Status** | **Proposed plan — nothing here is implemented.** For maintainer review and approval |
| **Date** | 2026-11-03 |
| **Baseline** | [v1.2.0](release-baseline-v1.2.0.md) (stable). v1.2.x maintenance continues in parallel under the [maintenance policy](release-and-maintenance-policy.md) |
| **Evidence** | [Post-release audit](post-release-audit-v1.2.0.md) — finding IDs `BASE-xxx` and discrepancies `D-xx` refer to it |

## Table of contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [Category assessment](#2-category-assessment)
3. [Change matrix](#3-change-matrix)
4. [Change details](#4-change-details)
5. [Scope definition](#5-scope-definition)
6. [Milestones](#6-milestones)
7. [Quality gates, Definition of Done and acceptance](#7-quality-gates-definition-of-done-and-acceptance)
8. [Compatibility and migration](#8-compatibility-and-migration)
9. [Why v1.3.0 and not v2.0.0](#9-why-v130-and-not-v200)
10. [Risks](#10-risks)

Effort estimates are **ranges in person-days of focused work** by one maintainer, excluding review wait time. They carry real uncertainty; no calendar dates are proposed.

---

## 1. Goals and non-goals

**Goals** — each is tied to evidence:

1. **Close the remaining resource-control gap** and make limits configurable and documented (BASE-002, BASE-005).
2. **Make the documentation trustworthy by construction**: claims about behavior are checked by tests (24 discrepancies found, §8 of the audit).
3. **Make the service observable and reproducible to operate**: structured logs, readiness, rotation, container verification in CI (BASE-006, 011, 012, 014).
4. **Make the build reproducible and supply-chain-controlled**: lockfiles, pinned tooling, SBOM (BASE-009, 010, 021).
5. **Measure the product's core quality — detection** — instead of asserting it (audit §10, BASE-001).

**Non-goals for v1.3.0:** machine-learning detection, a multi-tenant policy store or any persistence, SSO/OIDC, a UI rewrite, hosted/SaaS features, Kubernetes packaging, any breaking contract change (see §9).

---

## 2. Category assessment

| Category | Applicable? | Basis |
|---|---|---|
| Architecture / modularity | **Partly** | The core is already separated from the web layer. The actual gaps are configuration (scattered, doc-drifting) and the length of `app/main.py`. **Not proposed:** microservices, a plugin framework, or a rewrite |
| API and UI boundaries / versioning | **Light** | The contract is small. Proposed: contract tests and an optional `/v1` alias (V13-011) |
| Persistence / database / migrations | **Not applicable** | The service is stateless by design [V]. No persistence is proposed |
| Background processing | **Not applicable** | No jobs or queues. Only V13-015 (deferred) would add worker processes, solely to bound CPU |
| Authentication / authorization | **Yes** | One shared key, no rotation (V13-006); UI gate (V13-007) |
| Audit logging | **Yes** | Folded into V13-004 (structured logging with request/key attribution) |
| Rate limiting / abuse control | **Mostly done in v1.2.0** | Remaining: Redis verification (V13-014) |
| Configuration / secure defaults | **Yes** | V13-001, V13-002 |
| Dependency and supply chain | **Yes** | V13-008 |
| Threat model and regression testing | **Yes** | A short threat model is a V13-003 deliverable; regression tests exist and are extended by V13-010 |
| Health / readiness, graceful shutdown | **Yes** | V13-013 |
| Retry and timeout policies | **Limited** | Redis timeouts exist; the UI→API call has a timeout; no other outbound calls exist |
| Metrics / observability | **Yes** | V13-004 (logs); a metrics endpoint is **optional**, deferred until a user need is stated |
| Performance and scalability | **Measure first** | V13-012. No caching or distributed design is proposed without data. Known baseline: ≈ 1.0–1.3 s CPU for a maximum-size ordinary request; 7.1 s for the normalization-amplification case |
| UX / accessibility | **Limited** | The UI is an operator console, not the product. No accessibility work is proposed without a stated requirement |
| Developer experience | **Yes** | Local `.env` loading (V13-002), lockfile workflow (V13-008), docs generated from settings |
| Testing and CI quality | **Yes** | V13-003, V13-009, V13-010, V13-012 |

---

## 3. Change matrix

Priority: **P0** blocker for the release · **P1** high value · **P2** valuable · **P3** deferred. Complexity: Small / Medium / Large / Very Large.

| ID | Name | Fixes | Priority | Complexity | Effort (person-days) | Breaking risk | Tier |
|---|---|---|---|---|---|---|---|
| **V13-001** | Scan-limit governance | BASE-002, BASE-005 (part) | **P0** | Medium | 3–6 | Low | **Must** |
| **V13-002** | Typed configuration, unknown-variable detection, generated reference | BASE-005, D-22, D-23 | P1 | Medium | 4–8 | Low | **Must** |
| **V13-003** | Documentation tested against code; threat model | BASE-003, 004, 006 | P1 | Small–Medium | 2–5 | None | **Must** |
| **V13-004** | Structured logging, access log, tracebacks | BASE-014, D-17, D-23 | P1 | Medium | 3–6 | Low | **Must** |
| **V13-008** | Reproducible builds and supply-chain controls | BASE-009, 010, 021 | P1 | Large | 5–10 | None for users | **Must** (lock + pins); SBOM/provenance **Should** |
| **V13-009** | Container verification in CI | BASE-011 | P1 | Medium | 3–6 | None | **Must** |
| **V13-010** | Detection evaluation harness and dataset | audit §10, BASE-001 | P1 | Large | 8–15 | Medium (detector behavior) | **Must** (harness); improvements **Should** |
| **V13-005** | Security-header policy | BASE-003 | P2 | Small | 1–3 | Low | Should |
| **V13-012** | Performance baseline and load test | L1, BASE-002 | P2 | Medium | 3–5 | None | Should |
| **V13-013** | Operability: readiness, shutdown, log rotation | BASE-006, 012 | P2 | Small–Medium | 2–4 | Low | Should |
| **V13-006** | API-key lifecycle (multiple keys, rotation) | L5 | P1 | Large | 8–15 | Low | Should — **first to defer** |
| **V13-007** | UI gate hardening | BASE-007 | P2 | Small–Medium | 2–4 | Low | Optional |
| **V13-011** | Contract tests and optional `/v1` alias | compatibility | P2 | Medium | 3–6 | None | Optional |
| **V13-014** | Redis backend verification | BASE-015 | P2 | Medium | 3–5 | None | Optional |
| **V13-015** | Process-isolated scanning with a hard timeout | L1 | P3 | Very Large | 10–20 | Medium | **Deferred** |

**Scope check.** *Must* totals **28–56** person-days, *Should* adds **14–27**. For a single maintainer this is a large release. Recommended handling: ship **Must + V13-013 + V13-005** as v1.3.0, and plan V13-006 as the lead item of the following minor release (v1.4.0). This is a recommendation for the maintainer to decide.

---

## 4. Change details

Each change lists the evidence for the current limitation, the proposal, and what proves it done. "Compat" is the backward-compatibility plan; the compatibility rules are in the [baseline §8](release-baseline-v1.2.0.md#8-compatibility-contract-for-the-v12x-line).

### V13-001 — Scan-limit governance

| | |
|---|---|
| **Current limitation** | Length limits count input characters while scanning runs on NFKC-normalized text (up to 18× longer). 878 KiB took 7.1 s/+58 MB and was allowed [X] (BASE-002). `MAX_FINDINGS_PER_REQUEST` is a constant, yet documented as a variable (D-22) |
| **Proposed behavior** | A configurable cap on total post-normalization characters per request (fail closed: `block`, offending documents quarantined, same synthetic finding mechanism as the finding budget); `GUARDRAILS_MAX_FINDINGS_PER_REQUEST` becomes a real setting; both published in `GET /policy`. Defaults equal the v1.2.1 values |
| **Benefit** | Bounded CPU/memory amplification; operators can tune limits knowingly |
| **Security** | Removes a resource-exhaustion path; the new rejection must not trigger on realistic input |
| **Dependencies** | v1.2.1 introduces the fixed cap (A-02); this item makes it configurable. Soft dependency on V13-002 |
| **Compat** | New variables only; defaults preserve behavior; new `/policy` keys are additive |
| **Required tests** | `U+FDFA`/other expanding characters at, below and above the cap; the cap with multiple documents (quarantine, unscanned later documents); empty input; cap of 0/small; env parsing tests; `/policy` reflects settings |
| **Acceptance** | The 6 × 50k `U+FDFA` case is blocked in < 1 s with < 20 MB growth; ordinary maximum-size requests unchanged; documentation matches `/policy` (V13-003 test) |
| **Risks / rollback** | Cap too low rejects legitimate text → default chosen above the largest plain-ASCII request; roll back by raising the setting |

### V13-002 — Typed configuration, unknown-variable detection, generated reference

| | |
|---|---|
| **Current limitation** | Settings are module-level globals read at import; unknown `GUARDRAILS_*` names are silently ignored, so documented-but-nonexistent variables look like they work (D-22, D-23); `.env` is not loaded outside Compose (D-24) |
| **Proposed behavior** | A single typed settings object (the existing strict parsing preserved), a startup **warning** for unrecognized `GUARDRAILS_*` variables (opt-in failure via `GUARDRAILS_STRICT_ENV=true`), optional `.env` loading for local development only, and `docs/configuration.md` generated from the settings definitions |
| **Benefit** | Typos and stale docs become visible; one source of truth |
| **Security** | Typos in security settings no longer fail silently |
| **Dependencies** | None; V13-001 and V13-004 add settings through it |
| **Compat** | Warning (not error) by default; all existing names/defaults unchanged; the `app.config` module attributes remain importable |
| **Required tests** | Every setting round-trips; unknown variable warns / fails in strict mode; generated reference equals committed file; `.env` loading is off in containers |
| **Acceptance** | Zero documented variables unread by code and vice versa (checked in CI) |
| **Risks / rollback** | Refactor risk to the 18 existing settings → keep the current parsing tests unchanged as the safety net |

### V13-003 — Documentation tested against code; threat model

| | |
|---|---|
| **Current limitation** | 24 documented claims do not match the code (audit §8) because nothing tests prose |
| **Proposed behavior** | Tests that assert: the set of security headers listed in docs equals those sent; the placeholder text and health payload quoted in docs equal the code; the documented environment variables equal the settings; markdown links resolve; `API_VERSION` equals the newest changelog heading. A one-page threat model (assets, trust boundaries, abuse cases) in `docs/` |
| **Benefit** | Prevents recurrence; gives reviewers a security reference |
| **Security** | Removes the risk of false assurance from public claims |
| **Dependencies** | v1.2.1 corrects the existing discrepancies first |
| **Compat** | Documentation/tests only |
| **Required tests** | The tests themselves; a deliberate-mismatch check (documented once) proving they can fail |
| **Acceptance** | All discrepancy classes D-01…D-24 are covered by a failing-then-passing test |
| **Risks / rollback** | Brittle text matching → assert on structured values (header names, ids), not prose |

### V13-004 — Structured logging, access log, tracebacks

| | |
|---|---|
| **Current limitation** | No per-request access log; 500s log the exception type only while a traceback appears via Uvicorn re-raise; the documented JSON log schema and `GUARDRAILS_LOG_FORMAT` do not exist (BASE-014, D-17, D-23) |
| **Proposed behavior** | `GUARDRAILS_LOG_FORMAT=text\|json` (default `text`); one access-log event per request (request id, method, route, status, duration, client key, decision) and error events with the traceback at ERROR level, **never** request content; redaction tests |
| **Benefit** | Diagnosable incidents and a real audit trail |
| **Security** | Must not log prompts, documents or credentials; attacker-controlled values stay escaped |
| **Dependencies** | V13-002 for the setting |
| **Compat** | Default output format unchanged; log format is explicitly **not** part of the compatibility contract |
| **Required tests** | Field presence per event; no content/credential leakage (including under errors); JSON validity; traceback present at ERROR |
| **Acceptance** | An operator can trace a request from the `X-Request-ID` header to its log events |
| **Risks / rollback** | Log volume → document rotation (V13-013) |

### V13-005 — Security-header policy

| | |
|---|---|
| **Current limitation** | Docs promise CSP, Permissions-Policy and HSTS; the app sends four other headers (BASE-003) |
| **Proposed behavior** | Decide and document one policy: send `Permissions-Policy` and a restrictive `Content-Security-Policy` for API responses (excluding the interactive `/docs` and `/redoc` pages, which need scripts), and an opt-in `Strict-Transport-Security` (`GUARDRAILS_HSTS_MAX_AGE`, off by default, only meaningful behind TLS) |
| **Benefit** | Documentation matches behavior; defense-in-depth for the docs pages |
| **Security** | A wrong CSP breaks Swagger UI; HSTS misuse can lock clients out |
| **Compat** | Additive headers on JSON responses |
| **Required tests** | Header set per route class; `/docs` still loads; HSTS absent by default |
| **Acceptance** | V13-003's header test passes against the documented policy |
| **Risks / rollback** | Revert to the v1.2 header set via one constant |

### V13-006 — API-key lifecycle

| | |
|---|---|
| **Current limitation** | One shared static key: no rotation window, revocation, or attribution (L5) |
| **Proposed behavior** | Accept several named keys (id + key; optionally digests only), log the key **id** with each request, optional per-key quota; `GUARDRAILS_API_KEY` keeps working as a single key |
| **Benefit** | Rotation without downtime; per-client revocation; attribution |
| **Security** | Never log the key; store digests where possible; constant-time comparison across all candidates |
| **Dependencies** | V13-002, V13-004 |
| **Compat** | Single-key configuration unchanged |
| **Required tests** | Rotation overlap; revoked key rejected; timing-safe comparison; log attribution; failed-auth limiter unaffected |
| **Acceptance** | Rotate a key with zero failed requests in a scripted test |
| **Risks / rollback** | Touches the authentication path → keep the single-key path byte-for-byte equivalent and tested |

### V13-007 — UI gate hardening

| | |
|---|---|
| **Current limitation** | Wrong-password delay is per session only (BASE-007) |
| **Proposed behavior** | Process-wide failed-attempt limiter with lockout window; session expiry; documentation that production exposure requires an authenticating reverse proxy |
| **Compat** | UI behavior only |
| **Required tests** | Parallel-session guessing is throttled; helper-level unit tests; E2E case |
| **Acceptance** | N parallel sessions cannot exceed the configured attempt rate |

### V13-008 — Reproducible builds and supply-chain controls

| | |
|---|---|
| **Current limitation** | No lockfile or hashes; floating base image; unpinned CI tools; browsers downloaded at run time; no SBOM or provenance (BASE-009, 010, 021) |
| **Proposed behavior** | Hash-pinned lockfiles for API, UI and dev environments with a documented regeneration workflow; base images pinned by digest; Playwright, Bandit, pip-audit and pip pinned; `pip-audit` runs on the locked set; CycloneDX SBOM attached to releases; build provenance attestation if supported by the hosting plan |
| **Benefit** | The tested dependency set is the shipped set |
| **Security** | Reduces dependency-substitution risk |
| **Dependencies** | None; precedes V13-009's image build |
| **Compat** | Runtime behavior unchanged; contributors follow the lock workflow |
| **Required tests / checks** | CI installs with `--require-hashes`; a job fails when the lock is stale |
| **Acceptance** | Two builds of the same commit install identical package sets |
| **Risks / rollback** | Maintenance burden → Dependabot handles updates; fall back to unlocked install by reverting the CI step |

### V13-009 — Container verification in CI

| | |
|---|---|
| **Current limitation** | Container hardening is checked by reading files, never by running containers (BASE-011) |
| **Proposed behavior** | A CI job builds both images, starts the Compose stack and waits for health, asserts via `docker inspect` the non-root user, read-only root filesystem, dropped capabilities and limits, runs a short smoke test against `/health`, `/analyze` (with a generated key) and a rejected request, scans images for vulnerabilities, and tears everything down |
| **Benefit** | The shipped runtime posture is proven, not assumed |
| **Security** | Image scan adds OS-package visibility |
| **Dependencies** | V13-008 (pinned base) |
| **Required tests** | The job itself; failure injection once (documented) |
| **Acceptance** | Required status check on pull requests |

### V13-010 — Detection evaluation harness and dataset

| | |
|---|---|
| **Current limitation** | Detection quality is unmeasured. A small earlier probe caught 2 of 13 paraphrase/encoding attacks [H]; BASE-001 shows a bypass that tests did not guard |
| **Proposed behavior** | A versioned dataset of labelled attack and benign samples (including known bypass classes: oversized encodings, spaced letters, HTML entities, combining marks, paraphrases, non-English), a harness reporting precision/recall **per rule and per category**, a CI check that fails on regression against the committed baseline, and a summary in the docs. Rule improvements are driven by measured gaps |
| **Benefit** | The product's core promise becomes measurable |
| **Security** | The dataset contains attack strings only; no real PII |
| **Dependencies** | None (BASE-001's High-severity fix lands in v1.2.1) |
| **Compat** | The harness is additive. Each detector change is a recorded behavior change (minor release) |
| **Required tests** | Harness unit tests; deterministic ordering; baseline file format |
| **Acceptance** | Baseline recall and false-positive rate published; CI fails when either worsens beyond an agreed tolerance |
| **Risks / rollback** | Overfitting to the dataset → hold out a validation split |

### V13-011 — Contract tests and optional `/v1` alias

Snapshot test of the OpenAPI schema, a consistent error body shape (today `422` uses a list and other errors a string), and an optional `/v1/analyze` alias while `/analyze` remains. **Compat:** additive. **Acceptance:** schema snapshot changes require a deliberate update. **Effort 3–6 d, Optional.**

### V13-012 — Performance baseline and load test

| | |
|---|---|
| **Current limitation** | Costs are known only from ad-hoc probes: ≈ 1.0–1.3 s CPU for a maximum-size ordinary request; 7.1 s for the amplification case (BASE-002); no regression guard |
| **Proposed behavior** | A reproducible benchmark (typical, maximum-size, dense-match, expansion) with recorded results; a nightly job; targets set **after** measurement as "baseline + agreed margin" |
| **Dependencies** | V13-001 for the expansion case |
| **Acceptance** | Documented baseline; CI notifies on regression |
| **Risks** | Shared CI runners are noisy → compare ratios, not absolute times |

### V13-013 — Operability

Distinct `/livez` and `/readyz`; `--timeout-graceful-shutdown` in the image; Compose log rotation (`logging.options`); corrected upgrade/rollback runbooks; explicit single-container restart-gap guidance. (Log rotation and runbook corrections ship earlier in v1.2.1 — A-05, A-08.) **Compat:** new endpoints are additive; `/health` unchanged. **Effort 2–4 d, Should.**

### V13-014 — Redis backend verification

Integration tests against a real Redis service container in CI; a pinned `redis` version; an optional image build argument to install it; documented multi-replica semantics. **Acceptance:** the limiter behaves identically to the in-memory one across two API instances. **Effort 3–5 d, Optional.**

### V13-015 — Process-isolated scanning with a hard timeout *(deferred)*

Run scanning in a worker process that can be killed on timeout, bounding CPU regardless of regex behavior. **Why deferred:** Very Large effort, adds process management and failure modes, and V13-001 plus V13-012 may reduce the residual risk enough. **Revisit if** measurement after V13-001 still shows unacceptable worst-case CPU. It would change timeout/error behavior (a compatibility decision).

---

## 5. Scope definition

### 5.1 Must-have
V13-001, V13-002, V13-003, V13-004, V13-008 (lockfiles and pinning), V13-009, V13-010 (harness and baseline).

### 5.2 Should-have
V13-005, V13-012, V13-013, V13-008 (SBOM/provenance), V13-010 (detector improvements), and — only if capacity allows — V13-006.

### 5.3 Optional
V13-007, V13-011, V13-014.

### 5.4 Explicitly out of scope
- V13-015 (deferred) and any ML/model-based detection.
- Persistence, multi-tenancy, policy editing endpoints, SSO/OIDC, SaaS features.
- Kubernetes manifests or Helm charts (until requested).
- **Any breaking change**: removing or renaming variables or endpoints, changing response fields or decision values, or flipping `GUARDRAILS_ALLOW_ANONYMOUS`'s code default (→ v2.0.0, §9).

### 5.5 Release-blocking defects (v1.3.0)
Any open Critical/High finding; an authentication or rate-limit bypass; a regression of the v1.2.0 compatibility contract not listed in the changelog; failing required CI checks; a container smoke test failure; a discrepancy found by the documentation tests.

---

## 6. Milestones

No dates are proposed. Durations depend on maintainer capacity.

| Milestone | Deliverables | Depends on | Acceptance criteria | Exit condition |
|---|---|---|---|---|
| **M0 — Requirements and baseline** | Maintainer decisions recorded (scope tier, support policy); [audit](post-release-audit-v1.2.0.md) follow-ups A-13…A-15 verified; **v1.2.1 released** (A-01…A-10) | Audit | Provenance confirmed; CI/E2E results recorded; v1.2.1 tagged | Scope approved |
| **M1 — Design** | Short design notes for V13-001/002/004/008/009/010 (settings model, log schema, dataset format, lock workflow, CI job); threat model draft | M0 | Each design reviewed against the compatibility contract; open questions listed | Designs approved |
| **M2 — Core implementation** | V13-002 (settings), V13-001, V13-004, V13-005, V13-013 | M1 | Unit tests pass; coverage ≥ 95 %; no contract change | Features merged behind unchanged defaults |
| **M3 — Integration and migration** | V13-008 (locks, pins), V13-009 (container job), V13-003 (docs tests), generated configuration reference | M2 | CI green with locked install; container job required; docs tests fail on injected mismatch | CI pipeline stable for a full cycle |
| **M4 — Security and regression testing** | V13-010 harness + baseline; V13-012 benchmarks; security re-audit of the diff; E2E run | M3 | No open Critical/High; detection baseline recorded; perf baseline recorded | Audit sign-off |
| **M5 — Release candidate and deployment validation** | `v1.3.0-rc.1` tag *(proposal only)*; deployment smoke on a clean host; upgrade test from v1.2.x with a v1.2 `.env`; rollback rehearsal | M4 | Upgrade needs no configuration change; rollback succeeds | RC accepted |
| **M6 — Release and post-release monitoring** | `v1.3.0` per the [policy](release-and-maintenance-policy.md); post-release verification; v1.2.x lifecycle announcement | M5 | Checklist complete; tag/release verified | Release verified; follow-ups logged |

---

## 7. Quality gates, Definition of Done and acceptance

### 7.1 Quality gates (all required for v1.3.0)

1. Unit/integration suite green on every supported Python version in the CI matrix; **coverage ≥ 95 %** (the current gate; 100 % is not required and is not treated as evidence of correctness).
2. Playwright E2E green.
3. Bandit (covering `app/`, `ui/`, `cli.py`), `pip-audit` on **all** requirement sets, TruffleHog and CodeQL (v4) green.
4. Container job green (V13-009).
5. Documentation tests green (V13-003).
6. Detection baseline not worse than recorded (V13-010).
7. Benchmark within the agreed margin (V13-012).
8. No open Critical/High finding.

### 7.2 Definition of Done (per change)

Implemented; regression tests that fail without the change; docs and generated references updated; changelog entry in the right category; compatibility impact stated; security review of the diff; CI green.

### 7.3 Release acceptance

All *Must* items done; quality gates pass on the release commit; the release checklist is complete; upgrade from the latest v1.2.x verified with an unmodified v1.2 configuration.

---

## 8. Compatibility and migration

- Default behavior of v1.2.x configurations is preserved; every new setting has a default equal to the previous behavior.
- Responses gain no mandatory fields; new `/policy` keys are additive.
- Detector changes are behavior changes: each is listed in the changelog with the rule id and the dataset evidence.
- **Migration guide** (in the v1.3.0 changelog and docs): new settings, the unknown-variable warning, the lock workflow for contributors, the new CI checks.
- Rollback to the latest v1.2.x must work without configuration changes (verified in M5).

---

## 9. Why v1.3.0 and not v2.0.0

Everything above is additive or internal. **v2.0.0 would be warranted** by any of: renaming or removing public variables or endpoints; changing response fields or decision/rule identifiers; making the unversioned `/analyze` path deprecated-and-removed; flipping the code default of `GUARDRAILS_ALLOW_ANONYMOUS` to `false` (a breaking change for local development, although a security improvement); or replacing the authentication model. These are collected as **v2.0.0 candidates** and are not part of this roadmap.

---

## 10. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Scope too large for one maintainer | High | Slipped or rushed release | Tiered scope (§5); defer V13-006; ship in smaller minors if needed |
| Detector improvements change decisions for existing users | Medium | Unexpected blocks | Dataset-backed changes, changelog entries, minor-release policy |
| Lockfile workflow burdens contributors | Medium | Fewer contributions | Document one command; Dependabot automation |
| CI runtime and cost increase (container job, E2E) | Medium | Slower feedback | Run the container job on pull requests to `main` only; cache layers |
| Unverified assumptions about GitHub features (Dependabot detecting `requirements.*.txt`, provenance attestation availability) | Medium | Plan items blocked | Verify in M0; fall back to scripted equivalents |
| Documentation tests become brittle | Medium | Noise | Assert structured values, not prose |
