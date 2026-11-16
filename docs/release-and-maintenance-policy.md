# Release and Maintenance Policy

| | |
|---|---|
| **Status** | **Proposed — requires maintainer approval.** Sections describing existing conventions are marked *(existing)*; everything else is a recommendation |
| **Date** | 2026-11-03 |
| **Applies to** | SentraGuard Lite from v1.2.0 onward |
| **Related** | [Release baseline](release-baseline-v1.2.0.md) · [v1.3.0 roadmap](roadmap-v1.3.0.md) · [Release checklist](release-checklist.md) · [Security policy](../.github/SECURITY.md) · [Contributing guide](../CONTRIBUTING.md) |

## Table of contents

1. [Principles](#1-principles)
2. [Versioning](#2-versioning)
3. [What belongs in v1.2.x](#3-what-belongs-in-v12x)
4. [Patch-release workflow](#4-patch-release-workflow)
5. [Security hotfix procedure](#5-security-hotfix-procedure)
6. [Release and tag policy](#6-release-and-tag-policy)
7. [Maintenance lifecycle](#7-maintenance-lifecycle)
8. [Changelog rules](#8-changelog-rules)
9. [Failed releases and rollback](#9-failed-releases-and-rollback)
10. [Decisions needed from the maintainer](#10-decisions-needed-from-the-maintainer)

---

## 1. Principles

1. **v1.2.0 is the stable baseline.** Maintenance releases preserve compatibility wherever practical; larger architectural and user-facing changes are evaluated for v1.3.0.
2. **A version number communicates compatibility intent, not the size of a diff.**
3. **Release when a validated change justifies it** — never to fill a version number.
4. **Published tags and releases are immutable.** Fix forward.
5. **Evidence before claims**: a release note, security document or checklist item states only what has been verified.

---

## 2. Versioning

Semantic Versioning (`MAJOR.MINOR.PATCH`) is used. The *compatibility contract* it refers to is defined in [baseline §8](release-baseline-v1.2.0.md#8-compatibility-contract-for-the-v12x-line).

| Version | Meaning | Example for this project |
|---|---|---|
| **v1.2.0** | Stable baseline | The current release |
| **v1.2.1, v1.2.2, …** | Backward-compatible fixes: bug fixes, security fixes, safe dependency updates, documentation corrections, small operational improvements. **Contract preserved** | Scanning a bounded prefix of oversized base64 tokens (BASE-001 High-severity remediation); correcting `SECURITY.md` |
| **v1.3.0** | Backward-compatible **feature additions** and planned enhancements too substantial for a patch. New settings/endpoints/fields allowed; **defaults and existing behavior preserved** | Configuration subsystem, structured logging ([roadmap](roadmap-v1.3.0.md)) |
| **v2.0.0** | **Breaking** changes that start a new contract | Removing or renaming a variable/endpoint, changing response fields or decision values, flipping the code default of `GUARDRAILS_ALLOW_ANONYMOUS` |
| `-rc.N` suffix | Release candidate for a minor/major; **not** used for patches | `v1.3.0-rc.1` |

### 2.1 When a small change is breaking

Treat as **breaking** (minor or major, never a patch) even if the diff is a few lines:

- Changing a **default**, especially a security default (`GUARDRAILS_ALLOW_ANONYMOUS`, thresholds, limits).
- Changing the text of the published `incomplete_scan_prompt`, a rule id, a `risk_tags` value, or a decision value.
- Adding a **required** variable, or making an unknown or previously accepted value invalid (strict parsing of an existing variable).
- Tightening a limit so that input accepted today is rejected.
- Removing or renaming a header, field, flag or log field that integrations may parse (log *format* is explicitly **not** contractual; see baseline §8).
- Changing Compose service names, ports, or the container user.

Treat as **not breaking** even if the diff is large: internal refactors with unchanged behavior and tests; dependency patch updates; new log fields; documentation rewrites.

### 2.2 Detection changes

Detector behavior *is* product behavior. Rule of thumb:

- **Patch:** a fix that makes a **known-bad input detected** (a bypass fix) or a **known-benign input no longer flagged** (a false-positive fix), with a regression test and a changelog entry naming the rule id.
- **Minor:** new rules, retuned severities or thresholds, or anything that changes decisions for inputs not previously classified incorrectly.
- Every detector change is recorded in the changelog under *Security* or *Changed*.

### 2.3 Security fixes and urgency

A security fix ships as the **next patch** even if it forces a small compatibility exception. If no compatible fix exists, document the break prominently, consider an advisory, and prefer a patch release with a clear migration note over leaving users exposed. Urgent handling: [§5](#5-security-hotfix-procedure).

---

## 3. What belongs in v1.2.x

Releases occur only when at least one *user-affecting, validated* change is ready. CI-only, test-only and internal changes merge to `main` and appear in the next release's notes; they do not trigger a release by themselves.

| Category | Qualifies as a patch when | Defer or use a minor when | Examples from this project |
|---|---|---|---|
| **Confirmed bug fix** | Reproduced, regression test added, contract preserved | Fix requires a contract change | A response or log defect with a failing test |
| **Security vulnerability / bypass** | Fix preserves §2.1; a test proves the exploit fails | Requires a breaking change with no compatible alternative (then: announce, document, decide) | BASE-001 (oversized base64, High severity); BASE-002 bounded post-normalization cap (a *new rejection* only of pathological input, with a high threshold and a changelog note) |
| **Safe dependency update** | Patch/minor of a pinned dependency, full tests and `pip-audit` pass, no behavior change | Major version bump or behavior change | Updating pinned `fastapi`/`uvicorn`/`streamlit`; Dependabot PRs |
| **CI workflow fix** | Keeps required check names and permissions least-privilege | Changes what gates a release | CodeQL Action v3 → v4 (BASE-008); pinning CI tools (BASE-009); extending Bandit to `ui/` |
| **Documentation correction** | Brings text in line with verified behavior | The text describes a *new* behavior | The 24 discrepancies D-01…D-24 |
| **Small UI/API defect** | Contract preserved | Needs a new field, endpoint or setting | A UI rendering defect with a test |
| **Test reliability** | Removes flakiness without relaxing assertions | Requires new infrastructure | Pinning Playwright; fixing a timing-sensitive test |
| **Small operational improvement** | Config/documentation only, supported deployment unchanged | Changes supported topology or defaults | Compose `logging.options` for rotation (BASE-012); documenting Uvicorn proxy trust (BASE-013) |

> Documentation-only changes need not trigger a release **unless they correct a security-relevant public claim** (the release ZIP contains `SECURITY.md`, so a wrong claim ships with it). That is why the audit's documentation corrections justify v1.2.1.

### 3.1 Candidate v1.2.1 content (non-binding)

Ship only items that are implemented and verified; drop any that are not ready. See the [audit register](post-release-audit-v1.2.0.md#9-prioritized-remediation-register).

| Include | Source |
|---|---|
| Bounded-prefix scanning of oversized base64 tokens (High severity bypass fix) | A-01 / BASE-001 |
| Post-normalization length cap | A-02 / BASE-002 |
| Documentation corrections, revised release checklist and runbook | A-03…A-05 / BASE-003…006 |
| CodeQL Action v4; pinned CI tools; Bandit scope | A-06, A-07 |
| Compose log rotation; Uvicorn proxy-trust documentation | A-08, A-09 |
| Test tying `API_VERSION` to the changelog | A-10 |

**Not** v1.2.1: structured logging, configuration subsystem, lockfiles, container CI, the detection harness (v1.3.0).

---

## 4. Patch-release workflow

*(existing conventions are used wherever they exist: branch prefixes, Conventional Commits, pull requests to `main`)*

| # | Step | Repository-specific detail |
|---|---|---|
| 1 | Record the defect | GitHub issue (or private advisory for security — [§5](#5-security-hotfix-procedure)) with reproduction and affected versions |
| 2 | Classify | Severity, affected versions, and **compatibility impact** against [baseline §8](release-baseline-v1.2.0.md#8-compatibility-contract-for-the-v12x-line) and §2.1 above |
| 3 | Branch from the correct base *(existing prefixes)* | `fix/<bug-description>`, `hardening/<scope>`, `docs/<topic>`, `test/<scope>` (CONTRIBUTING lines 99–103), from `main` while `main` is still the 1.2 line; from `release/1.2` afterwards (§4.1) |
| 4 | Smallest safe fix | No drive-by refactors; one concern per pull request |
| 5 | Regression test | A test that **fails without the fix** (verify by temporarily reverting it) |
| 6 | Run checks locally | `python -m pytest -m "not e2e" --cov=app --cov-report=term-missing --cov-fail-under=95`; E2E when UI/auth is touched; `bandit -r app ui cli.py -ll`; `pip-audit` for changed requirement files |
| 7 | Review the diff | Including dependency changes and any new or changed log output (no secrets, no request content) |
| 8 | Update `CHANGELOG.md` | Add the entry under the next version heading (or `## Unreleased` until the version is decided) in the right category (§8) |
| 9 | Update version metadata | `API_VERSION` in `app/config.py` and the top changelog heading **must match**; search the docs for the old version string. (A test enforcing this is proposed as A-10; until then, the checklist verifies it) |
| 10 | Open a pull request to `main` | Conventional Commit title (`fix: …`); the PR template referenced by CONTRIBUTING does not exist yet — describe scope, risk and test evidence |
| 11 | Required checks and review | Checks (exact job names): `Run Python tests (Python 3.11)`, `Run Python tests (Python 3.14)`, `Browser E2E Tests (Playwright / Chromium / Python 3.11)`, `Python static security analysis (Bandit)`, `Dependency vulnerability audit (pip-audit)`, `Secret detection (TruffleHog)`, `CodeQL (Python)`. **Branch protection does not currently enforce them** (empirically confirmed in audit A-14; open tracking action A-18) |
| 12 | Merge | Follow repository practice (merge commits are used in the history) |
| 13 | Create an **annotated** tag | `git tag -a vX.Y.Z <merge-sha> -m "SentraGuard Lite vX.Y.Z"` (use `-s` if a signing key is configured); push the tag only after step 12's commit is on `main`/`release/*` |
| 14 | Publish release notes | Extract the changelog section (snippet below); mark pre-releases only for `-rc` |
| 15 | Verify the published tag and release | `git rev-parse vX.Y.Z^{commit}` equals the intended commit; `git cat-file -t vX.Y.Z` is `tag`; the release shows the correct target; download the ZIP and compare its archive comment |
| 16 | Smoke test | Clean checkout of the tag: `docker compose up -d --wait`, `curl` `/health`, one authenticated `/analyze`, one rejected request, then `docker compose down` |
| 17 | Follow-up | Open issues for anything deferred; update the audit/action register |

**Extract release notes from the changelog** (validated against this repository's `CHANGELOG.md`):

```bash
VERSION=1.2.1
awk -v v="$VERSION" '$0 == "## " v {f=1; next} /^## / && f {exit} f' CHANGELOG.md > release-notes.md
test -s release-notes.md || { echo "no changelog section for $VERSION"; exit 1; }
```

**Check that the declared version matches the changelog** (skips an `Unreleased` section):

```bash
python - <<'PY'
import pathlib, re
code = re.search(r'API_VERSION = "([^"]+)"', pathlib.Path("app/config.py").read_text()).group(1)
head = re.search(r"^## (?!Unreleased)(\S+)", pathlib.Path("CHANGELOG.md").read_text(), re.M).group(1)
print("API_VERSION =", code, "| newest changelog heading =", head)
raise SystemExit(0 if code == head else "version mismatch")
PY
```

### 4.1 Maintenance branch strategy

Keep `main` always releasable (trunk-based). **While `main` contains only 1.2-compatible changes, patches go to `main`.** At the moment the **first v1.3-only change** would merge, first create `release/1.2` from the latest `v1.2.x` tag; thereafter fixes land on `main` and are cherry-picked to `release/1.2` (security fixes first on whichever is faster, then ported). Do not create `release/1.2` earlier — it adds work with no benefit. *(recommendation)*

---

## 5. Security hotfix procedure

An expedited path that keeps the audit trail. Time targets are **recommendations**: `SECURITY.md` currently promises 24-hour acknowledgement and fixes, which a single maintainer may not be able to honor (audit BASE-016); reconcile the two (action A-17).

| Stage | Actions |
|---|---|
| **1. Intake** | Reports arrive through GitHub **Private Vulnerability Reporting** (confirm it is enabled [N]) or the contact in `SECURITY.md`. Acknowledge, assign an owner, never discuss details publicly |
| **2. Triage** | Reproduce; identify affected versions (diff against the tags); classify severity using the table in `SECURITY.md` and **record the reasoning**; decide: patch now, or schedule |
| **3. Private fix** | Develop in a **private** location (a GitHub temporary private fork attached to a draft advisory). No public branch, pull request, issue or commit message that reveals the weakness before the fix is released |
| **4. Regression test** | A test that reproduces the exploit and fails without the fix; check for the same pattern elsewhere (siblings, other detectors, docs claiming the behavior) |
| **5. Review** | Independent review if possible; dependency and secret review of the diff; confirm the fix preserves §2.1 or document the exception |
| **6. Validate** | The **full** required CI set still runs — none is skipped for speed. Re-run E2E if authentication or the UI is touched |
| **7. Release** | Patch version (§4 steps 8–16). Release notes name the fixed weakness at the level appropriate to the advisory — enough for users to judge exposure, without a working exploit |
| **8. Advisory** | Publish the GitHub Security Advisory (request a CVE when warranted); list affected and fixed versions; credit the reporter if they agree |
| **9. Backport** | Backport to every **supported** maintenance line (§7) when severity ≥ Medium. Lower severities go into the next regular patch |
| **10. Monitor** | For several days after release watch new issues, Dependabot/code-scanning alerts, and reports of regressions; record the outcome |

**Dependency vulnerabilities:** a `pip-audit` finding in a *pinned* direct or transitive dependency follows the same path when the vulnerable code is reachable; otherwise it is a normal dependency patch.

---

## 6. Release and tag policy

| Topic | Policy |
|---|---|
| **Tag name** | `vMAJOR.MINOR.PATCH`; release candidates `vMAJOR.MINOR.PATCH-rc.N` |
| **Tag type** | **Annotated** (`git tag -a`). Signed (`-s`) when a signing key is available; the checklist records which was used |
| **Target** | A commit already on `main` (or `release/*`) with all required checks green. Verify with `git rev-parse <tag>^{commit}` before publishing |
| **Pre-tag requirements** | The [release checklist](release-checklist.md) gates 1–7 complete; `API_VERSION` equals the changelog heading |
| **Release notes** | Exactly the changelog section for that version (script above), plus a short "Upgrade notes" paragraph when behavior changes |
| **Immutability** | **Never move, delete or reuse a tag that has been published.** If a tag was pushed by mistake and nobody could have consumed it, record why before correcting; otherwise fix forward |
| **Failed or bad release** | Publish the next patch. Edit the bad release's notes with a warning and a link to the fix; mark it pre-release if it is dangerous. Do not rewrite history |
| **Draft releases** | May be deleted before publication; a published release may not |
| **Artifacts** | Today: GitHub's generated source archives (the commit SHA is stored in the ZIP comment; verify by extracting and diffing against `git archive` — see [audit §3](post-release-audit-v1.2.0.md#3-release-identity-and-provenance)). Proposed in the roadmap (V13-008): checksums, an SBOM and build-provenance attestations |
| **Integrity check for consumers** | Download the ZIP, read its comment (`unzip -z`), compare with the tag's commit, and diff the extracted tree against `git archive <tag>` |
| **No automation yet** | There is no release workflow; releases are manual and follow the checklist. Automation is not proposed until the manual process has been exercised a few times |

---

## 7. Maintenance lifecycle

**(recommendation — requires maintainer approval; the project currently states no support duration)**

| Line | Receives | Duration |
|---|---|---|
| Latest minor (today v1.2.x) | Bug, security and dependency fixes | Until the next minor is released |
| Previous minor (v1.2.x after v1.3.0) | **Security and critical-bug fixes only** | **90 days after v1.3.0 is generally available** (≥ 3 months), then end of life |
| Previous major (v1.x after v2.0.0) | Security fixes only | 6 months after v2.0.0 |
| Older lines | None | — |

On v1.3.0 release:

1. Publish a final v1.2.x patch (if fixes are pending) whose notes state the end-of-life date.
2. Update the supported-versions table in `SECURITY.md` and add an upgrade section to the v1.3.0 notes (compatibility is preserved, so the upgrade should need no configuration change — verified before release).
3. Add a short README note pointing users of v1.2.x to the upgrade notes.
4. Create `release/1.2` if it does not exist (§4.1).

Support commitments are promises; the maintainer should confirm capacity before adopting these durations.

---

## 8. Changelog rules

*(the existing file follows the "Keep a Changelog" style with `## <version>` headings and no dates)*

- **Sections:** `Security`, `Fixed`, `Added`, `Changed`, `Breaking changes` (minor/major only), `Documentation`, `Not changed (known limitations)` and, when relevant, `Upgrade notes`.
- **`## Unreleased`** accumulates entries for the next version; at release it is renamed to the version heading. It is never used to describe changes that are not merged.
- **Never edit the entries of a published version.** If a published entry is wrong (as several statements in the 1.2.0 notes are — audit §8), add a **"Corrections to the 1.2.0 notes"** subsection to the *next* release.
- **No entry without an implementation.** Do not add a `v1.2.1` heading until its changes are merged and validated.
- Security entries cite the finding or advisory id and the regression test.
- *Recommendation:* add the release date to each heading when the next release is cut (maintainer decision).

---

## 9. Failed releases and rollback

| Situation | Action |
|---|---|
| Defect found after publishing | Fix forward: next patch. Annotate the faulty release |
| Users must stop using a release immediately | Edit its notes with a warning, mark as pre-release, publish the fix and an advisory if security-relevant |
| Deployment of a new release fails | Redeploy the previous **tag** (`git checkout <tag>`, rebuild; images are not published). The service is stateless, so no data restore is required — see [baseline §7](release-baseline-v1.2.0.md#7-backup-recovery-and-rollback-assumptions) |
| Wrong tag pushed | Follow the immutability rule in §6; record what happened |
| CI breaks after a dependency or action update | Revert that update via a normal pull request |

---

## 10. Decisions needed from the maintainer

| # | Decision | Recommended |
|---|---|---|
| 1 | Adopt this policy (or amend) | Adopt |
| 2 | Support duration after v1.3.0 | 90 days security-only |
| 3 | Branch protection / required checks | Require the seven checks in §4 step 11 |
| 4 | Signed tags | Sign if a key exists |
| 5 | Align `SECURITY.md` timelines with real capacity | Yes (A-17) |
| 6 | Severity classification of detection bypasses | Resolved: Option A (High per `SECURITY.md`; A-17) |
| 7 | Add release dates to changelog headings | Yes, from the next release |
| 8 | Supported Python versions (3.12 and 3.13 are documented but not tested) | Either test them or document 3.11 and 3.14 only (A-11) |
