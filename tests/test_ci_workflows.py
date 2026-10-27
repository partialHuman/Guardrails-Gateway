"""Tests to validate GitHub Actions CI/CD workflows and security configurations.

Ensures:
  - All workflow files exist and have required top-level structures.
  - Workflows declare explicit, least-privilege permissions.
  - Dangerous triggers (such as unconstrained pull_request_target) are prohibited.
  - Required triggers (push to main and pull_request to main) are present.
  - Third-party actions are pinned to immutable 40-character commit SHAs.
  - CI enforces the minimum test coverage threshold.
  - Security audit and SAST tools (Bandit, pip-audit, TruffleHog, CodeQL) are configured.
  - Repository SECURITY.md policy is maintained.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
SHA_REGEX = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


@pytest.fixture(scope="module")
def workflow_texts() -> dict[str, str]:
    """Load text contents of all workflow YAML files in .github/workflows/."""
    workflows: dict[str, str] = {}
    for yml_file in sorted(WORKFLOWS_DIR.glob("*.yml")):
        workflows[yml_file.name] = yml_file.read_text(encoding="utf-8")
    return workflows


def test_required_workflow_files_exist():
    """Verify that all core CI and security workflow files exist."""
    expected = {"ci.yml", "security.yml", "codeql.yml"}
    actual = {f.name for f in WORKFLOWS_DIR.glob("*.yml")}
    assert expected.issubset(actual), f"Missing workflows: {expected - actual}"


def test_workflows_have_required_sections(workflow_texts):
    """Ensure all workflow files declare name, triggers, permissions, and jobs."""
    assert len(workflow_texts) >= 3
    for name, text in workflow_texts.items():
        assert re.search(r"^name:\s*.+", text, re.MULTILINE), f"{name} is missing 'name:'"
        assert re.search(r"^on:\s*", text, re.MULTILINE) or re.search(r"^['\"]on['\"]:\s*", text, re.MULTILINE), (
            f"{name} is missing 'on:' trigger section"
        )
        assert re.search(r"^permissions:\s*", text, re.MULTILINE), f"{name} is missing top-level 'permissions:'"
        assert re.search(r"^jobs:\s*", text, re.MULTILINE), f"{name} is missing 'jobs:'"


def test_workflows_are_valid_yaml_when_yaml_installed(workflow_texts):
    """If PyYAML is installed, verify all workflow files parse without syntax errors."""
    if yaml is None:
        pytest.skip("PyYAML is not installed in this environment; skipping YAML AST validation")
    for name, text in workflow_texts.items():
        parsed = yaml.safe_load(text)
        assert isinstance(parsed, dict), f"{name} did not parse into a valid YAML mapping"
        assert "name" in parsed
        assert "jobs" in parsed


def test_workflows_define_least_privilege_permissions(workflow_texts):
    """Ensure workflows define explicit permissions and prohibit wildcard write permissions."""
    for name, text in workflow_texts.items():
        # Verify permissions: block exists
        perm_match = re.search(r"^permissions:\s*\n((?:\s+[a-zA-Z0-9_-]+:\s*[a-zA-Z0-9_-]+\s*\n?)+)", text, re.MULTILINE)
        if perm_match:
            for line in perm_match.group(1).splitlines():
                if ":" in line:
                    _, val = line.split(":", 1)
                    assert val.strip() in ("read", "write", "none"), f"{name} has invalid permission {val}"
        else:
            # Single-line permission
            single_match = re.search(r"^permissions:\s*([a-zA-Z0-9_-]+)", text, re.MULTILINE)
            assert single_match, f"{name} missing permissions definition"
            assert single_match.group(1) in ("read-all", "contents"), f"{name} has invalid permission {single_match.group(1)}"

        # Prohibit write-all
        assert "write-all" not in text, f"{name} must not contain wildcard write-all permissions"


def test_no_dangerous_workflow_triggers(workflow_texts):
    """Ensure no workflow uses dangerous pull_request_target with untrusted checkouts."""
    for name, text in workflow_texts.items():
        assert "pull_request_target" not in text, (
            f"Workflow {name} must not use pull_request_target to prevent pwn-request attacks"
        )


def test_workflows_cover_main_branch_triggers(workflow_texts):
    """Verify push to main and pull_request to main triggers exist across workflows."""
    for name in ("ci.yml", "security.yml", "codeql.yml"):
        text = workflow_texts[name]
        assert "pull_request:" in text, f"{name} must trigger on pull_request"
        assert "push:" in text, f"{name} must trigger on push"
        assert "main" in text, f"{name} must target main branch"


def test_third_party_actions_pinned_to_commit_sha(workflow_texts):
    """Verify that third-party GitHub Actions are pinned to full commit SHAs for supply chain security."""
    for name, text in workflow_texts.items():
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("uses:"):
                action_ref = line.split("uses:")[1].strip().split("#")[0].strip()
                if action_ref.startswith("./"):
                    continue
                assert "@" in action_ref, f"Action reference '{action_ref}' in {name} missing '@'"
                _, ref = action_ref.split("@", 1)
                assert SHA_REGEX.match(ref), (
                    f"Action in {name} is not pinned to an immutable 40-character commit SHA: '{action_ref}'"
                )


def test_ci_enforces_coverage_threshold(workflow_texts):
    """Verify CI workflow strictly enforces minimum 95% test coverage."""
    ci_text = workflow_texts["ci.yml"]
    assert "--cov-fail-under=95" in ci_text or "--cov-fail-under=100" in ci_text, (
        "ci.yml must enforce coverage threshold of at least 95%"
    )


def test_security_workflow_contains_audit_tools(workflow_texts):
    """Verify security workflows configure Bandit, pip-audit, and TruffleHog."""
    sec_text = workflow_texts["security.yml"]
    assert re.search(r"^\s{2}bandit:\s*$", sec_text, re.MULTILINE), "security.yml missing bandit job"
    assert re.search(r"^\s{2}dependency-audit:\s*$", sec_text, re.MULTILINE), "security.yml missing dependency-audit job"
    assert re.search(r"^\s{2}secret-scan:\s*$", sec_text, re.MULTILINE), "security.yml missing secret-scan job"

    # Verify CodeQL has dedicated workflow
    codeql_text = workflow_texts["codeql.yml"]
    assert re.search(r"^\s{2}analyze:\s*$", codeql_text, re.MULTILINE), "codeql.yml missing analyze job"


def test_security_policy_file_exists():
    """Verify .github/SECURITY.md exists and contains disclosure and SLA sections."""
    sec_doc = REPO_ROOT / ".github" / "SECURITY.md"
    assert sec_doc.exists(), ".github/SECURITY.md must exist"
    content = sec_doc.read_text(encoding="utf-8")
    assert "Reporting a Vulnerability" in content
    assert "Severity Classification" in content
    assert "Critical" in content
    assert "TruffleHog" in content
    assert "CodeQL" in content


def test_trufflehog_native_event_handling_configuration(workflow_texts):
    """Verify TruffleHog secret-scan job relies on native action event dispatching without manual base/head."""
    sec_text = workflow_texts["security.yml"]

    # 1. Verify checkout retains fetch-depth: 0
    assert "fetch-depth: 0" in sec_text, "TruffleHog checkout must specify fetch-depth: 0 for full git history"

    # 2. Verify pinned TruffleHog action SHA and required arguments
    pinned_action = "uses: trufflesecurity/trufflehog@c85580b712841eda4c53bc28fc6ace6100e8c16c"
    assert pinned_action in sec_text, "TruffleHog step must use immutable commit SHA pin"
    assert "--only-verified" in sec_text, "TruffleHog step must include --only-verified flag"
    assert "path: ./" in sec_text, "TruffleHog step must include path: ./"

    # 3. Verify that base and head inputs are NOT explicitly defined, enabling native event handling
    if yaml is not None:
        parsed = yaml.safe_load(sec_text)
        jobs = parsed.get("jobs", {})
        secret_job = jobs.get("secret-scan", {})
        steps = secret_job.get("steps", [])

        # Find trufflehog step
        truffle_step = None
        for step in steps:
            uses = step.get("uses", "")
            if "trufflesecurity/trufflehog" in uses:
                truffle_step = step
                break

        assert truffle_step is not None, "security.yml missing TruffleHog action step"
        step_with = truffle_step.get("with", {})
        assert "base" not in step_with, (
            "TruffleHog step must omit explicit 'base' input to enable native push/PR/schedule dispatch"
        )
        assert "head" not in step_with, (
            "TruffleHog step must omit explicit 'head' input to enable native push/PR/schedule dispatch"
        )
        assert step_with.get("path") == "./"
        assert "--only-verified" in step_with.get("extra_args", "")

        # 4. Verify triggers include push, pull_request, and schedule
        triggers = parsed.get(True) or parsed.get("on", {})
        assert "push" in triggers, "security.yml must trigger on push"
        assert "pull_request" in triggers, "security.yml must trigger on pull_request"
        assert "schedule" in triggers, "security.yml must trigger on schedule"
    else:
        # Regex fallback when PyYAML is not installed
        assert not re.search(r"^\s+base:\s*", sec_text, re.MULTILINE), (
            "security.yml must omit explicit 'base' input to avoid base == head error"
        )
        assert not re.search(r"^\s+head:\s*", sec_text, re.MULTILINE), (
            "security.yml must omit explicit 'head' input to avoid base == head error"
        )
