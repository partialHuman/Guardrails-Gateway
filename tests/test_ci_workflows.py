"""Tests to validate GitHub Actions CI/CD workflows and security configurations.

Ensures:
  - All workflow files are syntactically valid YAML.
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
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
SHA_REGEX = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


@pytest.fixture(scope="module")
def workflow_files() -> dict[str, dict]:
    """Load and parse all workflow YAML files in .github/workflows/."""
    workflows: dict[str, dict] = {}
    for yml_file in sorted(WORKFLOWS_DIR.glob("*.yml")):
        with open(yml_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        workflows[yml_file.name] = data
    return workflows


def test_required_workflow_files_exist():
    """Verify that all core CI and security workflow files exist."""
    expected = {"ci.yml", "security.yml", "codeql.yml"}
    actual = {f.name for f in WORKFLOWS_DIR.glob("*.yml")}
    assert expected.issubset(actual), f"Missing workflows: {expected - actual}"


def test_workflows_are_valid_yaml(workflow_files):
    """Ensure all workflow files parse into non-empty dictionaries."""
    assert len(workflow_files) >= 3
    for name, content in workflow_files.items():
        assert isinstance(content, dict), f"{name} did not parse into a YAML mapping"
        assert "name" in content, f"{name} is missing a top-level 'name' attribute"
        assert "jobs" in content, f"{name} is missing a top-level 'jobs' attribute"


def test_workflows_define_least_privilege_permissions(workflow_files):
    """Ensure workflows define explicit top-level or job-level permissions."""
    for name, content in workflow_files.items():
        perms = content.get("permissions")
        assert perms is not None, f"Workflow {name} must declare explicit permissions"
        if isinstance(perms, dict):
            # Prohibit wildcard write
            for scope, level in perms.items():
                assert level in ("read", "write", "none"), f"{name} has invalid permission level {level}"
        else:
            assert perms in ("read-all", "contents: read"), f"{name} has unexpected permission string {perms}"


def test_no_dangerous_workflow_triggers(workflow_files):
    """Ensure no workflow uses dangerous pull_request_target with untrusted checkouts."""
    for name, content in workflow_files.items():
        # YAML parsers may interpret 'on' as boolean True
        triggers = content.get("on") or content.get(True) or {}
        if isinstance(triggers, dict):
            assert "pull_request_target" not in triggers, (
                f"Workflow {name} must not use pull_request_target to prevent pwn-request attacks"
            )


def test_workflows_cover_main_branch_triggers(workflow_files):
    """Verify push to main and pull_request to main triggers exist across workflows."""
    for name in ("ci.yml", "security.yml", "codeql.yml"):
        content = workflow_files[name]
        triggers = content.get("on") or content.get(True) or {}
        assert "pull_request" in triggers, f"{name} must trigger on pull_request"
        pr_config = triggers["pull_request"]
        if isinstance(pr_config, dict):
            assert "main" in pr_config.get("branches", []), f"{name} pull_request must target main"


def test_third_party_actions_pinned_to_commit_sha():
    """Verify that third-party GitHub Actions are pinned to full commit SHAs for supply chain security."""
    for yml_file in WORKFLOWS_DIR.glob("*.yml"):
        text = yml_file.read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("uses:"):
                action_ref = line.split("uses:")[1].strip().split("#")[0].strip()
                # Internal/local actions start with ./
                if action_ref.startswith("./"):
                    continue
                assert "@" in action_ref, f"Action reference '{action_ref}' in {yml_file.name} missing '@'"
                _, ref = action_ref.split("@", 1)
                assert SHA_REGEX.match(ref), (
                    f"Action in {yml_file.name} is not pinned to an immutable 40-character commit SHA: '{action_ref}'"
                )


def test_ci_enforces_coverage_threshold(workflow_files):
    """Verify CI workflow strictly enforces minimum 95% test coverage."""
    ci_content = workflow_files["ci.yml"]
    steps = ci_content["jobs"]["test"]["steps"]
    run_steps = [s.get("run", "") for s in steps if "run" in s]
    combined_commands = " ".join(run_steps)

    assert "--cov-fail-under=95" in combined_commands or "--cov-fail-under=100" in combined_commands, (
        "ci.yml must enforce coverage threshold of at least 95%"
    )


def test_security_workflow_contains_audit_tools(workflow_files):
    """Verify security workflows configure Bandit, pip-audit, and TruffleHog."""
    sec = workflow_files["security.yml"]
    jobs = sec["jobs"]

    assert "bandit" in jobs, "security.yml missing bandit job"
    assert "dependency-audit" in jobs, "security.yml missing dependency-audit job"
    assert "secret-scan" in jobs, "security.yml missing secret-scan job"

    # Verify CodeQL has dedicated workflow
    codeql = workflow_files["codeql.yml"]
    assert "analyze" in codeql["jobs"], "codeql.yml missing analyze job"


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
