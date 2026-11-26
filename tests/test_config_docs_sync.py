"""Permanent synchronization, determinism, and import-isolation tests for config docs."""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import app.config as config
from app.config_specs import CONFIG_SPECS
from scripts import generate_config_docs

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_SCRIPT = REPO_ROOT / "scripts" / "generate_config_docs.py"
DOCS_PATH = REPO_ROOT / "docs" / "configuration.md"


def test_docs_match_generated_output_byte_for_byte():
    expected_bytes = generate_config_docs.render_configuration_markdown().encode("utf-8")
    actual_bytes = DOCS_PATH.read_bytes()
    assert b"\r\n" not in actual_bytes
    assert actual_bytes == expected_bytes


def test_repeated_generation_is_byte_deterministic():
    first = generate_config_docs.render_configuration_markdown()
    second = generate_config_docs.render_configuration_markdown()
    assert first == second
    assert first.encode("utf-8") == second.encode("utf-8")


def test_cli_check_passes_when_in_sync():
    res = subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stderr


def test_cli_check_fails_on_drift_and_write_updates_temp_target(tmp_path):
    temp_doc = tmp_path / "configuration.md"
    temp_doc.write_text("# drifted documentation\n", encoding="utf-8")

    check_drifted = subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT), "--check", "--path", str(temp_doc)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert check_drifted.returncode != 0
    assert "out of sync" in check_drifted.stderr.lower()
    # --check must not modify the target file silently.
    assert temp_doc.read_text(encoding="utf-8") == "# drifted documentation\n"

    # Missing file also fails --check cleanly.
    missing_doc = tmp_path / "missing.md"
    check_missing = subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT), "--check", "--path", str(missing_doc)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert check_missing.returncode != 0

    # --write writes LF output to temp target cleanly and subsequent --check passes.
    write_res = subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT), "--write", "--path", str(temp_doc)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert write_res.returncode == 0
    assert b"\r\n" not in temp_doc.read_bytes()
    assert temp_doc.read_bytes() == DOCS_PATH.read_bytes()

    check_synced = subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT), "--check", "--path", str(temp_doc)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert check_synced.returncode == 0


def test_all_metadata_fields_variables_controls_and_distinct_urls_rendered():
    rendered = DOCS_PATH.read_text(encoding="utf-8")

    for required_heading in (
        "Environment Variable",
        "Default",
        "Type",
        "Component",
        "Required / Optional",
        "Validation Constraints",
        "Sensitive",
        "Deprecated",
        "Description",
    ):
        assert required_heading in rendered

    for section_num in range(1, 7):
        assert f"### {section_num}." in rendered

    # All overview rows and detail headings must represent each canonical variable exactly once.
    overview_block = rendered.split("## Detailed Variable Specifications", 1)[0]
    overview_vars = re.findall(r"^\| `([A-Z0-9_]+)` \|", overview_block, re.M)
    detail_vars = re.findall(r"^#### `([A-Z0-9_]+)`$", rendered, re.M)
    expected_vars = [spec.env_var for spec in CONFIG_SPECS]
    assert overview_vars == expected_vars
    assert len(detail_vars) == len(expected_vars)
    assert set(detail_vars) == set(expected_vars)

    # Confirm all 4 previously undocumented vars and 2 V13-002 controls are documented.
    for expected_var in (
        "GUARDRAILS_MAX_NORMALIZED_PROMPT_CHARS",
        "GUARDRAILS_MAX_NORMALIZED_DOC_CHARS",
        "GUARDRAILS_MAX_NORMALIZED_REQUEST_CHARS",
        "GUARDRAILS_API_URL",
        "GUARDRAILS_ENV_FILE",
        "GUARDRAILS_STRICT_ENV",
    ):
        assert expected_var in overview_vars
        assert expected_var in detail_vars

    # Confirm API_URL (UI) and GUARDRAILS_API_URL (CLI) remain distinct.
    assert "| `API_URL` | `\"http://localhost:8000\" / \"http://api:8000\"` | `URL String` | UI |" in rendered
    assert "| `GUARDRAILS_API_URL` | `\"http://127.0.0.1:8000\"` | `URL String` | CLI |" in rendered

    # Confirm runtime Settings.model_fields bijective parity matches generator AST check.
    mapped_attrs = [s.python_attr for s in CONFIG_SPECS if s.python_attr is not None]
    assert tuple(mapped_attrs) == generate_config_docs.extract_settings_field_names()
    assert set(mapped_attrs) == set(config.Settings.model_fields.keys())


def test_sensitive_runtime_values_never_leak_into_generated_docs():
    secret_env = {
        **os.environ,
        "GUARDRAILS_REQUIRE_AUTH": "invalid-bool-value",
        "GUARDRAILS_API_KEY": "live-secret-api-key-DO-NOT-EMIT",
        "GUARDRAILS_RATE_LIMIT_REDIS_URL": "rediss://admin:live-redis-secret@host:6380/0",
        "GUARDRAILS_UI_PASSWORD": "live-ui-secret-password",
        "GUARDRAILS_ENV_FILE": "/nonexistent/live-env-file.env",
    }
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path('scripts').resolve()))\n"
        "import generate_config_docs\n"
        "print(generate_config_docs.render_configuration_markdown())\n"
    )
    res = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=secret_env,
        capture_output=True,
        text=True,
        check=True,
    )
    for secret in (
        "live-secret-api-key-DO-NOT-EMIT",
        "live-redis-secret",
        "live-ui-secret-password",
        "/nonexistent/live-env-file.env",
    ):
        assert secret not in res.stdout


def test_generator_import_isolation_in_fresh_subprocess():
    init_file = REPO_ROOT / "app" / "__init__.py"
    assert init_file.read_bytes() == b""

    hostile_env = {
        **os.environ,
        "GUARDRAILS_REQUIRE_AUTH": "not-a-boolean",
        "GUARDRAILS_API_KEY": "subproc-hostile-api-secret",
        "GUARDRAILS_ENV_FILE": "/nonexistent/subproc.env",
    }
    probe_code = (
        "import importlib, sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, str(Path('scripts').resolve()))\n"
        "import generate_config_docs\n"
        "out1 = generate_config_docs.render_configuration_markdown()\n"
        "out2 = generate_config_docs.render_configuration_markdown()\n"
        "assert out1 == out2\n"
        "assert 'app' not in sys.modules\n"
        "assert 'app.config' not in sys.modules\n"
        "assert 'app.config_specs' not in sys.modules\n"
        "assert 'pydantic' not in sys.modules\n"
        "assert generate_config_docs.SPECS_MODULE_NAME not in sys.modules\n"
        "print('ISOLATED_OK')\n"
    )
    res = subprocess.run(
        [sys.executable, "-c", probe_code],
        cwd=REPO_ROOT,
        env=hostile_env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout.strip() == "ISOLATED_OK"


def test_temporary_metadata_module_registration_and_cleanup_on_success_and_failure(
    monkeypatch,
):
    mod_name = generate_config_docs.SPECS_MODULE_NAME
    assert mod_name not in sys.modules

    # 1. Normal execution: module IS registered inside sys.modules during exec_module()
    #    (allowing @dataclass annotations resolution) and removed cleanly afterward.
    observed_during_exec: list[bool] = []
    real_spec_from_file_location = importlib.util.spec_from_file_location

    def spy_spec(name, location, *args, **kwargs):
        spec = real_spec_from_file_location(name, location, *args, **kwargs)
        orig_exec = spec.loader.exec_module

        def wrapped_exec(module):
            observed_during_exec.append(name in sys.modules and sys.modules[name] is module)
            return orig_exec(module)

        spec.loader.exec_module = wrapped_exec
        return spec

    monkeypatch.setattr(importlib.util, "spec_from_file_location", spy_spec)
    loaded = generate_config_docs.load_config_specs_module()
    assert observed_during_exec == [True]
    assert len(loaded.CONFIG_SPECS) == len(CONFIG_SPECS)
    assert mod_name not in sys.modules

    # 2. Forced exec_module() failure: finally block still removes temporary registration.
    def failing_spec(name, location, *args, **kwargs):
        spec = real_spec_from_file_location(name, location, *args, **kwargs)

        def failing_exec(module):
            observed_during_exec.append(name in sys.modules and sys.modules[name] is module)
            raise RuntimeError("forced exec_module failure")

        spec.loader.exec_module = failing_exec
        return spec

    monkeypatch.setattr(importlib.util, "spec_from_file_location", failing_spec)
    with pytest.raises(RuntimeError, match="forced exec_module failure"):
        generate_config_docs.load_config_specs_module()
    assert observed_during_exec == [True, True]
    assert mod_name not in sys.modules
