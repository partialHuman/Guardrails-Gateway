"""SG-002 / SG-009: the shipped deployment is closed and constrained by default."""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


COMPOSE = read("docker-compose.yml")


def service_block(name: str) -> str:
    match = re.search(
        rf"^  {name}:\n(?P<body>.*?)(?=^  \S|\Z)", COMPOSE, re.S | re.M
    )
    assert match, f"service {name!r} not found"
    return match.group("body")


@pytest.mark.parametrize("service", ["api", "ui"])
def test_published_ports_bind_to_loopback_by_default(service):
    ports = re.findall(r'^\s+- "([^"]+:\d+:\d+)"', service_block(service), re.M)

    assert ports, "no published ports found"

    for mapping in ports:
        assert mapping.startswith("${GUARDRAILS_BIND_ADDRESS:-127.0.0.1}:"), mapping


@pytest.mark.parametrize("service", ["api", "ui"])
@pytest.mark.parametrize(
    "setting",
    [
        r"mem_limit:\s*\S+",
        r"cpus:\s*[\d.]+",
        r"pids_limit:\s*\d+",
        r"cap_drop:\s*\n\s+- ALL",
        r"no-new-privileges:true",
    ],
)
def test_services_are_resource_limited_and_unprivileged(service, setting):
    assert re.search(setting, service_block(service)), setting


def test_api_filesystem_is_read_only_with_scratch_tmpfs():
    block = service_block("api")

    assert re.search(r"read_only:\s*true", block)
    assert re.search(r"tmpfs:\s*\n\s+- /tmp", block)


def test_api_refuses_anonymous_start_unless_opted_in():
    assert "GUARDRAILS_ALLOW_ANONYMOUS=${GUARDRAILS_ALLOW_ANONYMOUS:-false}" in service_block("api")


def test_ui_is_locked_unless_password_or_explicit_opt_in():
    block = service_block("ui")

    assert "GUARDRAILS_UI_PASSWORD: ${GUARDRAILS_UI_PASSWORD:-}" in block
    assert "GUARDRAILS_UI_ALLOW_ANONYMOUS: ${GUARDRAILS_UI_ALLOW_ANONYMOUS:-false}" in block


def test_compose_has_no_hardcoded_secrets():
    assignment = re.compile(r"^\s*(-\s*)?[A-Z_]*(KEY|PASSWORD)[A-Z_]*\s*[=:]")

    checked = 0

    for line in COMPOSE.splitlines():
        if assignment.match(line):
            checked += 1
            assert "${" in line, line

    assert checked >= 3  # the check really inspected the secret-bearing lines


def test_api_image_defaults_to_no_anonymous_access():
    dockerfile = read("Dockerfile.api")

    assert "GUARDRAILS_ALLOW_ANONYMOUS=false" in dockerfile


def test_api_image_runs_as_non_root_with_read_only_code():
    dockerfile = read("Dockerfile.api")

    assert re.search(r"^USER appuser$", dockerfile, re.M)
    assert "chown -R" not in dockerfile  # code is not writable by the runtime user


def test_api_server_does_not_advertise_itself():
    assert "--no-server-header" in read("Dockerfile.api")


def test_env_template_has_no_real_secret_and_env_is_ignored():
    template = read(".env.example")

    assert re.search(r"^GUARDRAILS_API_KEY=$", template, re.M)
    assert re.search(r"^GUARDRAILS_BIND_ADDRESS=127\.0\.0\.1$", template, re.M)

    for ignore_file in (".gitignore", ".dockerignore"):
        assert re.search(r"^\.env$", read(ignore_file), re.M), ignore_file


def test_line_endings_are_normalised():
    assert "eol=lf" in read(".gitattributes")


def test_redis_client_is_optional_not_in_the_runtime_image():
    assert "redis" not in read("requirements.api.txt").lower()
    assert "redis" in read("requirements.redis.txt").lower()
