"""CI must audit everything that ships, and keep pinned versions current."""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_ui_dependencies_are_audited():
    # The Streamlit UI image has its own (large) dependency tree; auditing
    # only the API requirements left it unchecked.
    security = read(".github/workflows/security.yml")

    assert re.search(r"pip-audit[^\n]*-r requirements\.ui\.txt", security)


def test_every_requirements_file_is_audited():
    security = read(".github/workflows/security.yml")

    for name in ("requirements.api.txt", "requirements.dev.txt", "requirements.ui.txt", "requirements.redis.txt"):
        assert name in security, name


def test_tests_run_on_more_than_one_python_version():
    ci = read(".github/workflows/ci.yml")

    match = re.search(r"python-version:\s*\[([^\]]+)\]", ci)

    assert match, "no python-version matrix"
    assert len(re.findall(r"\d+\.\d+", match.group(1))) >= 2
    assert "${{ matrix.python-version }}" in ci


def test_dependabot_covers_actions_python_and_docker():
    config = read(".github/dependabot.yml")

    for ecosystem in ("github-actions", "pip", "docker"):
        assert f'package-ecosystem: "{ecosystem}"' in config
