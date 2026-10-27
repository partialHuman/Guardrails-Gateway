"""Identifiers are bounded and clean; responses state which policy decided."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.policy import POLICY_VERSION
from app.main import app
from app.schemas import (
    MAX_IDENTIFIER_CHARS,
    ContextDocument,
    Metadata,
    SanitizedDocument,
)

client = TestClient(app)


def metadata(**overrides):
    values = {"app_id": "app", "user_id": "user", "request_id": "req"}
    values.update(overrides)
    return Metadata(**values)


@pytest.mark.parametrize("field", ["app_id", "user_id", "request_id"])
def test_identifiers_up_to_the_limit_are_accepted(field):
    metadata(**{field: "a" * MAX_IDENTIFIER_CHARS})


@pytest.mark.parametrize("field", ["app_id", "user_id", "request_id"])
def test_overlong_identifiers_are_rejected(field):
    with pytest.raises(ValidationError):
        metadata(**{field: "a" * (MAX_IDENTIFIER_CHARS + 1)})


@pytest.mark.parametrize("field", ["app_id", "user_id", "request_id"])
@pytest.mark.parametrize("bad", ["a\nb", "a\rb", "a\x00b", "a\x1bb", "a\x7fb"])
def test_identifiers_with_control_characters_are_rejected(field, bad):
    with pytest.raises(ValidationError):
        metadata(**{field: bad})


def test_document_id_is_bounded_and_clean():
    ContextDocument(id="d" * MAX_IDENTIFIER_CHARS, text="x")

    with pytest.raises(ValidationError):
        ContextDocument(id="d" * (MAX_IDENTIFIER_CHARS + 1), text="x")

    with pytest.raises(ValidationError):
        ContextDocument(id="doc\n1", text="x")


def test_api_rejects_a_megabyte_app_id():
    # It used to be logged verbatim: a 1 MiB log line from one request.
    response = client.post(
        "/analyze",
        json={
            "prompt": "hi",
            "context_docs": [],
            "metadata": {"app_id": "A" * 100_000, "user_id": "u", "request_id": "r"},
        },
    )

    assert response.status_code == 422


def test_response_states_the_policy_version():
    response = client.post(
        "/analyze",
        json={
            "prompt": "hello",
            "context_docs": [],
            "metadata": {"app_id": "a", "user_id": "u", "request_id": "r"},
        },
    )

    assert response.status_code == 200
    assert response.json()["policy_version"] == POLICY_VERSION == "3"


def test_sanitized_documents_have_no_length_cap():
    # Redaction can lengthen text; the response model must not reject that.
    SanitizedDocument(id="d", text="x" * 1_000_000)
