import pytest
from pydantic import ValidationError

from app.config import (
    MAX_CONTEXT_DOCS,
    MAX_DOC_CHARS,
    MAX_PROMPT_CHARS,
)
from app.schemas import AnalyzeRequest, ContextDocument


META = {
    "app_id": "test-app",
    "user_id": "test-user",
    "request_id": "req-boundary-test",
}


def test_prompt_at_maximum_length_is_accepted():
    request = AnalyzeRequest(
        prompt="x" * MAX_PROMPT_CHARS,
        metadata=META,
    )

    assert len(request.prompt) == MAX_PROMPT_CHARS


def test_prompt_over_maximum_length_is_rejected():
    with pytest.raises(ValidationError):
        AnalyzeRequest(
            prompt="x" * (MAX_PROMPT_CHARS + 1),
            metadata=META,
        )


def test_document_at_maximum_length_is_accepted():
    document = ContextDocument(
        id="boundary-doc",
        text="x" * MAX_DOC_CHARS,
    )

    assert len(document.text) == MAX_DOC_CHARS


def test_document_over_maximum_length_is_rejected():
    with pytest.raises(ValidationError):
        ContextDocument(
            id="oversized-doc",
            text="x" * (MAX_DOC_CHARS + 1),
        )


def test_context_document_count_over_limit_is_rejected():
    documents = [
        {"id": f"doc-{index}", "text": "x"}
        for index in range(MAX_CONTEXT_DOCS + 1)
    ]

    with pytest.raises(ValidationError):
        AnalyzeRequest(
            prompt="Summarize these documents.",
            context_docs=documents,
            metadata=META,
        )