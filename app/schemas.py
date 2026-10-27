from typing import List

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from app.config import MAX_CONTEXT_DOCS, MAX_DOC_CHARS, MAX_PROMPT_CHARS
from app.core.findings import Decision  # noqa: F401  (re-exported)

# Identifiers (app / user / document ids) are echoed into responses and logs,
# so they are length-bounded and must not contain control characters.
MAX_IDENTIFIER_CHARS = 128


def _reject_control_characters(value: str, field_name: str) -> str:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{field_name} must not contain control characters")

    return value


# ==========================================================
# REQUEST MODELS
# ==========================================================

class ContextDocument(BaseModel):
    """Single retrieved context document."""

    id: str = Field(
        ...,
        min_length=1,
        max_length=MAX_IDENTIFIER_CHARS,
        description="Unique document identifier",
        examples=["doc-1"]
    )

    @field_validator("id")
    @classmethod
    def validate_document_id(cls, value: str) -> str:
        return _reject_control_characters(value, "id")

    text: str = Field(
        ...,
        max_length=MAX_DOC_CHARS,
        description="Retrieved document text"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "doc-1",
                "text": "This document contains company policy."
            }
        }
    )


class SanitizedDocument(BaseModel):
    """
    Context document as returned in a response.

    Deliberately has no length cap: redaction can make text LONGER than the
    input (``a@b.co`` -> ``[REDACTED_EMAIL]``), and re-applying the request
    limit to the response turned valid PII-dense documents into HTTP 500s.
    """

    id: str

    text: str


class Metadata(BaseModel):
    """Metadata associated with the request."""

    app_id: str = Field(
        ...,
        max_length=MAX_IDENTIFIER_CHARS,
        examples=["chatbot-prod"]
    )

    user_id: str = Field(
        ...,
        max_length=MAX_IDENTIFIER_CHARS,
        examples=["user-123"]
    )

    @field_validator("app_id")
    @classmethod
    def validate_app_id(cls, value: str) -> str:
        return _reject_control_characters(value, "app_id")

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, value: str) -> str:
        return _reject_control_characters(value, "user_id")


    request_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        examples=["req-001"],
    )

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("request_id must not be empty or whitespace-only")

        return _reject_control_characters(value, "request_id")


    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "app_id": "chatbot-prod",
                "user_id": "user-123",
                "request_id": "req-001"
            }
        }
    )


class AnalyzeRequest(BaseModel):
    """Incoming analyze request."""

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=MAX_PROMPT_CHARS,
        description="User prompt"
    )

    context_docs: List[ContextDocument] = Field(
        default_factory=list,
        max_length=MAX_CONTEXT_DOCS,
        description="Optional retrieved documents (ids must be unique)"
    )

    metadata: Metadata

    @model_validator(mode="after")
    def unique_doc_ids(self):
        ids = [doc.id for doc in self.context_docs]

        if len(ids) != len(set(ids)):
            raise ValueError("context_docs ids must be unique")

        return self

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "prompt": "Summarize this document.",
                "context_docs": [
                    {
                        "id": "doc-1",
                        "text": "Company handbook."
                    }
                ],
                "metadata": {
                    "app_id": "chatbot-prod",
                    "user_id": "user-123",
                    "request_id": "req-001"
                }
            }
        }
    )


# ==========================================================
# RESPONSE MODELS
# ==========================================================

class Reason(BaseModel):
    """Why a detector was triggered."""

    tag: str = Field(
        ...,
        examples=["prompt_injection"]
    )

    evidence: str = Field(
        ...,
        examples=["Matched phrase: 'ignore previous instructions'"]
    )

    source: str = Field(
        "prompt",
        description="'prompt' or the id of the context document",
        examples=["prompt", "doc-1"]
    )

    rule: str = Field(
        "",
        description="Id of the rule that fired (see GET /policy)",
        examples=["override_instructions"]
    )


class AnalyzeResponse(BaseModel):
    """Response returned by POST /analyze."""

    decision: Decision

    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Overall calculated risk score"
    )

    risk_tags: List[str]

    sanitized_prompt: str

    sanitized_context_docs: List[SanitizedDocument] = Field(
        ...,
        description="Context documents after redaction. Quarantined documents are NOT included."
    )

    quarantined_doc_ids: List[str] = Field(
        default_factory=list,
        description="Documents dropped because they contained an injection"
    )

    reasons: List[Reason]

    policy_version: str = Field(
        "",
        description="Version of the detection policy that produced this decision (see GET /policy)",
        examples=["3"],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "decision": "transform",
                "risk_score": 65,
                "risk_tags": [
                    "pii",
                    "prompt_injection"
                ],
                "sanitized_prompt": "[REMOVED_PROMPT_INJECTION], mail [REDACTED_EMAIL]",
                "sanitized_context_docs": [
                    {
                        "id": "doc-1",
                        "text": "Company handbook."
                    }
                ],
                "quarantined_doc_ids": [],
                "policy_version": "3",
                "reasons": [
                    {
                        "tag": "prompt_injection",
                        "evidence": "Matched phrase: 'Ignore previous instructions'",
                        "source": "prompt",
                        "rule": "override_instructions"
                    },
                    {
                        "tag": "pii",
                        "evidence": "Email address detected",
                        "source": "prompt",
                        "rule": "email"
                    }
                ]
            }
        }
    )
