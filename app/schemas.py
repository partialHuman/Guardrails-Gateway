from typing import List

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.config import MAX_CONTEXT_DOCS, MAX_DOC_CHARS, MAX_PROMPT_CHARS
from app.core.findings import Decision  # noqa: F401  (re-exported)


# ==========================================================
# REQUEST MODELS
# ==========================================================

class ContextDocument(BaseModel):
    """Single retrieved context document."""

    id: str = Field(
        ...,
        min_length=1,
        description="Unique document identifier",
        examples=["doc-1"]
    )

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


class Metadata(BaseModel):
    """Metadata associated with the request."""

    app_id: str = Field(
        ...,
        examples=["chatbot-prod"]
    )

    user_id: str = Field(
        ...,
        examples=["user-123"]
    )

    request_id: str = Field(
        ...,
        examples=["req-001"]
    )

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

    sanitized_context_docs: List[ContextDocument] = Field(
        ...,
        description="Context documents after redaction. Quarantined documents are NOT included."
    )

    quarantined_doc_ids: List[str] = Field(
        default_factory=list,
        description="Documents dropped because they contained an injection"
    )

    reasons: List[Reason]

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
