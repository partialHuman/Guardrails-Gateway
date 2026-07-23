from enum import Enum
from typing import List

from pydantic import BaseModel, Field, ConfigDict


# ==========================================================
# ENUMS
# ==========================================================

class Decision(str, Enum):
    """Possible policy decisions."""

    ALLOW = "allow"
    TRANSFORM = "transform"
    BLOCK = "block"


# ==========================================================
# REQUEST MODELS
# ==========================================================

class ContextDocument(BaseModel):
    """Single retrieved context document."""

    id: str = Field(
        ...,
        description="Unique document identifier",
        examples=["doc-1"]
    )

    text: str = Field(
        ...,
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
        description="User prompt"
    )

    context_docs: List[ContextDocument] = Field(
        default_factory=list,
        description="Optional retrieved documents"
    )

    metadata: Metadata

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
        examples=["Matched phrase: ignore previous instructions"]
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

    sanitized_context_docs: List[ContextDocument]

    reasons: List[Reason]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "decision": "transform",
                "risk_score": 65,
                "risk_tags": [
                    "prompt_injection",
                    "pii"
                ],
                "sanitized_prompt": "Contact me at [REDACTED_EMAIL]",
                "sanitized_context_docs": [
                    {
                        "id": "doc-1",
                        "text": "Company handbook."
                    }
                ],
                "reasons": [
                    {
                        "tag": "prompt_injection",
                        "evidence": "Matched phrase: ignore previous instructions"
                    },
                    {
                        "tag": "pii",
                        "evidence": "Email detected"
                    }
                ]
            }
        }
    )