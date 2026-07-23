"""
Core analysis engine for SentraGuard Lite.
"""

from __future__ import annotations

from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    ContextDocument,
    Decision,
    Reason,
)

from app.core.detectors import (
    detect_prompt_injection,
    detect_pii,
    detect_rag_injection,
)

from app.core.sanitizer import (
    sanitize_prompt,
    sanitize_document,
)

from app.core.scorer import calculate_score

from app.core.policy import (
    BLOCK_THRESHOLD,
    TRANSFORM_THRESHOLD,
)

from app.core.logger import logger


def decide(score: int) -> Decision:
    """
    Determine the final policy decision based on the risk score.
    """

    if score >= BLOCK_THRESHOLD:
        return Decision.BLOCK

    if score >= TRANSFORM_THRESHOLD:
        return Decision.TRANSFORM

    return Decision.ALLOW


def analyze_request(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze an incoming request.

    Workflow:
        1. Analyze prompt
        2. Analyze context documents
        3. Compute score
        4. Decide action
        5. Sanitize content if required
        6. Return response
    """

    reasons: list[Reason] = []

    # -----------------------------------------------------
    # Prompt Analysis
    # -----------------------------------------------------

    reasons.extend(
        detect_prompt_injection(request.prompt)
    )

    reasons.extend(
        detect_pii(request.prompt)
    )

    # -----------------------------------------------------
    # Context Document Analysis
    # -----------------------------------------------------

    for doc in request.context_docs:

        reasons.extend(
            detect_rag_injection(doc.text)
        )

        reasons.extend(
            detect_pii(doc.text)
        )

    # -----------------------------------------------------
    # Calculate Risk
    # -----------------------------------------------------

    risk_score, risk_tags = calculate_score(reasons)

    decision = decide(risk_score)

    # -----------------------------------------------------
    # Sanitization
    # -----------------------------------------------------

    if decision == Decision.ALLOW:

        sanitized_prompt = request.prompt

        sanitized_docs = request.context_docs

    else:

        sanitized_prompt = sanitize_prompt(
            request.prompt
        )

        sanitized_docs = [

            ContextDocument(

                id=doc.id,

                text=sanitize_document(doc.text)

            )

            for doc in request.context_docs

        ]

    # -----------------------------------------------------
    # Logging
    # -----------------------------------------------------

    logger.info(
        {
            "request_id": request.metadata.request_id,
            "decision": decision.value,
            "risk_score": risk_score,
            "risk_tags": risk_tags,
        }
    )

    # -----------------------------------------------------
    # Response
    # -----------------------------------------------------

    return AnalyzeResponse(

        decision=decision,

        risk_score=risk_score,

        risk_tags=risk_tags,

        sanitized_prompt=sanitized_prompt,

        sanitized_context_docs=sanitized_docs,

        reasons=reasons,

    )