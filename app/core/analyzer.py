"""
Core analysis engine for SentraGuard Lite.

`evaluate()` is the pure engine (no web framework needed).
`analyze_request()` adapts it to the API request/response models.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Sequence

from app.core.detectors import (
    detect_pii,
    detect_prompt_injection,
    detect_rag_injection,
)
from app.core.findings import (
    ACTION_QUARANTINE,
    ACTION_REDACT,
    Decision,
    Finding,
)
from app.core.logger import logger
from app.core.policy import (
    BLOCK_THRESHOLD,
    TRANSFORM_THRESHOLD,
)
from app.core.sanitizer import apply_findings
from app.core.scorer import calculate_score
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    ContextDocument,
    Reason,
)


def decide(score: int) -> Decision:
    """
    Determine the policy decision implied by a risk score.
    """

    if score >= BLOCK_THRESHOLD:
        return Decision.BLOCK

    if score >= TRANSFORM_THRESHOLD:
        return Decision.TRANSFORM

    return Decision.ALLOW


@dataclass
class Evaluation:
    """Result of running the full pipeline on one request."""

    decision: Decision
    risk_score: int
    risk_tags: list[str]
    sanitized_prompt: str
    sanitized_docs: list[tuple[str, str]]
    quarantined_doc_ids: list[str]
    findings: list[Finding] = field(default_factory=list)


def evaluate(
    prompt: str,
    docs: Sequence[tuple[str, str]] = (),
) -> Evaluation:
    """
    Analyze a prompt and optional (doc_id, text) context documents.

    Workflow:
        1. Detect prompt injection + PII in the prompt
        2. Detect injection + PII in every context document
        3. Score all findings
        4. Redact the prompt, redact or quarantine documents
        5. Decide

    Decision semantics: the score sets the base decision, but if ANY
    content was changed (a redaction or a dropped document) the decision
    is at least TRANSFORM, so callers always know to use the sanitized
    output instead of the original.
    """

    # -----------------------------------------------------
    # Prompt
    # -----------------------------------------------------

    prompt_findings = (
        detect_prompt_injection(prompt, "prompt")
        + detect_pii(prompt, "prompt")
    )

    all_findings = list(prompt_findings)

    sanitized_prompt = apply_findings(prompt, prompt_findings)

    modified = bool(prompt_findings)

    # -----------------------------------------------------
    # Context documents
    # -----------------------------------------------------

    sanitized_docs: list[tuple[str, str]] = []

    quarantined: list[str] = []

    for doc_id, text in docs:

        doc_findings = (
            detect_rag_injection(text, doc_id)
            + detect_pii(text, doc_id)
        )

        all_findings.extend(doc_findings)

        if any(f.action == ACTION_QUARANTINE for f in doc_findings):
            quarantined.append(doc_id)
            modified = True
            continue

        redactions = [f for f in doc_findings if f.action == ACTION_REDACT]

        if redactions:
            modified = True

        sanitized_docs.append((doc_id, apply_findings(text, redactions)))

    # -----------------------------------------------------
    # Score + decision
    # -----------------------------------------------------

    risk_score, risk_tags = calculate_score(all_findings)

    decision = decide(risk_score)

    if modified and decision == Decision.ALLOW:
        decision = Decision.TRANSFORM

    return Evaluation(
        decision=decision,
        risk_score=risk_score,
        risk_tags=risk_tags,
        sanitized_prompt=sanitized_prompt,
        sanitized_docs=sanitized_docs,
        quarantined_doc_ids=quarantined,
        findings=all_findings,
    )


def build_reasons(findings: Sequence[Finding]) -> list[Reason]:
    """
    One Reason per (source, rule); repeated matches are summarised.
    """

    grouped: dict[tuple[str, str], list[Finding]] = {}

    for finding in findings:
        grouped.setdefault((finding.source, finding.rule_id), []).append(finding)

    reasons: list[Reason] = []

    for (source, rule_id), group in grouped.items():

        first = group[0]

        evidence = first.evidence

        if len(group) > 1:
            evidence += f" (+{len(group) - 1} more)"

        reasons.append(
            Reason(
                tag=first.tag,
                evidence=evidence,
                source=source,
                rule=rule_id,
            )
        )

    return reasons


def analyze_request(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze an incoming API request.
    """

    result = evaluate(
        request.prompt,
        [(doc.id, doc.text) for doc in request.context_docs],
    )

    # -----------------------------------------------------
    # Logging (metadata only - never prompt or document text)
    # -----------------------------------------------------

    logger.info(
        json.dumps(
            {
                "request_id": request.metadata.request_id,
                "app_id": request.metadata.app_id,
                "user_id": request.metadata.user_id,
                "decision": result.decision.value,
                "risk_score": result.risk_score,
                "risk_tags": result.risk_tags,
                "rules": sorted({f.rule_id for f in result.findings}),
                "quarantined_doc_ids": result.quarantined_doc_ids,
            }
        )
    )

    # -----------------------------------------------------
    # Response
    # -----------------------------------------------------

    return AnalyzeResponse(
        decision=result.decision,
        risk_score=result.risk_score,
        risk_tags=result.risk_tags,
        sanitized_prompt=result.sanitized_prompt,
        sanitized_context_docs=[
            ContextDocument(id=doc_id, text=text)
            for doc_id, text in result.sanitized_docs
        ],
        quarantined_doc_ids=result.quarantined_doc_ids,
        reasons=build_reasons(result.findings),
    )
