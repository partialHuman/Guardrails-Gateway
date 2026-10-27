"""
Core analysis engine for SentraGuard Lite.

`evaluate()` is the pure engine (no web framework needed).
`analyze_request()` adapts it to the API request/response models.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Sequence

from app.core.detectors import (
    detect_pii,
    limit_finding,
    detect_prompt_injection,
    detect_rag_injection,
)
from app.core.findings import (
    ACTION_QUARANTINE,
    ACTION_REDACT,
    Decision,
    Finding,
    ScanBudget,
)
from app.core.logger import logger
from app.core.policy import (
    BLOCK_THRESHOLD,
    INCOMPLETE_SCAN_PROMPT,
    MAX_FINDINGS_PER_REQUEST,
    POLICY_VERSION,
    TRANSFORM_THRESHOLD,
)
from app.core.sanitizer import apply_findings
from app.core.scorer import calculate_score
from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    Reason,
    SanitizedDocument,
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
    policy_version: str = POLICY_VERSION
    # False when the finding budget ran out: the prompt and/or documents were
    # NOT fully scanned. Such a result is always BLOCK (see evaluate()).
    scan_complete: bool = True


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

    Resource bound: all matches are reported and redacted (no per-rule
    cap), but the request as a whole may produce at most
    MAX_FINDINGS_PER_REQUEST findings, counted across the prompt and every
    document and across injection AND PII detection. One ScanBudget is
    shared by all detector calls and is enforced INSIDE them: a detector
    stops generating findings the moment the budget is spent, so nothing is
    collected and then discarded.

    When the budget runs out the scan is incomplete, and the result fails
    closed:

    * the decision is always BLOCK;
    * if the PROMPT was not fully scanned, ``sanitized_prompt`` is a fixed
      placeholder containing none of the caller's text (a half-redacted
      prompt must never look like safe output);
    * a DOCUMENT that was not fully scanned is quarantined whole, never
      forwarded partially redacted;
    * every later document is quarantined WITHOUT being scanned.

    A single synthetic ``scan_limit_exceeded`` finding records where the
    limit was hit. It is created outside the budget, so it is never counted
    against it. Note the budget bounds findings, not regex CPU time.
    """

    # -----------------------------------------------------
    # Prompt
    # -----------------------------------------------------

    budget = ScanBudget(MAX_FINDINGS_PER_REQUEST)

    # PII detection is a no-op when injection detection already used the
    # budget up (a spent budget makes a detector return immediately).
    prompt_findings = (
        detect_prompt_injection(prompt, "prompt", budget=budget)
        + detect_pii(prompt, "prompt", budget=budget)
    )

    all_findings = list(prompt_findings)

    if budget.exhausted:
        # Incomplete prompt scan: do NOT redact-and-trust what was seen so
        # far. Hand back a placeholder that carries none of the input.
        sanitized_prompt = INCOMPLETE_SCAN_PROMPT

        all_findings.append(limit_finding("prompt", quarantine=False))

        modified = True
    else:
        sanitized_prompt = apply_findings(prompt, prompt_findings)

        modified = bool(prompt_findings)

    # -----------------------------------------------------
    # Context documents
    # -----------------------------------------------------

    sanitized_docs: list[tuple[str, str]] = []

    quarantined: list[str] = []

    for doc_id, text in docs:

        if budget.exhausted:
            # Never forward a document we did not scan, and do not spend
            # any work scanning it: it is quarantined unseen.
            quarantined.append(doc_id)
            modified = True
            continue

        doc_findings = (
            detect_rag_injection(text, doc_id, budget=budget)
            + detect_pii(text, doc_id, budget=budget)
        )

        all_findings.extend(doc_findings)

        if budget.exhausted:
            # This document was cut short. Quarantine it WHOLE: its partial
            # findings are kept for reporting only, its text is dropped.
            all_findings.append(limit_finding(doc_id, quarantine=True))
            quarantined.append(doc_id)
            modified = True
            continue

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

    if budget.exhausted:
        # Explicit, independent of scoring weights and thresholds: an
        # incompletely scanned request is never allowed or merely
        # transformed.
        decision = Decision.BLOCK

    return Evaluation(
        decision=decision,
        risk_score=risk_score,
        risk_tags=risk_tags,
        sanitized_prompt=sanitized_prompt,
        sanitized_docs=sanitized_docs,
        quarantined_doc_ids=quarantined,
        findings=all_findings,
        policy_version=POLICY_VERSION,
        scan_complete=not budget.exhausted,
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

    start_time = time.perf_counter()

    result = evaluate(
        request.prompt,
        [(doc.id, doc.text) for doc in request.context_docs],
    )

    duration_ms = round((time.perf_counter() - start_time) * 1000, 3)

    # -----------------------------------------------------
    # Logging (metadata only - never prompt or document text)
    # -----------------------------------------------------


    logger.info(
        json.dumps(
            {
                "event": "analysis_completed",
                "request_id": request.metadata.request_id,
                "app_id": request.metadata.app_id,
                "decision": result.decision.value,
                "risk_score": result.risk_score,
                "risk_tags": result.risk_tags,
                "rules": sorted({f.rule_id for f in result.findings}),
                "quarantined_document_count": len(result.quarantined_doc_ids),
                "duration_ms": duration_ms,
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
            SanitizedDocument(id=doc_id, text=text)
            for doc_id, text in result.sanitized_docs
        ],
        quarantined_doc_ids=result.quarantined_doc_ids,
        reasons=build_reasons(result.findings),
        policy_version=result.policy_version,
    )
