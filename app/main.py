from fastapi import FastAPI

from app.config import API_DESCRIPTION, API_TITLE, API_VERSION
from app.core.analyzer import analyze_request
from app.core.policy import POLICY
from app.schemas import AnalyzeRequest, AnalyzeResponse

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=API_DESCRIPTION,
)


@app.get("/policy")
def get_policy():
    """
    Returns the active guardrails policy: thresholds, scoring weights
    and every detection rule with its severity.
    """
    return POLICY


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    """
    Analyze a prompt and optional RAG context.

    Returns:
    - decision (allow / transform / block)
    - risk_score
    - risk_tags
    - sanitized_prompt
    - sanitized_context_docs (quarantined documents are removed)
    - quarantined_doc_ids
    - reasons (tag, rule, source, evidence)

    If decision is not "allow", use the sanitized fields instead of
    the originals.
    """
    return analyze_request(request)
