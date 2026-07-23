from fastapi import FastAPI
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.core.analyzer import analyze_request
from app.core.policy import POLICY
from app.config import API_TITLE, API_VERSION

from app.config import (
    API_TITLE,
    API_VERSION,
    API_DESCRIPTION,
)

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=API_DESCRIPTION
)


@app.get("/policy")
def get_policy():
    """
    Returns the active guardrails policy.
    """
    return POLICY


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    """
    Analyze a prompt and optional RAG context.

    Returns:
    - decision
    - risk_score
    - risk_tags
    - sanitized_prompt
    - sanitized_context_docs
    - reasons
    """
    return analyze_request(request)