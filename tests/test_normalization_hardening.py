"""
Regression and adversarial tests for BASE-002 (Unicode Normalization Amplification).

Covers:
- Normal ASCII input (unaffected)
- Legitimate multilingual Unicode (French, German, Russian, Arabic, Hindi, Chinese, Japanese)
- Normalization expansion amplification (e.g. \uFDFA expanding 18x)
- Safe normalized limits enforcement on prompt (40,000 chars)
- Safe normalized limits enforcement on documents (100,000 chars)
- Request-level normalized characters budget (500,000 chars)
- Fail-closed behavior (Decision.BLOCK, INCOMPLETE_SCAN_PROMPT, quarantine)
- Repeated combining diacritics / Zalgo text bounded execution
- CPU time and memory boundedness
- API integration testing via TestClient
"""

import time
import tracemalloc
import pytest
from fastapi.testclient import TestClient

from app.config import (
    MAX_NORMALIZED_DOC_CHARS,
    MAX_NORMALIZED_PROMPT_CHARS,
    MAX_NORMALIZED_REQUEST_CHARS,
)
from app.core.analyzer import evaluate
from app.core.detectors import detect_pii, detect_prompt_injection, detect_rag_injection
from app.core.findings import Decision
from app.core.policy import INCOMPLETE_SCAN_PROMPT, LIMIT_RULE_ID
from app.main import app
from app.utils.text import NormalizationLimitExceeded, canonicalize

client = TestClient(app)
AUTH_HEADERS = {"x-api-key": "test-key"}


def test_ascii_normal_text_unaffected():
    text = "Hello world! This is ordinary ASCII text for SentraGuard Lite."
    assert canonicalize(text, max_chars=1000) == text


@pytest.mark.parametrize(
    "text,expected_sub",
    [
        ("Bonjour le monde! Ça va très bien, merci!", "Bonjour"),
        ("Übermäßige Straßengröße führt zu Verzögerungen!", "Straßengröße"),
        ("Съешь же ещё этих мягких французских булок", "французских"),
        ("مرحبا بكم في بوابة الحماية المتقدمة", "الحماية"),
        ("नमस्ते दुनिया, यह एक सुरक्षित गेटवे है", "सुरक्षित"),
        ("这是一个安全网关的测试用例文本", "安全网关"),
        ("これはセキュリティゲートウェイのテストです", "セキュリティ"),
    ],
)
def test_legitimate_multilingual_unicode_preserved(text, expected_sub):
    res = canonicalize(text, max_chars=MAX_NORMALIZED_PROMPT_CHARS)
    assert expected_sub in res

    eval_res = evaluate(text)
    assert eval_res.decision == Decision.ALLOW
    assert expected_sub in eval_res.sanitized_prompt


def test_normalization_limit_exceeded_exception():
    with pytest.raises(NormalizationLimitExceeded) as exc_info:
        canonicalize("\uFDFA" * 1000, max_chars=5000)

    assert exc_info.value.length == 18000
    assert exc_info.value.limit == 5000


def test_prompt_normalization_expansion_fails_closed():
    # 2500 \uFDFA characters raw = 45,000 normalized characters (> MAX_NORMALIZED_PROMPT_CHARS 40,000)
    amplified_prompt = "\uFDFA" * 2500

    findings = detect_prompt_injection(amplified_prompt)
    assert any(f.rule_id == LIMIT_RULE_ID for f in findings)

    eval_res = evaluate(amplified_prompt)
    assert eval_res.decision == Decision.BLOCK
    assert eval_res.sanitized_prompt == INCOMPLETE_SCAN_PROMPT
    assert any(f.rule_id == LIMIT_RULE_ID for f in eval_res.findings)


def test_prompt_near_boundary_below_limit_passes():
    # 2000 \uFDFA characters = 36,000 normalized characters (< MAX_NORMALIZED_PROMPT_CHARS 40,000)
    prompt = "\uFDFA" * 2000
    eval_res = evaluate(prompt)
    assert eval_res.decision == Decision.ALLOW
    assert eval_res.sanitized_prompt != INCOMPLETE_SCAN_PROMPT


def test_document_normalization_expansion_quarantines_and_blocks():
    # 6000 \uFDFA characters = 108,000 normalized characters (> MAX_NORMALIZED_DOC_CHARS 100,000)
    amplified_doc = "\uFDFA" * 6000

    findings = detect_rag_injection(amplified_doc, source="doc-hostile")
    assert any(f.rule_id == LIMIT_RULE_ID for f in findings)

    eval_res = evaluate("harmless query", [("doc-hostile", amplified_doc)])
    assert eval_res.decision == Decision.BLOCK
    assert "doc-hostile" in eval_res.quarantined_doc_ids
    assert not any(doc_id == "doc-hostile" for doc_id, _ in eval_res.sanitized_docs)


def test_document_near_boundary_below_limit_passes():
    # 5000 \uFDFA characters = 90,000 normalized characters (< MAX_NORMALIZED_DOC_CHARS 100,000)
    doc_text = "\uFDFA" * 5000
    eval_res = evaluate("harmless query", [("doc-ok", doc_text)])
    assert eval_res.decision == Decision.ALLOW
    assert "doc-ok" not in eval_res.quarantined_doc_ids
    assert any(doc_id == "doc-ok" for doc_id, _ in eval_res.sanitized_docs)


def test_pii_detector_handles_normalization_expansion():
    amplified = "\uFDFA" * 6000
    findings = detect_pii(amplified, source="doc-1")
    assert any(f.rule_id == LIMIT_RULE_ID for f in findings)


def test_repeated_combining_characters_bounded():
    # Zalgo text: base char followed by hundreds of combining accents
    zalgo = "e" + "\u0301" * 1000
    norm = canonicalize(zalgo, max_chars=10000)
    assert len(norm) > 0
    assert norm.startswith("é") or norm.startswith("e")


def test_request_level_total_normalized_budget_exhaustion():
    # Multiple documents that individually pass but collectively exceed MAX_NORMALIZED_REQUEST_CHARS
    doc1 = "Normal document content. " * 3000
    docs = [(f"doc-{i}", doc1) for i in range(10)]

    # Lower request budget temporarily to verify early cut-off
    from app.core import analyzer
    orig_budget = analyzer.MAX_NORMALIZED_REQUEST_CHARS
    try:
        analyzer.MAX_NORMALIZED_REQUEST_CHARS = 100_000
        eval_res = evaluate("hello", docs)
        assert eval_res.decision == Decision.BLOCK
        # Some later documents must be quarantined without being scanned
        assert len(eval_res.quarantined_doc_ids) > 0
    finally:
        analyzer.MAX_NORMALIZED_REQUEST_CHARS = orig_budget


def test_cpu_and_memory_boundedness_on_max_amplification():
    # Full 50,000 char maximum document composed entirely of \uFDFA
    max_doc = "\uFDFA" * 50000

    tracemalloc.start()
    t0 = time.perf_counter()
    eval_res = evaluate("check document", [("doc-max", max_doc)])
    t1 = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    elapsed = t1 - t0
    peak_mb = peak / (1024 * 1024)

    # Must complete in under 1.5 seconds and consume < 25 MB RAM (was 53+ MB before fix)
    assert elapsed < 1.5, f"Evaluation took too long: {elapsed:.2f}s"
    assert peak_mb < 25.0, f"Peak memory too high: {peak_mb:.2f} MB"
    assert eval_res.decision == Decision.BLOCK
    assert "doc-max" in eval_res.quarantined_doc_ids


def test_api_endpoint_blocks_amplified_payload_gracefully():
    # Test through FastAPI HTTP client
    amplified_doc = "\uFDFA" * 6000
    payload = {
        "prompt": "Hello assistant",
        "context_docs": [{"id": "doc-amp", "text": amplified_doc}],
        "metadata": {
            "app_id": "test-app",
            "user_id": "test-user",
            "request_id": "req-amp-1",
        },
    }

    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "block"
    assert data["risk_score"] == 100
    assert any(r["rule"] == LIMIT_RULE_ID for r in data["reasons"])
    assert "doc-amp" in data["quarantined_doc_ids"]
