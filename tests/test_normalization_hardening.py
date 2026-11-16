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
from app.core.findings import ACTION_QUARANTINE, Decision
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


# ======================================================================================
# SEC-002 Tests: LRU Cache Removal and Memory Unretention
# ======================================================================================


def test_canonicalize_has_no_lru_cache():
    """Verify that canonicalize does not have an lru_cache wrapper attached."""
    assert not hasattr(canonicalize, "cache_info")
    assert not hasattr(canonicalize, "cache_clear")


def test_canonicalize_repeated_identical_and_unique_inputs():
    """Repeated identical and unique large inputs normalize correctly without memory retention."""
    text1 = "Hello \u00a0 world! \uff29gnore"
    res1 = canonicalize(text1)
    res2 = canonicalize(text1)
    assert res1 == res2 == "Hello   world! Ignore"

    # Many unique large inputs (each 30,000 characters)
    tracemalloc.start()
    tracemalloc.reset_peak()

    for i in range(100):
        unique_text = f"prefix-{i:05d}-" + ("a" * 30000)
        norm = canonicalize(unique_text)
        assert len(norm) == 30013

    # Force garbage collection to ensure no global cache retention
    import gc
    gc.collect()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    current_mb = current / (1024 * 1024)
    # Current memory should be near zero (< 0.5 MB) because no entries are retained
    assert current_mb < 0.5, f"Uncollected retained memory too high: {current_mb:.2f} MB"


def test_canonicalize_exceptions_propagate_properly():
    """NormalizationLimitExceeded propagates as expected without caching."""
    with pytest.raises(NormalizationLimitExceeded) as exc_info:
        canonicalize("\uFDFA" * 3000, max_chars=1000)
    assert exc_info.value.limit == 1000
    assert exc_info.value.length == 54000


# ======================================================================================
# SEC-003 Tests: Normalized Request-Wide Budget Enforcement
# ======================================================================================


def test_cumulative_request_budget_boundary_just_below_exact_and_above(monkeypatch):
    """Test prompt + docs cumulative normalized lengths: just below, exact, and above limit."""
    from app.core import analyzer
    # Set safe, predictable test limits
    monkeypatch.setattr(analyzer, "MAX_NORMALIZED_PROMPT_CHARS", 10_000)
    monkeypatch.setattr(analyzer, "MAX_NORMALIZED_DOC_CHARS", 20_000)
    monkeypatch.setattr(analyzer, "MAX_NORMALIZED_REQUEST_CHARS", 20_000)

    prompt = "P " * 2500  # 5,000 normalized chars

    # 1. Just below limit: 5000 + 14900 = 19900 <= 20000
    doc_below = ("doc-below", "word " * 2980)  # 14,900 chars
    res_below = evaluate(prompt, [doc_below])
    assert res_below.decision == Decision.ALLOW
    assert res_below.scan_complete is True
    assert len(res_below.quarantined_doc_ids) == 0

    # 2. Exactly at limit: 5000 + 15000 = 20000 <= 20000
    doc_exact = ("doc-exact", "word " * 3000)  # 15,000 chars
    res_exact = evaluate(prompt, [doc_exact])
    assert res_exact.decision == Decision.ALLOW
    assert res_exact.scan_complete is True
    assert len(res_exact.quarantined_doc_ids) == 0

    # 3. Immediately above limit: 5000 + 15001 = 20001 > 20000
    doc_above = ("doc-above", "word " * 3000 + "x")  # 15,001 chars
    res_above = evaluate(prompt, [doc_above])
    assert res_above.decision == Decision.BLOCK
    assert res_above.scan_complete is False
    assert "doc-above" in res_above.quarantined_doc_ids
    assert any(f.rule_id == LIMIT_RULE_ID for f in res_above.findings)


def test_ten_5000_char_amplified_documents_cumulative_exhaustion():
    """Ten 5,000-char \uFDFA documents expand to 900,000 normalized characters total.

    Each document individually expands to 90,000 chars (<= MAX_NORMALIZED_DOC_CHARS 100,000).
    Prompt = 10 chars.
    Docs 0..4: 5 * 90,000 = 450,000 chars (<= 500,000).
    Doc 5: 450,000 + 90,000 = 540,000 chars (> 500,000).
    Doc 5 must be quarantined and fail closed; docs 6..9 quarantined unseen.
    """
    doc_text = "\uFDFA" * 5000  # expands to 90,000 normalized chars
    docs = [(f"doc-{i}", doc_text) for i in range(10)]

    eval_res = evaluate("hello", docs)
    assert eval_res.decision == Decision.BLOCK
    assert eval_res.scan_complete is False

    # Docs 0..4 pass cumulative check
    assert len(eval_res.sanitized_docs) == 5
    # Docs 5..9 quarantined (doc-5 triggered limit, doc-6..9 quarantined unseen)
    assert eval_res.quarantined_doc_ids == [f"doc-{i}" for i in range(5, 10)]

    limit_findings = [f for f in eval_res.findings if f.rule_id == LIMIT_RULE_ID]
    assert len(limit_findings) == 1
    assert limit_findings[0].source == "doc-5"
    assert limit_findings[0].action == ACTION_QUARANTINE


def test_single_document_exceeds_individual_limit_fails_closed():
    """A document that independently exceeds its individual normalized limit is quarantined."""
    doc_oversized = "\uFDFA" * 6000  # 108,000 chars > MAX_NORMALIZED_DOC_CHARS (100,000)
    normal_doc = "Normal document content"
    docs = [("doc-indiv-over", doc_oversized), ("doc-subsequent", normal_doc)]

    eval_res = evaluate("hello", docs)
    assert eval_res.decision == Decision.BLOCK
    assert eval_res.scan_complete is False
    assert "doc-indiv-over" in eval_res.quarantined_doc_ids
    # Subsequent document must be quarantined unseen
    assert "doc-subsequent" in eval_res.quarantined_doc_ids
    assert len(eval_res.sanitized_docs) == 0


def test_document_individually_passes_but_exceeds_cumulative_request_limit(monkeypatch):
    """Document individually within limit, but pushes cumulative total over request limit."""
    from app.core import analyzer
    monkeypatch.setattr(analyzer, "MAX_NORMALIZED_PROMPT_CHARS", 40_000)
    monkeypatch.setattr(analyzer, "MAX_NORMALIZED_DOC_CHARS", 100_000)
    monkeypatch.setattr(analyzer, "MAX_NORMALIZED_REQUEST_CHARS", 150_000)

    prompt = "prompt text " * 1000  # 12,000 chars
    doc1 = ("doc-1", "valid doc text " * 4000)  # 60,000 chars
    doc2 = ("doc-2", "valid doc text " * 6000)  # 90,000 chars (12k + 60k + 90k = 162k > 150k)
    doc3 = ("doc-3", "valid doc text " * 1000)  # 15,000 chars

    eval_res = evaluate(prompt, [doc1, doc2, doc3])
    assert eval_res.decision == Decision.BLOCK
    assert eval_res.scan_complete is False

    # doc-1 processed
    assert len(eval_res.sanitized_docs) == 1
    assert eval_res.sanitized_docs[0][0] == "doc-1"

    # doc-2 exceeded cumulative budget (12k + 60k + 90k = 162k > 150k)
    # doc-3 quarantined unseen
    assert eval_res.quarantined_doc_ids == ["doc-2", "doc-3"]
    assert any(f.rule_id == LIMIT_RULE_ID and f.source == "doc-2" for f in eval_res.findings)


def test_api_endpoint_blocks_cumulative_budget_exhaustion(monkeypatch):
    """Verify that HTTP API endpoint returns 200 with Decision.BLOCK on cumulative budget exhaustion."""
    from app.core import analyzer
    monkeypatch.setattr(analyzer, "MAX_NORMALIZED_REQUEST_CHARS", 25_000)

    payload = {
        "prompt": "Inspect these documents",
        "context_docs": [
            {"id": "doc-a", "text": "A" * 15000},
            {"id": "doc-b", "text": "B" * 15000},
        ],
        "metadata": {
            "app_id": "test-app",
            "user_id": "test-user",
            "request_id": "req-cumul-1",
        },
    }

    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "block"
    assert data["risk_score"] == 100
    assert "doc-b" in data["quarantined_doc_ids"]
    assert any(r["rule"] == LIMIT_RULE_ID for r in data["reasons"])


def test_legitimate_multilingual_documents_continue_to_work():
    """Legitimate multilingual documents in French, German, Russian, Arabic, Hindi, Chinese, Japanese."""
    multilingual_docs = [
        ("doc-fr", "Bonjour le monde! Ceci est un document sécurisé."),
        ("doc-de", "Übermäßige Straßengröße führt zu Verzögerungen."),
        ("doc-ru", "Съешь же ещё этих мягких французских булок."),
        ("doc-ar", "مرحبا بكم في بوابة الحماية المتقدمة."),
        ("doc-hi", "नमस्ते दुनिया, यह एक सुरक्षित गेटवे है।"),
        ("doc-zh", "这是一个安全网关的测试用例。"),
        ("doc-ja", "これはセキュリティゲートウェイのテストです。"),
    ]

    eval_res = evaluate("Multilingual check prompt", multilingual_docs)
    assert eval_res.decision == Decision.ALLOW
    assert eval_res.scan_complete is True
    assert len(eval_res.quarantined_doc_ids) == 0
    assert len(eval_res.sanitized_docs) == len(multilingual_docs)


def test_prompt_alone_exceeding_request_budget_fails_closed(monkeypatch):
    """When MAX_NORMALIZED_REQUEST_CHARS is configured lower than prompt length."""
    from app.core import analyzer
    monkeypatch.setattr(analyzer, "MAX_NORMALIZED_REQUEST_CHARS", 50)
    prompt = "A" * 100
    res = evaluate(prompt)
    assert res.decision == Decision.BLOCK
    assert res.scan_complete is False
    assert any(f.rule_id == LIMIT_RULE_ID for f in res.findings)


def test_legacy_mock_detectors_without_canonical_argument_handled_gracefully(monkeypatch):
    """Ensure custom/mocked detector wrappers without canonical parameter work cleanly."""
    from app.core import analyzer

    orig_inj = analyzer.detect_prompt_injection
    orig_apply = analyzer.apply_findings

    # Mock that only takes (text, source, *, budget=None)
    def legacy_inj(text, source="prompt", *, budget=None):
        return orig_inj(text, source, budget=budget)

    def legacy_apply(text, findings):
        return orig_apply(text, findings)

    monkeypatch.setattr(analyzer, "detect_prompt_injection", legacy_inj)
    monkeypatch.setattr(analyzer, "apply_findings", legacy_apply)

    res = evaluate("clean prompt here")
    assert res.decision == Decision.ALLOW
