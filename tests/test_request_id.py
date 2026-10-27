"""SG-012: every response carries a correlation id, including rejected ones."""

import re

import pytest
from fastapi.testclient import TestClient

import app.config as config
from app import main
from app.core.rate_limiter import InMemoryRateLimiter
from app.main import app

GENERATED = re.compile(r"[0-9a-f]{32}")

KEY = "request-id-test-key-0123456789ab"

BODY = {
    "prompt": "hi",
    "context_docs": [],
    "metadata": {"app_id": "t", "user_id": "u", "request_id": "r-1"},
}


def test_a_request_id_is_generated_when_none_is_sent():
    response = TestClient(app).get("/health")

    assert GENERATED.fullmatch(response.headers["X-Request-ID"])


def test_ids_are_unique_per_request():
    client = TestClient(app)

    ids = {client.get("/health").headers["X-Request-ID"] for _ in range(5)}

    assert len(ids) == 5


@pytest.mark.parametrize("inbound", ["abc-123", "req_2026.10.24:7", "A" * 64])
def test_well_formed_inbound_id_is_echoed(inbound):
    response = TestClient(app).get("/health", headers={"X-Request-ID": inbound})

    assert response.headers["X-Request-ID"] == inbound


@pytest.mark.parametrize(
    "inbound",
    ["has spaces", "x" * 65, "<script>alert(1)</script>", "semi;colon", "a,b", "caf\u00e9"],
)
def test_malformed_inbound_id_is_replaced_not_echoed(inbound):
    response = TestClient(app).get(
        "/health", headers={"X-Request-ID": inbound.encode("latin-1", "replace")}
    )

    assert GENERATED.fullmatch(response.headers["X-Request-ID"])


def test_present_on_404_and_405():
    client = TestClient(app)

    assert "X-Request-ID" in client.get("/no-such-route").headers
    assert "X-Request-ID" in client.get("/analyze").headers


def test_present_on_401(monkeypatch):
    monkeypatch.setattr(config, "API_KEY", KEY)
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)

    response = TestClient(app).post("/analyze", json=BODY)

    assert response.status_code == 401
    assert "X-Request-ID" in response.headers


def test_present_on_413(monkeypatch):
    monkeypatch.setattr(main, "MAX_REQUEST_BODY_BYTES", 10)

    response = TestClient(app).post("/analyze", json=BODY)

    assert response.status_code == 413
    assert "X-Request-ID" in response.headers


def test_present_on_429(monkeypatch):
    monkeypatch.setattr(main, "rate_limiter", InMemoryRateLimiter(1, 60))
    client = TestClient(app)

    client.get("/policy")
    response = client.get("/policy")

    assert response.status_code == 429
    assert "X-Request-ID" in response.headers


def test_present_on_unhandled_500_and_matches_the_log(monkeypatch, caplog):
    def boom(_request):
        raise RuntimeError("boom")

    monkeypatch.setattr(main, "analyze_request", boom)

    with caplog.at_level("ERROR", logger="sentraguard"):
        response = TestClient(app, raise_server_exceptions=False).post(
            "/analyze", json=BODY, headers={"X-Request-ID": "trace-500"}
        )

    assert response.status_code == 500
    assert response.headers["X-Request-ID"] == "trace-500"
    assert "request_id=trace-500" in caplog.text
    assert "boom" not in response.text


def test_failed_auth_log_carries_the_request_id(monkeypatch, caplog):
    monkeypatch.setattr(config, "API_KEY", KEY)
    monkeypatch.setattr(config, "REQUIRE_AUTH", True)

    with caplog.at_level("WARNING", logger="sentraguard"):
        response = TestClient(app).post(
            "/analyze", json=BODY, headers={"X-Request-ID": "trace-401"}
        )

    assert response.status_code == 401
    assert "request_id=trace-401" in caplog.text
