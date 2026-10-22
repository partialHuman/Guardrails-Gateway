
from fastapi.testclient import TestClient

from app.main import app, rate_limiter

client = TestClient(app)

EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}


def assert_security_headers(response):
    for name, value in EXPECTED_HEADERS.items():
        assert response.headers[name] == value


def test_policy_response_has_security_headers():
    response = client.get("/policy")

    assert response.status_code == 200
    assert_security_headers(response)


def test_validation_error_has_security_headers():
    response = client.post("/analyze", json={})

    assert response.status_code == 422
    assert_security_headers(response)


def test_rate_limited_response_has_security_headers(monkeypatch):
    monkeypatch.setattr(rate_limiter, "max_requests", 1)
    rate_limiter._requests.clear()

    try:
        first = client.get("/policy")
        second = client.get("/policy")

        assert first.status_code == 200
        assert second.status_code == 429
        assert_security_headers(second)
    finally:
        rate_limiter._requests.clear()
