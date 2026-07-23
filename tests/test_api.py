from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_policy():

    response = client.get("/policy")

    assert response.status_code == 200


def test_analyze():

    payload = {

        "prompt": "Hello",

        "context_docs": [],

        "metadata": {

            "app_id": "demo",

            "user_id": "user",

            "request_id": "1"

        }

    }

    response = client.post(
        "/analyze",
        json=payload
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"] == "allow"

    assert data["risk_score"] == 0