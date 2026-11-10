import pytest
from fastapi.testclient import TestClient

from app.config import Settings, load_settings
from app.main import create_app
from app.models import MAX_BODY_LEN

TEST_KEY = "test-key-" + "x" * 32


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(Settings(api_key=TEST_KEY, enable_docs=False)))


def valid_email(**overrides) -> dict:
    email = {
        "sender": "Alice <alice@example.com>",
        "subject": "Hello",
        "body_text": "Hi there",
    }
    email.update(overrides)
    return email


def test_health_is_public(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_with_valid_key(client):
    response = client.post("/analyze", json=valid_email(), headers={"X-API-Key": TEST_KEY})
    assert response.status_code == 200
    body = response.json()
    assert 0 <= body["score"] <= 100
    assert body["verdict"] in {"safe", "suspicious", "malicious"}


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong"}, {"X-API-Key": ""}])
def test_analyze_rejects_missing_or_wrong_key(client, headers):
    response = client.post("/analyze", json=valid_email(), headers=headers)
    assert response.status_code == 401


def test_rejects_oversized_body(client):
    huge = valid_email(body_text="a" * (MAX_BODY_LEN + 1))
    response = client.post("/analyze", json=huge, headers={"X-API-Key": TEST_KEY})
    assert response.status_code == 422


def test_rejects_unknown_fields(client):
    response = client.post(
        "/analyze", json=valid_email(evil="1"), headers={"X-API-Key": TEST_KEY}
    )
    assert response.status_code == 422


@pytest.mark.parametrize("field", [{"attachments": []}, {"return_path": "x@y.com"}])
def test_unused_fields_are_not_accepted(client, field):
    # Data minimization: the API refuses data it would not use.
    response = client.post("/analyze", json=valid_email(**field), headers={"X-API-Key": TEST_KEY})
    assert response.status_code == 422


def test_docs_disabled_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_refuses_to_start_without_strong_key(monkeypatch):
    monkeypatch.setenv("API_KEY", "short")
    with pytest.raises(RuntimeError):
        load_settings()
