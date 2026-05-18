from fastapi.testclient import TestClient

from postara.api import create_app
from postara.accounts import AccountService
from postara.users import UserService


def test_health_endpoint_returns_ok():
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_messages_rejects_unsupported_query_with_standard_error():
    accounts = AccountService()
    users = UserService()
    user, token = users.register(email="user@example.com", password="secret123", name="User")
    account = accounts.create_for_user(
        user_id=user.id,
        name="work",
        email="work@example.com",
        provider="gmail",
        password="app-password",
    )
    _key, api_key = users.create_api_key(user.id, name="Test")
    client = TestClient(create_app(accounts=accounts, users=users))

    response = client.get(
        f"/mailboxes/{account.name}/messages",
        headers={"X-Api-Key": api_key},
        params={"text_contains": "invoice"},
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "unsupported_provider_feature"
    assert body["error"]["request_id"].startswith("req_")
    assert body["error"]["details"] == {"fields": ["text_contains"]}
    assert response.headers["X-Request-Id"] == body["error"]["request_id"]


def test_missing_auth_uses_standard_401_message():
    client = TestClient(create_app())

    response = client.get("/mailboxes/1/messages")

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Authentication failed."


def test_owner_health_not_found_uses_request_id_for_non_owner():
    users = UserService()
    users.register(email="owner@example.com", password="secret123", name="Owner")
    member, token = users.register(email="member@example.com", password="secret123", name="Member")
    assert member.role == "member"
    client = TestClient(create_app(accounts=AccountService(), users=users))

    response = client.get(
        "/owner/health/detailed",
        headers={"Authorization": f"Bearer {token}", "X-Request-Id": "req_test_member"},
    )

    assert response.status_code == 404
    assert response.json()["error"]["request_id"] == "req_test_member"
    assert response.headers["X-Request-Id"] == "req_test_member"


def test_configured_cors_origins_are_applied(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", '["https://app.example.com"]')
    client = TestClient(create_app(accounts=AccountService(), users=UserService()))

    response = client.options(
        "/health",
        headers={
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"
