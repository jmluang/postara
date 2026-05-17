from fastapi.testclient import TestClient

from postara.accounts import AccountService
from postara.api import create_app
from postara.users import UserService


def test_user_can_register_login_fetch_me_and_logout():
    client = TestClient(create_app(accounts=AccountService(), users=UserService()))

    registered = client.post(
        "/auth/register",
        json={
            "email": "user@example.com",
            "password": "secret123",
            "name": "User",
        },
    )
    assert registered.status_code == 201
    assert registered.json()["user"]["email"] == "user@example.com"
    assert registered.json()["user"]["role"] == "owner"
    assert registered.json()["session_token"].startswith("pst_session_")

    token = registered.json()["session_token"]
    me = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["user"]["email"] == "user@example.com"

    logout = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout.status_code == 204

    after_logout = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert after_logout.status_code == 401


def test_duplicate_user_email_is_rejected():
    client = TestClient(create_app(accounts=AccountService(), users=UserService()))
    payload = {"email": "user@example.com", "password": "secret123", "name": "User"}

    assert client.post("/auth/register", json=payload).status_code == 201
    response = client.post("/auth/register", json=payload)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "user_email_already_exists"


def test_register_validation_error_names_invalid_field():
    client = TestClient(create_app(accounts=AccountService(), users=UserService()))

    response = client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "123", "name": "User"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert response.json()["error"]["details"]["fields"][0]["field"] == "password"


def test_login_rate_limits_repeated_password_failures():
    client = TestClient(create_app(accounts=AccountService(), users=UserService()))
    client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "secret123", "name": "User"},
    )

    responses = [
        client.post("/auth/login", json={"email": "user@example.com", "password": "bad"})
        for _ in range(6)
    ]

    assert [response.status_code for response in responses[:5]] == [401, 401, 401, 401, 401]
    assert responses[5].status_code == 429
    assert responses[5].json()["error"]["code"] == "rate_limited"


def test_register_rate_limits_repeated_duplicate_email_attempts():
    client = TestClient(create_app(accounts=AccountService(), users=UserService()))
    payload = {"email": "user@example.com", "password": "secret123", "name": "User"}
    assert client.post("/auth/register", json=payload).status_code == 201

    responses = [client.post("/auth/register", json=payload) for _ in range(6)]

    assert [response.status_code for response in responses[:5]] == [409, 409, 409, 409, 409]
    assert responses[5].status_code == 429
    assert responses[5].json()["error"]["code"] == "rate_limited"


def test_user_can_change_own_password():
    client = TestClient(create_app(accounts=AccountService(), users=UserService()))
    registered = client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "secret123", "name": "User"},
    )
    token = registered.json()["session_token"]

    changed = client.put(
        "/me/password",
        headers={"Authorization": f"Bearer {token}"},
        json={"current_password": "secret123", "new_password": "better123"},
    )
    old_login = client.post("/auth/login", json={"email": "user@example.com", "password": "secret123"})
    new_login = client.post("/auth/login", json={"email": "user@example.com", "password": "better123"})

    assert changed.status_code == 204
    assert old_login.status_code == 401
    assert new_login.status_code == 200


def test_user_can_update_own_name():
    client = TestClient(create_app(accounts=AccountService(), users=UserService()))
    registered = client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "secret123", "name": "User"},
    )
    token = registered.json()["session_token"]

    updated = client.patch(
        "/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Renamed User"},
    )

    assert updated.status_code == 200
    assert updated.json()["user"]["name"] == "Renamed User"
