from fastapi.testclient import TestClient

from courier.accounts import AccountService
from courier.api import create_app
from courier.providers.base import AuthenticationError
from courier.users import UserService


class FakeMailboxRuntime:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.validated = []

    def validate_credentials(self, **kwargs):
        self.validated.append(kwargs)
        if not self.valid:
            raise AuthenticationError("invalid credentials")


def client_and_token(runtime: FakeMailboxRuntime | None = None) -> tuple[TestClient, str, FakeMailboxRuntime]:
    fake_runtime = runtime or FakeMailboxRuntime()
    client = TestClient(create_app(accounts=AccountService(), users=UserService(), mailbox_runtime=fake_runtime))
    response = client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "secret123", "name": "User"},
    )
    assert response.status_code == 201
    return client, response.json()["session_token"], fake_runtime


def create_mailbox(client: TestClient, token: str, email: str = "work@example.com") -> dict:
    response = client.post(
        "/mailboxes",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "work",
            "email": email,
            "provider": "gmail",
            "password": "app-password",
        },
    )
    assert response.status_code == 201
    return response.json()


def test_user_can_create_and_list_mailbox_without_exposing_secrets():
    client, token, runtime = client_and_token()

    created = create_mailbox(client, token)
    listed = client.get("/mailboxes", headers={"Authorization": f"Bearer {token}"})

    assert created["mailbox"]["email"] == "work@example.com"
    assert "encrypted_password" not in created["mailbox"]
    assert listed.status_code == 200
    assert listed.json()["mailboxes"][0]["id"] == created["mailbox"]["id"]
    assert runtime.validated[0]["imap_host"] == "imap.gmail.com"


def test_credentials_update_rejects_invalid_mailbox_password():
    client, token, _runtime = client_and_token(FakeMailboxRuntime(valid=False))
    response = client.post(
        "/mailboxes",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "work",
            "email": "work@example.com",
            "provider": "gmail",
            "password": "wrong",
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "credentials_invalid"


def test_user_can_delete_own_mailbox():
    client, token, _runtime = client_and_token()
    created = create_mailbox(client, token)

    deleted = client.delete(
        f"/mailboxes/{created['mailbox']['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    listed = client.get("/mailboxes", headers={"Authorization": f"Bearer {token}"})

    assert deleted.status_code == 204
    assert listed.json()["mailboxes"] == []


def test_admin_token_routes_are_removed():
    client, _token, _runtime = client_and_token()

    response = client.get("/admin/accounts", headers={"X-Admin-Token": "anything"})

    assert response.status_code == 404
