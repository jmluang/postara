from fastapi.testclient import TestClient

from courier.accounts import AccountService
from courier.api import create_app
from courier.users import UserService


class FakeMailboxRuntime:
    def validate_credentials(self, **kwargs):
        return None


def owner_workspace():
    accounts = AccountService()
    users = UserService()
    client = TestClient(create_app(accounts=accounts, users=users, mailbox_runtime=FakeMailboxRuntime()))
    owner = client.post(
        "/auth/register",
        json={"email": "owner@example.com", "password": "secret123", "name": "Owner"},
    ).json()["session_token"]
    member = client.post(
        "/auth/register",
        json={"email": "member@example.com", "password": "secret123", "name": "Member"},
    ).json()["session_token"]
    return client, owner, member


def test_owner_can_list_and_disable_users():
    client, owner_token, member_token = owner_workspace()

    users = client.get("/owner/users", headers={"Authorization": f"Bearer {owner_token}"})
    disabled = client.patch(
        "/owner/users/2/status",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"status": "disabled"},
    )
    member_me = client.get("/me", headers={"Authorization": f"Bearer {member_token}"})
    enabled = client.patch(
        "/owner/users/2/status",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"status": "active"},
    )

    assert users.status_code == 200
    assert [user["email"] for user in users.json()["users"]] == ["owner@example.com", "member@example.com"]
    assert disabled.status_code == 200
    assert disabled.json()["user"]["disabled_at"] is not None
    assert member_me.status_code == 401
    assert enabled.status_code == 200
    assert enabled.json()["user"]["disabled_at"] is None


def test_owner_can_reset_member_password_and_list_mailboxes():
    client, owner_token, member_token = owner_workspace()
    mailbox = client.post(
        "/mailboxes",
        headers={"Authorization": f"Bearer {member_token}"},
        json={
            "name": "Member mailbox",
            "email": "mailbox@example.com",
            "provider": "gmail",
            "password": "app-password",
        },
    )
    reset = client.put(
        "/owner/users/2/password",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"new_password": "reset1234"},
    )
    login = client.post("/auth/login", json={"email": "member@example.com", "password": "reset1234"})
    mailboxes = client.get("/owner/mailboxes", headers={"Authorization": f"Bearer {owner_token}"})
    member_forbidden = client.get("/owner/users", headers={"Authorization": f"Bearer {login.json()['session_token']}"})

    assert mailbox.status_code == 201
    assert reset.status_code == 204
    assert login.status_code == 200
    assert mailboxes.status_code == 200
    assert mailboxes.json()["mailboxes"][0]["email"] == "mailbox@example.com"
    assert member_forbidden.status_code == 404


def test_owner_can_list_audit_events():
    client, owner_token, _member_token = owner_workspace()

    events = client.get("/owner/audit/events", headers={"Authorization": f"Bearer {owner_token}"})

    assert events.status_code == 200
    assert "events" in events.json()
