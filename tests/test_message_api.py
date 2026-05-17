from fastapi.testclient import TestClient

from courier.api import create_app
from courier.accounts import AccountService
from courier.providers.base import Folder, Message, MessageSummary
from courier.users import UserService


class FakeMailboxRuntime:
    def __init__(self):
        self.mark_seen_calls = []
        self.list_message_calls = []

    def list_messages(self, account, password, folder, query):
        self.list_message_calls.append((account.id, folder))
        return [
            MessageSummary(
                uid="123",
                subject="Hello",
                from_address="sender@example.com",
                date=None,
                seen=False,
                has_attachments=False,
            )
        ]

    def list_folders(self, account, password):
        return [
            Folder("INBOX", "INBOX", "/", []),
            Folder("CUSTOM", "Receipts", "/", []),
        ]

    def fetch_message(self, account, password, folder, uid):
        if uid != "123":
            return None
        return Message(
            uid="123",
            subject="Hello",
            from_address="sender@example.com",
            date=None,
            text="plain",
            html="<p>html</p>",
            seen=False,
            attachments=[],
        )

    def mark_seen(self, account, password, folder, uid, seen):
        self.mark_seen_calls.append((account.id, password, folder, uid, seen))


def client_with_account() -> tuple[TestClient, int, str, FakeMailboxRuntime]:
    accounts = AccountService()
    users = UserService()
    user, session_token = users.register(email="user@example.com", password="secret123", name="User")
    account = accounts.create_for_user(
        user_id=user.id,
        name="work",
        email="work@example.com",
        provider="gmail",
        password="app-password",
    )
    _key, api_key = users.create_api_key(user.id, name="Test")
    runtime = FakeMailboxRuntime()
    return TestClient(create_app(accounts=accounts, users=users, mailbox_runtime=runtime)), account.id, session_token, api_key, runtime


def test_list_messages_uses_mailbox_runtime():
    client, account_id, _session_token, api_key, _runtime = client_with_account()

    response = client.get(
        f"/mailboxes/{account_id}/messages",
        headers={"X-Api-Key": api_key},
    )

    assert response.status_code == 200
    assert response.json()["messages"][0]["uid"] == "123"


def test_list_folders_uses_mailbox_runtime():
    client, account_id, session_token, _api_key, _runtime = client_with_account()

    response = client.get(
        f"/mailboxes/{account_id}/folders",
        headers={"Authorization": f"Bearer {session_token}"},
    )

    assert response.status_code == 200
    assert response.json()["folders"][1]["native_name"] == "Receipts"


def test_fetch_message_returns_not_found_for_unknown_uid():
    client, account_id, _session_token, api_key, _runtime = client_with_account()

    response = client.get(
        f"/mailboxes/{account_id}/messages/999",
        headers={"X-Api-Key": api_key},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "message_not_found"


def test_fetch_message_returns_provider_message():
    client, account_id, session_token, _api_key, _runtime = client_with_account()

    response = client.get(
        f"/mailboxes/{account_id}/messages/123",
        headers={"Authorization": f"Bearer {session_token}"},
    )

    assert response.status_code == 200
    assert response.json()["message"]["html"] == "<p>html</p>"


def test_list_messages_accepts_folder_query_parameter():
    client, account_id, session_token, _api_key, runtime = client_with_account()

    response = client.get(
        f"/mailboxes/{account_id}/messages",
        headers={"Authorization": f"Bearer {session_token}"},
        params={"folder": "Receipts"},
    )

    assert response.status_code == 200
    assert runtime.mark_seen_calls == []
    assert runtime.list_message_calls == [(account_id, "Receipts")]
