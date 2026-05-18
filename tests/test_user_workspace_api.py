from fastapi.testclient import TestClient
from urllib.parse import quote

from postara.accounts import AccountService
from postara.api import create_app
from postara.credentials import AppPasswordCredential
from postara.providers.base import AuthenticationError, Folder, Message, MessageSummary
from postara.users import UserService


class FakeMailboxRuntime:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.validated = []
        self.list_message_calls = []
        self.fetch_message_calls = []
        self.folder_calls = []
        self.mark_seen_calls = []

    def validate_credentials(self, **kwargs):
        self.validated.append(kwargs)
        if not self.valid:
            raise AuthenticationError("invalid credentials")

    def list_messages(self, account, password, folder, query):
        self.list_message_calls.append((account.id, folder, query.cursor))
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

    def fetch_message(self, account, password, folder, uid):
        self.fetch_message_calls.append((account.id, folder, uid))
        if uid != "123":
            return None
        return Message(
            uid="123",
            subject="Hello",
            from_address="sender@example.com",
            date=None,
            text="plain body",
            html="<p>html body</p>",
            seen=False,
            attachments=[],
        )

    def list_folders(self, account, password):
        self.folder_calls.append((account.id, password))
        return [Folder("INBOX", "INBOX", "/", [])]

    def mark_seen(self, account, password, folder, uid, seen):
        self.mark_seen_calls.append((account.id, folder, uid, seen))


def workspace_client(runtime: FakeMailboxRuntime | None = None) -> TestClient:
    return TestClient(
        create_app(
            accounts=AccountService(),
            users=UserService(),
            mailbox_runtime=runtime or FakeMailboxRuntime(),
        )
    )


def register(client: TestClient, email: str) -> str:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "secret123", "name": email},
    )
    assert response.status_code == 201
    return response.json()["session_token"]


def create_mailbox(client: TestClient, token: str, email: str = "work@example.com", name: str = "Work") -> dict:
    response = client.post(
        "/mailboxes",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": name,
            "email": email,
            "provider": "gmail",
            "password": "app-password",
        },
    )
    assert response.status_code == 201
    return response.json()["mailbox"]


def mailbox_path(mailbox: dict) -> str:
    return quote(mailbox["name"], safe="")


def test_user_creates_and_lists_only_own_mailboxes():
    client = workspace_client()
    first_token = register(client, "first@example.com")
    second_token = register(client, "second@example.com")

    created = create_mailbox(client, first_token)

    first_list = client.get("/mailboxes", headers={"Authorization": f"Bearer {first_token}"})
    second_list = client.get("/mailboxes", headers={"Authorization": f"Bearer {second_token}"})

    assert first_list.json()["mailboxes"][0]["id"] == created["id"]
    assert second_list.json()["mailboxes"] == []


def test_different_users_can_connect_same_mailbox_email():
    client = workspace_client()
    first_token = register(client, "first@example.com")
    second_token = register(client, "second@example.com")

    first_mailbox = create_mailbox(client, first_token, email="shared@example.com")
    second_mailbox = create_mailbox(client, second_token, email="shared@example.com")

    assert first_mailbox["email"] == "shared@example.com"
    assert second_mailbox["email"] == "shared@example.com"
    assert first_mailbox["id"] != second_mailbox["id"]


def test_user_can_create_api_key_and_access_own_mailbox_messages():
    client = workspace_client()
    token = register(client, "user@example.com")
    mailbox = create_mailbox(client, token, name="work-gmail")

    key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Production"},
    )

    assert key_response.status_code == 201
    raw_key = key_response.json()["api_key"]
    assert raw_key.startswith("pst_live_")

    mailbox_name = quote(mailbox["name"], safe="")
    messages = client.get(f"/mailboxes/{mailbox_name}/messages", headers={"X-Api-Key": raw_key})
    assert messages.status_code == 200
    assert messages.json()["messages"][0]["uid"] == "123"

    detail = client.get(f"/mailboxes/{mailbox_name}/messages/123", headers={"X-Api-Key": raw_key})
    assert detail.status_code == 200
    assert detail.json()["mailbox_id"] == mailbox["id"]
    assert detail.json()["mailbox_name"] == "work-gmail"
    assert detail.json()["message"]["html"] == "<p>html body</p>"


def test_mailbox_api_name_must_be_url_safe_ascii():
    client = workspace_client()
    token = register(client, "bad-name@example.com")

    response = client.post(
        "/mailboxes",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Work Gmail",
            "email": "work@example.com",
            "provider": "gmail",
            "password": "app-password",
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_api_key_can_list_accessible_mailboxes_by_api_name():
    client = workspace_client()
    token = register(client, "list-mailboxes@example.com")
    first = create_mailbox(client, token, email="first-mailbox@example.com", name="primary-gmail")
    second = create_mailbox(client, token, email="second-mailbox@example.com", name="receipts-gmail")
    all_key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "All mailboxes"},
    )
    scoped_key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Receipts only", "mailbox_id": second["id"], "scopes": ["read"]},
    )

    all_mailboxes = client.get("/mailboxes", headers={"X-Api-Key": all_key_response.json()["api_key"]})
    scoped_mailboxes = client.get("/mailboxes", headers={"X-Api-Key": scoped_key_response.json()["api_key"]})

    assert all_mailboxes.status_code == 200
    assert [mailbox["name"] for mailbox in all_mailboxes.json()["mailboxes"]] == [first["name"], second["name"]]
    assert all_mailboxes.json()["mailboxes"][0]["api_path"] == f"/mailboxes/{mailbox_path(first)}"
    assert scoped_mailboxes.status_code == 200
    assert [mailbox["name"] for mailbox in scoped_mailboxes.json()["mailboxes"]] == [second["name"]]


def test_user_cannot_create_duplicate_mailbox_api_name():
    client = workspace_client()
    token = register(client, "duplicate-name@example.com")
    create_mailbox(client, token, email="first@example.com", name="Support")

    response = client.post(
        "/mailboxes",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Support",
            "email": "second@example.com",
            "provider": "gmail",
            "password": "app-password",
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "mailbox_name_already_exists"


def test_user_can_rename_mailbox_api_name():
    client = workspace_client()
    token = register(client, "rename@example.com")
    mailbox = create_mailbox(client, token, name="old-name")
    key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Production"},
    )

    response = client.patch(
        f"/mailboxes/{mailbox['id']}/name",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "new-name"},
    )
    old_path = client.get("/mailboxes/old-name/messages", headers={"X-Api-Key": key_response.json()["api_key"]})
    new_path = client.get("/mailboxes/new-name/messages", headers={"X-Api-Key": key_response.json()["api_key"]})

    assert response.status_code == 200
    assert response.json()["mailbox"]["name"] == "new-name"
    assert old_path.status_code == 404
    assert new_path.status_code == 200


def test_user_cannot_rename_mailbox_to_existing_api_name():
    client = workspace_client()
    token = register(client, "rename-duplicate@example.com")
    first = create_mailbox(client, token, email="first@example.com", name="first")
    second = create_mailbox(client, token, email="second@example.com", name="second")

    response = client.patch(
        f"/mailboxes/{second['id']}/name",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": first["name"]},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "mailbox_name_already_exists"


def test_api_key_scope_limits_mailbox_and_operations():
    runtime = FakeMailboxRuntime()
    client = workspace_client(runtime)
    token = register(client, "scoped@example.com")
    allowed = create_mailbox(client, token, email="allowed@example.com", name="Allowed")
    denied = create_mailbox(client, token, email="denied@example.com", name="Denied")
    key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Reader", "mailbox_id": allowed["id"], "scopes": ["read"]},
    )
    raw_key = key_response.json()["api_key"]

    allowed_messages = client.get(f"/mailboxes/{mailbox_path(allowed)}/messages", headers={"X-Api-Key": raw_key})
    denied_messages = client.get(f"/mailboxes/{mailbox_path(denied)}/messages", headers={"X-Api-Key": raw_key})
    mark_seen = client.post(
        f"/mailboxes/{mailbox_path(allowed)}/messages/123/seen",
        headers={"X-Api-Key": raw_key},
        json={"seen": True},
    )

    assert key_response.status_code == 201
    assert key_response.json()["api_key_record"]["mailbox_id"] == allowed["id"]
    assert key_response.json()["api_key_record"]["scopes"] == ["read"]
    assert allowed_messages.status_code == 200
    assert denied_messages.status_code == 404
    assert mark_seen.status_code == 403
    assert mark_seen.json()["error"]["code"] == "scope_forbidden"


def test_mark_seen_uses_scoped_key_and_session():
    runtime = FakeMailboxRuntime()
    client = workspace_client(runtime)
    token = register(client, "mark@example.com")
    mailbox = create_mailbox(client, token)
    key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Marker", "mailbox_id": mailbox["id"], "scopes": ["mark_seen"]},
    )

    key_mark = client.post(
        f"/mailboxes/{mailbox_path(mailbox)}/messages/123/seen",
        headers={"X-Api-Key": key_response.json()["api_key"]},
        json={"seen": True},
    )
    session_mark = client.post(
        f"/mailboxes/{mailbox_path(mailbox)}/messages/124/seen",
        headers={"Authorization": f"Bearer {token}"},
        json={"seen": False},
    )

    assert key_mark.status_code == 200
    assert key_mark.json() == {"mailbox_id": mailbox["id"], "mailbox_name": mailbox["name"], "uid": "123", "seen": True}
    assert session_mark.status_code == 200
    assert runtime.mark_seen_calls == [
        (mailbox["id"], "INBOX", "123", True),
        (mailbox["id"], "INBOX", "124", False),
    ]


def test_user_session_can_browse_mailbox_without_raw_api_key():
    runtime = FakeMailboxRuntime()
    client = workspace_client(runtime)
    token = register(client, "session-browser@example.com")
    mailbox = create_mailbox(client, token)

    folders = client.get(f"/mailboxes/{mailbox_path(mailbox)}/folders", headers={"Authorization": f"Bearer {token}"})
    messages = client.get(
        f"/mailboxes/{mailbox_path(mailbox)}/messages",
        headers={"Authorization": f"Bearer {token}"},
        params={"folder": "Receipts", "cursor": "122", "limit": 1},
    )
    detail = client.get(
        f"/mailboxes/{mailbox_path(mailbox)}/messages/123",
        headers={"Authorization": f"Bearer {token}"},
        params={"folder": "Receipts"},
    )

    assert folders.status_code == 200
    assert messages.status_code == 200
    assert messages.json()["next_cursor"] == "123"
    assert detail.status_code == 200
    assert runtime.folder_calls == [(mailbox["id"], AppPasswordCredential(password="app-password"))]
    assert runtime.list_message_calls == [(mailbox["id"], "Receipts", "122")]
    assert runtime.fetch_message_calls == [(mailbox["id"], "Receipts", "123")]


def test_user_can_disable_and_enable_api_key_status():
    client = workspace_client()
    token = register(client, "keys@example.com")
    mailbox = create_mailbox(client, token)
    key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Production"},
    )
    key_id = key_response.json()["api_key_record"]["id"]
    raw_key = key_response.json()["api_key"]

    disable = client.patch(
        f"/api-keys/{key_id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "disabled"},
    )
    disabled_list = client.get("/api-keys", headers={"Authorization": f"Bearer {token}"})
    disabled_messages = client.get(f"/mailboxes/{mailbox_path(mailbox)}/messages", headers={"X-Api-Key": raw_key})
    enable = client.patch(
        f"/api-keys/{key_id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "active"},
    )
    enabled_messages = client.get(f"/mailboxes/{mailbox_path(mailbox)}/messages", headers={"X-Api-Key": raw_key})

    assert disable.status_code == 200
    assert disable.json()["api_key"]["status"] == "disabled"
    assert disabled_list.json()["api_keys"][0]["id"] == key_id
    assert disabled_list.json()["api_keys"][0]["status"] == "disabled"
    assert disabled_messages.status_code == 401
    assert enable.status_code == 200
    assert enable.json()["api_key"]["status"] == "active"
    assert enabled_messages.status_code == 200


def test_user_can_delete_api_key_permanently():
    client = workspace_client()
    token = register(client, "delete-key@example.com")
    mailbox = create_mailbox(client, token)
    key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Production"},
    )
    key_id = key_response.json()["api_key_record"]["id"]
    raw_key = key_response.json()["api_key"]

    delete = client.delete(f"/api-keys/{key_id}", headers={"Authorization": f"Bearer {token}"})
    listed = client.get("/api-keys", headers={"Authorization": f"Bearer {token}"})
    messages = client.get(f"/mailboxes/{mailbox_path(mailbox)}/messages", headers={"X-Api-Key": raw_key})
    enable = client.patch(
        f"/api-keys/{key_id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "active"},
    )

    assert delete.status_code == 204
    assert listed.json()["api_keys"] == []
    assert messages.status_code == 401
    assert enable.status_code == 404


def test_user_message_detail_returns_not_found_for_unknown_uid():
    client = workspace_client()
    token = register(client, "detail@example.com")
    mailbox = create_mailbox(client, token)
    key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Production"},
    )

    response = client.get(f"/mailboxes/{mailbox_path(mailbox)}/messages/999", headers={"X-Api-Key": key_response.json()["api_key"]})

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "message_not_found"


def test_user_api_key_cannot_access_another_users_mailbox():
    client = workspace_client()
    first_token = register(client, "first@example.com")
    second_token = register(client, "second@example.com")
    mailbox = create_mailbox(client, second_token, email="second-mailbox@example.com")
    key_response = client.post(
        "/api-keys",
        headers={"Authorization": f"Bearer {first_token}"},
        json={"name": "Production"},
    )

    response = client.get(
        f"/mailboxes/{mailbox_path(mailbox)}/messages",
        headers={"X-Api-Key": key_response.json()["api_key"]},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "account_not_found"


def test_legacy_account_api_key_routes_are_not_exposed():
    client = workspace_client()

    for method, path in (
        ("post", "/accounts/1/rotate-api-key"),
        ("get", "/accounts/1/key-info"),
        ("put", "/accounts/1/credentials"),
        ("get", "/accounts/1/folders"),
        ("get", "/accounts/1/messages"),
        ("get", "/accounts/1/messages/123"),
        ("post", "/accounts/1/messages/123/seen"),
    ):
        response = getattr(client, method)(path, headers={"X-Api-Key": "pst_live_deadbeef.deadbeefdeadbeefdeadbeefdeadbeef"})
        assert response.status_code == 404


def test_user_session_can_open_openapi_and_admin_token_header_is_ignored():
    client = workspace_client()
    token = register(client, "user@example.com")

    spec = client.get("/openapi.json", headers={"Authorization": f"Bearer {token}"})
    unauthenticated_spec = client.get("/openapi.json")
    old_admin_endpoint = client.get("/admin/accounts", headers={"X-Admin-Token": "anything"})

    assert spec.status_code == 200
    assert "/mailboxes" in spec.json()["paths"]
    assert unauthenticated_spec.status_code == 401
    assert old_admin_endpoint.status_code == 404
