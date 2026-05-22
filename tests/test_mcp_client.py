import asyncio

import httpx
import pytest

from postara.accounts import AccountService
from postara.api import create_app
from postara.mcp.client import PostaraClient, PostaraMCPError
from postara.providers.base import Folder, Message, MessageSummary
from postara.users import UserService


class FakeMailboxRuntime:
    def __init__(self) -> None:
        self.last_query = None

    def list_messages(self, account, password, folder, query):
        self.last_query = query
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
        return [Folder("INBOX", "INBOX", "/", []), Folder("CUSTOM", "Receipts", "/", [])]

    def fetch_message(self, account, password, folder, uid):
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

    def mark_seen(self, account, password, folder, uid, seen):
        return None


def _build(*, scopes=("read",), api_key=None) -> tuple[PostaraClient, FakeMailboxRuntime]:
    accounts = AccountService()
    users = UserService()
    user, _session = users.register(email="user@example.com", password="secret123", name="User")
    accounts.create_for_user(
        user_id=user.id,
        name="work",
        email="work@example.com",
        provider="gmail",
        password="app-password",
    )
    _key, real_key = users.create_api_key(user.id, name="Test", scopes=list(scopes))
    runtime = FakeMailboxRuntime()
    app = create_app(accounts=accounts, users=users, mailbox_runtime=runtime)
    client = PostaraClient(
        "http://testserver",
        api_key if api_key is not None else real_key,
        transport=httpx.ASGITransport(app=app),
    )
    return client, runtime


def _run(client: PostaraClient, coro_factory):
    async def body():
        try:
            return await coro_factory(client)
        finally:
            await client.aclose()

    return asyncio.run(body())


def test_list_mailboxes_includes_health():
    client, _runtime = _build()

    data = _run(client, lambda c: c.list_mailboxes())

    mailbox = data["mailboxes"][0]
    assert mailbox["name"] == "work"
    assert mailbox["health"]["status"] in {"unknown", "ok"}


def test_list_folders_returns_native_names():
    client, _runtime = _build()

    data = _run(client, lambda c: c.list_folders("work"))

    assert data["folders"][1]["native_name"] == "Receipts"


def test_list_messages_passes_filters_through():
    client, runtime = _build()

    data = _run(client, lambda c: c.list_messages("work", limit=5, unread_only=True))

    assert data["messages"][0]["uid"] == "123"
    assert runtime.last_query.limit == 5
    assert runtime.last_query.unread_only is True


def test_get_message_returns_body():
    client, _runtime = _build()

    data = _run(client, lambda c: c.get_message("work", "123"))

    assert data["message"]["text"] == "plain body"


def test_get_message_unknown_uid_raises_readable_error():
    client, _runtime = _build()

    with pytest.raises(PostaraMCPError) as exc:
        _run(client, lambda c: c.get_message("work", "999"))

    assert "message_not_found" in str(exc.value)


def test_mark_message_seen_with_scope_succeeds():
    client, _runtime = _build(scopes=("read", "mark_seen"))

    data = _run(client, lambda c: c.mark_message_seen("work", "123", seen=True))

    assert data["seen"] is True


def test_mark_message_seen_without_scope_raises_readable_error():
    client, _runtime = _build(scopes=("read",))

    with pytest.raises(PostaraMCPError) as exc:
        _run(client, lambda c: c.mark_message_seen("work", "123", seen=True))

    assert "scope" in str(exc.value).lower()


def test_invalid_api_key_raises_readable_error():
    client, _runtime = _build(api_key="pst_live_zzzzzzzz.zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

    with pytest.raises(PostaraMCPError) as exc:
        _run(client, lambda c: c.list_mailboxes())

    assert "traceback" not in str(exc.value).lower()
