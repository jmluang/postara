import asyncio

import httpx
import pytest

from postara.accounts import AccountService
from postara.api import create_app
from postara.mcp.client import PostaraClient, PostaraMCPError
from postara.mcp.tools import (
    build_mcp,
    get_message,
    list_mailboxes,
    set_client,
)
from postara.providers.base import Folder, Message, MessageSummary
from postara.users import UserService

EXPECTED_TOOLS = {
    "list_mailboxes",
    "list_folders",
    "list_messages",
    "get_message",
    "mark_message_seen",
}


class FakeMailboxRuntime:
    def list_messages(self, account, password, folder, query):
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
        return [Folder("INBOX", "INBOX", "/", [])]

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


def _install_client() -> PostaraClient:
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
    _key, api_key = users.create_api_key(user.id, name="Test", scopes=["read"])
    app = create_app(accounts=accounts, users=users, mailbox_runtime=FakeMailboxRuntime())
    client = PostaraClient("http://testserver", api_key, transport=httpx.ASGITransport(app=app))
    set_client(client)
    return client


def test_build_mcp_registers_all_tools():
    mcp = build_mcp()

    tools = asyncio.run(mcp.list_tools())

    assert {tool.name for tool in tools} == EXPECTED_TOOLS


def test_tool_calls_through_to_postara():
    client = _install_client()

    async def body():
        try:
            return await list_mailboxes()
        finally:
            await client.aclose()

    data = asyncio.run(body())

    assert data["mailboxes"][0]["name"] == "work"


def test_tool_propagates_readable_error():
    client = _install_client()

    async def body():
        try:
            return await get_message("work", "999")
        finally:
            await client.aclose()

    with pytest.raises(PostaraMCPError):
        asyncio.run(body())
