"""MCP tools that wrap the Postara mailbox API.

Each tool is a plain async function (directly callable in tests) and is also
registered onto a FastMCP server by ``build_mcp``. Tool docstrings mirror the
agent guidance in ``docs/agent-api.md``.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from postara.mcp.client import PostaraClient

_client: PostaraClient | None = None


def set_client(client: PostaraClient) -> None:
    """Install the PostaraClient the tools call. Set this before serving."""
    global _client
    _client = client


def get_client() -> PostaraClient:
    if _client is None:
        raise RuntimeError("PostaraClient is not configured; call set_client first.")
    return _client


async def list_mailboxes() -> dict:
    """List mailboxes this API key can access.

    Use a mailbox's ``name`` or ``api_path`` for later calls, never the numeric
    ``mailbox_id``. Skip any mailbox whose ``health.status`` is
    ``reconnect_required`` and tell the user to reconnect it in Postara.
    """
    return await get_client().list_mailboxes()


async def list_folders(mailbox: str) -> dict:
    """List folders in a mailbox.

    ``mailbox`` is the mailbox ``name`` from list_mailboxes. Use a folder's
    ``native_name`` as the ``folder`` argument of the other tools.
    """
    return await get_client().list_folders(mailbox)


async def list_messages(
    mailbox: str,
    folder: str = "INBOX",
    limit: int = 20,
    cursor: str | None = None,
    unread_only: bool = False,
    since: str | None = None,
    before: str | None = None,
    from_address: str | None = None,
    subject_contains: str | None = None,
    text_contains: str | None = None,
    has_attachment: bool | None = None,
) -> dict:
    """List message summaries in a folder.

    ``since`` and ``before`` are ISO 8601 datetime strings. Paginate with the
    ``next_cursor`` value from the previous response. Some providers reject
    ``subject_contains`` / ``text_contains`` / ``has_attachment`` with an
    ``unsupported_provider_feature`` error; retry without those filters.
    """
    return await get_client().list_messages(
        mailbox,
        folder=folder,
        limit=limit,
        cursor=cursor,
        unread_only=unread_only,
        since=since,
        before=before,
        from_address=from_address,
        subject_contains=subject_contains,
        text_contains=text_contains,
        has_attachment=has_attachment,
    )


async def get_message(mailbox: str, uid: str, folder: str = "INBOX") -> dict:
    """Fetch one message by uid. Prefer the ``text`` body for summarizing."""
    return await get_client().get_message(mailbox, uid, folder=folder)


async def mark_message_seen(
    mailbox: str, uid: str, seen: bool = True, folder: str = "INBOX"
) -> dict:
    """Mark a message read or unread.

    Only call this when the user explicitly asks to change read state. The API
    key must include the ``mark_seen`` scope; on a ``scope_forbidden`` error,
    stop and tell the user the key lacks that scope.
    """
    return await get_client().mark_message_seen(mailbox, uid, seen=seen, folder=folder)


ALL_TOOLS = (
    list_mailboxes,
    list_folders,
    list_messages,
    get_message,
    mark_message_seen,
)


def build_mcp() -> FastMCP:
    """Build the Postara FastMCP server with all tools registered."""
    mcp = FastMCP("postara")
    for tool in ALL_TOOLS:
        mcp.tool()(tool)
    return mcp
