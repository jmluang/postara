"""HTTP client that wraps the Postara REST API for the MCP server.

The MCP server is a thin client: it holds a base URL and an API key, and calls
a running Postara instance over HTTP. The same client works against a
self-hosted deployment or the hosted service.
"""

from __future__ import annotations

import os

import httpx

DEFAULT_BASE_URL = "http://127.0.0.1:18080"


class PostaraConfigError(RuntimeError):
    """Raised when required MCP server configuration is missing."""


class PostaraMCPError(RuntimeError):
    """A Postara request failed. Carries a human-readable, agent-safe message."""


def _error_message(response: httpx.Response) -> str:
    """Turn a Postara error response into one readable line, no secrets."""
    try:
        body = response.json()
    except ValueError:
        return f"Postara request failed (HTTP {response.status_code})."
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict):
        code = error.get("code", "error")
        message = error.get("message", "").strip()
        return f"{message} [{code}]".strip() if message else f"Postara error: {code}."
    return f"Postara request failed (HTTP {response.status_code})."


class PostaraClient:
    """Async client over the Postara mailbox REST API."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"X-Api-Key": api_key},
            transport=transport,
            timeout=30.0,
        )

    @classmethod
    def from_env(cls) -> "PostaraClient":
        """Build a client from POSTARA_BASE_URL / POSTARA_API_KEY."""
        api_key = os.environ.get("POSTARA_API_KEY")
        if not api_key:
            raise PostaraConfigError(
                "POSTARA_API_KEY is required. Create a scoped API key in Postara "
                "and set it in the environment."
            )
        base_url = os.environ.get("POSTARA_BASE_URL", DEFAULT_BASE_URL)
        return cls(base_url, api_key)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json: dict | None = None,
    ) -> dict:
        try:
            response = await self._client.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            raise PostaraMCPError(
                f"Could not reach Postara at {self.base_url}: {exc}"
            ) from exc
        if response.status_code >= 400:
            raise PostaraMCPError(_error_message(response))
        return response.json()

    async def list_mailboxes(self) -> dict:
        return await self._request("GET", "/mailboxes")

    async def list_folders(self, mailbox: str) -> dict:
        return await self._request("GET", f"/mailboxes/{mailbox}/folders")

    async def list_messages(self, mailbox: str, **filters: object) -> dict:
        params = {key: value for key, value in filters.items() if value is not None}
        return await self._request("GET", f"/mailboxes/{mailbox}/messages", params=params)

    async def get_message(self, mailbox: str, uid: str, folder: str = "INBOX") -> dict:
        return await self._request(
            "GET", f"/mailboxes/{mailbox}/messages/{uid}", params={"folder": folder}
        )

    async def mark_message_seen(
        self, mailbox: str, uid: str, seen: bool = True, folder: str = "INBOX"
    ) -> dict:
        return await self._request(
            "POST",
            f"/mailboxes/{mailbox}/messages/{uid}/seen",
            params={"folder": folder},
            json={"seen": seen},
        )
