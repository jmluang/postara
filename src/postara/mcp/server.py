"""Entry point for the ``postara-mcp`` console script.

Runs a stdio MCP server that exposes Postara mailbox tools. Configure it with
POSTARA_BASE_URL and POSTARA_API_KEY.
"""

from __future__ import annotations

import sys


def main() -> None:
    try:
        import mcp.server.fastmcp  # noqa: F401
    except ModuleNotFoundError:
        print(
            "postara-mcp requires the MCP extra. Install it with:\n"
            "  pip install 'postara[mcp]'",
            file=sys.stderr,
        )
        sys.exit(1)

    from postara.mcp.client import PostaraClient, PostaraConfigError
    from postara.mcp.tools import build_mcp, set_client

    try:
        client = PostaraClient.from_env()
    except PostaraConfigError as exc:
        print(f"postara-mcp: {exc}", file=sys.stderr)
        sys.exit(1)

    set_client(client)
    build_mcp().run()  # stdio transport


if __name__ == "__main__":
    main()
