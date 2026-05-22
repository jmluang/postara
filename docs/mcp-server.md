# Postara MCP Server

`postara-mcp` exposes a Postara mailbox as [Model Context Protocol](https://modelcontextprotocol.io)
tools, so MCP clients like Claude Desktop, Cursor, and Cline can read mail
through Postara.

It is a thin client: it holds a base URL and an API key and calls a running
Postara instance over HTTP. The same command works against a self-hosted
deployment or the hosted service.

## Install

```bash
pip install 'postara[mcp]'
```

The `postara-mcp` console script is then on your PATH.

## Configure

The server reads two environment variables:

| Variable | Required | Default | Notes |
|---|---|---|---|
| `POSTARA_API_KEY` | yes | — | A scoped API key created in the Postara app. |
| `POSTARA_BASE_URL` | no | `http://127.0.0.1:18080` | URL of the running Postara instance. |

Create the API key in Postara (Workspace → API keys). Give it only the scopes
the client needs:

- `read` — discover mailboxes, list folders and messages, fetch messages.
- `mark_seen` — change read/unread state. Add this only if the client should
  mark messages seen.

You can also scope a key to a single mailbox. One `postara-mcp` process uses one
API key, so it sees exactly the mailboxes that key can access.

## Connect Claude Desktop

Add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "postara": {
      "command": "postara-mcp",
      "env": {
        "POSTARA_BASE_URL": "http://127.0.0.1:18080",
        "POSTARA_API_KEY": "pst_live_your_key_here"
      }
    }
  }
}
```

Restart Claude Desktop. The Postara tools appear in the tool list.

## Connect Cursor / Cline

Cursor and Cline use the same MCP server config shape: command `postara-mcp`
with `POSTARA_BASE_URL` and `POSTARA_API_KEY` in `env`. See each editor's MCP
settings for where the config file lives.

## Tools

| Tool | Purpose |
|---|---|
| `list_mailboxes` | Discover mailboxes the key can access. Includes connection `health`. |
| `list_folders` | List folders in a mailbox. |
| `list_messages` | List message summaries, with folder/date/sender/read filters. |
| `get_message` | Fetch one message body by uid. |
| `mark_message_seen` | Mark a message read or unread (needs the `mark_seen` scope). |

`list_mailboxes` returns a `health` block per mailbox. A client should skip a
mailbox whose `health.status` is `reconnect_required` and ask the user to
reconnect it in Postara.

## Transport

`postara-mcp` runs over stdio, the transport Claude Desktop, Cursor, and Cline
use for local MCP servers. SSE / streamable-HTTP transport is not exposed yet.

## Distribution checklist (B3)

Submitting `postara-mcp` to public MCP registries is a manual step:

- [ ] Publish `postara` with the `mcp` extra to PyPI.
- [ ] Submit to the MCP server registry / awesome-mcp lists.
- [ ] Link this page from the Postara docs site.
