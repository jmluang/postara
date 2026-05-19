# Postara Agent API Guide

This guide is for AI agents and automation clients that read mail through Postara.

Postara exposes user-connected mailboxes over stable HTTP routes. Agents should use
the mailbox API name returned by discovery, not the internal mailbox id.

Messages are runtime provider data. Postara does not persist provider message bodies
or message metadata in its application database. Treat `seen` as provider state:
fetching detail does not mark a message read, and read/unread changes require the
explicit mark-seen endpoint.

## Authentication

Use an API key in every agent request:

```bash
X-Api-Key: $POSTARA_API_KEY
```

The local development base URL is:

```text
http://127.0.0.1:18080
```

## Agent Workflow

1. Discover accessible mailboxes with `GET /mailboxes`.
2. Choose a mailbox from the returned `mailboxes` list.
3. Use the returned `api_path` exactly for folder and message calls.
4. List folders if the task does not specify a folder.
5. List messages with a small `limit`.
6. Fetch a message by `uid` before summarizing or extracting details.
7. Mark a message seen only when the caller explicitly asks and the key has the `mark_seen` scope.

Do not construct routes from `mailbox_id`. The public mailbox route uses the mailbox `name`.

## Discover Mailboxes

```bash
curl -H "X-Api-Key: $POSTARA_API_KEY" \
  http://127.0.0.1:18080/mailboxes
```

Example response:

```json
{
  "mailboxes": [
    {
      "name": "gmail-primary",
      "email": "user@example.com",
      "provider": "gmail",
      "auth_type": "oauth2",
      "api_path": "/mailboxes/gmail-primary"
    }
  ]
}
```

Selection rules for agents:

- If there is one mailbox, use it.
- If the user named a mailbox, match against `name` first, then `email`.
- If multiple mailboxes remain possible, ask the caller which mailbox to use.
- Store `name` or `api_path` in agent memory, not `mailbox_id`.

Mailbox names contain only letters, numbers, and hyphens:

```text
^[A-Za-z0-9-]+$
```

## List Folders

```bash
curl -H "X-Api-Key: $POSTARA_API_KEY" \
  http://127.0.0.1:18080/mailboxes/gmail-primary/folders
```

Example response:

```json
{
  "mailbox_name": "gmail-primary",
  "folders": [
    {
      "semantic_name": "INBOX",
      "native_name": "INBOX",
      "delimiter": "/",
      "flags": []
    }
  ]
}
```

Use `native_name` as the `folder` query parameter. `semantic_name` is a normalized hint for humans and agents.

## List Messages

```bash
curl -G \
  -H "X-Api-Key: $POSTARA_API_KEY" \
  --data-urlencode "folder=INBOX" \
  --data-urlencode "limit=12" \
  http://127.0.0.1:18080/mailboxes/gmail-primary/messages
```

Example response:

```json
{
  "mailbox_name": "gmail-primary",
  "folder": "INBOX",
  "messages": [
    {
      "uid": "123",
      "subject": "Welcome",
      "from_address": "sender@example.com",
      "date": "2026-05-18T10:00:00+00:00",
      "seen": false,
      "has_attachments": false
    }
  ],
  "next_cursor": "123"
}
```

Supported query parameters:

| Parameter | Type | Notes |
|---|---|---|
| `folder` | string | Defaults to `INBOX`. Use the folder `native_name`. |
| `limit` | integer | Defaults to `20`. Prefer small limits for agent loops. |
| `cursor` | string | Pass `next_cursor` from the previous response. |
| `unread_only` | boolean | `true` returns unread messages only. |
| `since` | datetime | Provider-side date filter. |
| `before` | datetime | Provider-side date filter. |
| `from_address` | string | Provider-side sender filter. |
| `subject_contains` | string | May return `unsupported_provider_feature`. |
| `text_contains` | string | May return `unsupported_provider_feature`. |
| `has_attachment` | boolean | May return `unsupported_provider_feature`. |

For Gmail, `subject_contains`, `text_contains`, and `has_attachment` are not
currently supported provider-side. If the API returns
`unsupported_provider_feature`, retry without those filters and filter
client-side only when the message volume is small enough for the task.

## Fetch One Message

```bash
curl -H "X-Api-Key: $POSTARA_API_KEY" \
  "http://127.0.0.1:18080/mailboxes/gmail-primary/messages/123?folder=INBOX"
```

Example response:

```json
{
  "mailbox_name": "gmail-primary",
  "message": {
    "uid": "123",
    "subject": "Welcome",
    "from_address": "sender@example.com",
    "date": "2026-05-18T10:00:00+00:00",
    "text": "Plain text body",
    "html": "<p>HTML body</p>",
    "seen": false,
    "attachments": []
  }
}
```

Prefer `text` for extraction and summarization. Use `html` only when the plain text body is missing or incomplete.

## Mark Seen

Only call this endpoint when the caller asks to change read state.

The API key must include the `mark_seen` scope.

```bash
curl -X POST \
  -H "X-Api-Key: $POSTARA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"seen": true}' \
  "http://127.0.0.1:18080/mailboxes/gmail-primary/messages/123/seen?folder=INBOX"
```

## Current Limits

Postara currently supports mailbox discovery, folder listing, message listing,
message fetch, and optional read-state updates.

There is no public send, reply, forward, delete, archive, label, or attachment
download API yet. Agents must not claim these actions are available.

## Error Handling

Postara returns structured errors:

```json
{
  "error": {
    "code": "mailbox_reconnect_required",
    "message": "Mailbox must be reconnected before provider requests can continue."
  },
  "request_id": "..."
}
```

Common error codes:

| Status | Code | Agent behavior |
|---|---|---|
| `401` | `auth_missing` | Ask for an API key. |
| `401` | `auth_malformed` | Ask for the key to be checked. |
| `401` | `auth_invalid` | Ask for a new or enabled API key. |
| `401` | `invalid_credentials` | Browser/session login failed; do not expose whether the email exists. |
| `403` | `scope_forbidden` | Do not retry. Explain that the key lacks the required scope. |
| `403` | `auth_challenge_required` | Browser/session auth requires an additional challenge. |
| `403` | `auth_challenge_failed` | Browser/session challenge failed. |
| `429` | `rate_limited` | Back off before retrying. |
| `404` | `account_not_found` | Re-run `GET /mailboxes`; the mailbox name may have changed or the key may be scoped elsewhere. |
| `404` | `message_not_found` | Do not retry the same uid. Refresh the message list if needed. |
| `409` | `mailbox_reconnect_required` | Ask the user to reconnect the mailbox in Postara. |
| `400` | `unsupported_provider_feature` | Retry without unsupported filters when safe. |
| `502` | `provider_error` | Retry later with backoff. |

## Logging Guidance

Agents may log safe operation metadata such as mailbox API name, message uid,
status code, and request id. Do not log message bodies, subjects, senders,
recipients, snippets, attachment names, or raw API keys.

## Safe Agent Defaults

- Use `limit=10` to `20` unless the user asks for a broader scan.
- Fetch details only for messages needed to answer the task.
- Never log full message bodies unless the user explicitly asks for diagnostic output.
- Never expose the raw API key in logs, tool output, or final answers.
- Treat mailbox `email`, message body, and attachments as user data.
