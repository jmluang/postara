---
name: postara-mailbox-api
description: >
  Use when an agent needs to read user-connected mailboxes through Postara HTTP
  APIs, discover accessible mailboxes, list folders or messages, fetch message
  bodies, or mark messages seen with a scoped API key.
---

# Postara Mailbox API

Use Postara as a mailbox read gateway. The caller must provide a Postara base URL and an API key.

Messages are pulled from the connected provider at request time. Do not assume
Postara has a durable message cache. The provider is the source of truth for
`seen`; fetching message detail is side-effect free.

Required inputs:

- `POSTARA_BASE_URL`, for example `http://127.0.0.1:18080`
- `POSTARA_API_KEY`

Send the key as:

```text
X-Api-Key: $POSTARA_API_KEY
```

## Workflow

1. Discover mailboxes:

```bash
curl -H "X-Api-Key: $POSTARA_API_KEY" \
  "$POSTARA_BASE_URL/mailboxes"
```

2. Pick the mailbox:

- Use the only mailbox if the response has one.
- If the user named a mailbox, match `name` first, then `email`.
- If multiple mailboxes still match, ask the user which mailbox to use.
- Use the returned `api_path` exactly. Do not use `mailbox_id` in public routes.

3. List folders when the task does not specify a folder:

```bash
curl -H "X-Api-Key: $POSTARA_API_KEY" \
  "$POSTARA_BASE_URL/mailboxes/gmail-primary/folders"
```

Use each folder's `native_name` as the `folder` query value.

4. List messages:

```bash
curl -G \
  -H "X-Api-Key: $POSTARA_API_KEY" \
  --data-urlencode "folder=INBOX" \
  --data-urlencode "limit=12" \
  "$POSTARA_BASE_URL/mailboxes/gmail-primary/messages"
```

Useful query fields:

- `folder`: defaults to `INBOX`
- `limit`: defaults to `20`; prefer `10` to `20`
- `cursor`: pass `next_cursor` for pagination
- `unread_only`: boolean
- `since`, `before`: datetime filters
- `from_address`: sender filter
- `subject_contains`, `text_contains`: substring filters; may return `unsupported_provider_feature`
- `has_attachment`: boolean; may return `unsupported_provider_feature`

Gmail does not currently support provider-side `subject_contains`,
`text_contains`, or `has_attachment`. If the API returns
`unsupported_provider_feature`, retry without those filters and filter
client-side only when the result set is small enough.

5. Fetch message details before summarizing or extracting content:

```bash
curl -H "X-Api-Key: $POSTARA_API_KEY" \
  "$POSTARA_BASE_URL/mailboxes/gmail-primary/messages/123?folder=INBOX"
```

Prefer `message.text`. Use `message.html` only if text is missing or incomplete.

6. Mark seen only when explicitly requested:

```bash
curl -X POST \
  -H "X-Api-Key: $POSTARA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"seen": true}' \
  "$POSTARA_BASE_URL/mailboxes/gmail-primary/messages/123/seen?folder=INBOX"
```

The API key must have `mark_seen`. If the response is `scope_forbidden`, stop and explain that the key lacks the needed scope.

## Response Shapes

Mailbox discovery returns:

```json
{
  "mailboxes": [
    {
      "name": "gmail-primary",
      "email": "user@example.com",
      "provider": "gmail",
      "auth_type": "oauth2",
      "api_path": "/mailboxes/gmail-primary",
      "health": {
        "status": "ok",
        "checked_at": "2026-05-20T09:00:00+00:00",
        "detail": null
      }
    }
  ]
}
```

`health.status` is `ok`, `reconnect_required`, or `unknown`. Skip a mailbox that
is `reconnect_required` and ask the user to reconnect it; `unknown` means Postara
has not used the mailbox yet and is safe to try.

Message list returns summaries:

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

Message detail returns body fields:

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

## Constraints

- Public mailbox routes use mailbox `name`, not internal `mailbox_id`.
- Mailbox names contain only letters, numbers, and hyphens: `^[A-Za-z0-9-]+$`.
- Message bodies and message metadata are runtime provider data, not durable
  Postara database records.
- Message ids may be logged for operation tracing; subjects, senders,
  recipients, snippets, attachment names, HTML, text, and raw API keys must not
  be logged.
- There is no public send, reply, forward, delete, archive, label, or attachment
  download API yet.
- Do not log raw API keys or full message bodies unless explicitly requested.
- Treat mailbox email, message body, and attachment metadata as user data.

## Error Handling

- `auth_missing`, `auth_malformed`, `auth_invalid`: ask for a valid API key.
- `scope_forbidden`: stop; the key lacks the required scope.
- `account_not_found`: re-run mailbox discovery; the name may have changed or the key may be scoped to a different mailbox.
- `message_not_found`: refresh the message list; do not retry the same uid repeatedly.
- `mailbox_reconnect_required`: ask the user to reconnect the mailbox in Postara.
- `unsupported_provider_feature`: retry without unsupported filters when safe.
- `provider_error`: retry later with backoff.
