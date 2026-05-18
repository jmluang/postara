# Postara

Postara is a lightweight IMAP-to-HTTP gateway for product teams that need stable mailbox APIs without building and maintaining their own email ingestion layer.

It connects user-owned mailboxes, normalizes folders and messages into predictable JSON, and exposes scoped API keys for application access.

## Status

Postara is in early development. The current public repository contains the backend service and the prebuilt app bundle used by the local workspace.

## Local Development

Create a `.env` file with Postgres connection settings:

```dotenv
DATABASE_URL=postgresql://user:password@host:6543/postara
DIRECT_URL=postgresql://user:password@host:5432/postara
POSTARA_SECRETS_DIR=/absolute/path/to/postara/secrets
```

`DATABASE_URL` is used by the running service. `DIRECT_URL` is used for migrations.

Run locally:

```bash
scripts/run_local.sh
```

The app opens at `http://127.0.0.1:18080/app`.

## Mailbox API Names

Each mailbox has a user-facing API name used in external mailbox routes:

```text
/mailboxes/{mailbox_name}/messages
```

Mailbox API names are unique per user and may contain only letters, numbers, and hyphens:

```text
gmail-primary
work-gmail-1
receipts
```

Spaces, underscores, slashes, and non-ASCII characters are rejected so external clients never need URL encoding for mailbox names.

Rename a mailbox API name from an authenticated user session:

```bash
curl -X PATCH \
  -H "Authorization: Bearer $POSTARA_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"gmail-primary"}' \
  http://127.0.0.1:18080/mailboxes/1/name
```

## API Key Usage

Create API keys in the app, copy the raw key once, then use it with `X-Api-Key`.

Agent-specific instructions are available in:

- [Agent API Guide](docs/agent-api.md)
- [Postara Mailbox API Skill](docs/skills/postara-mailbox-api/SKILL.md)

Discover which mailboxes the API key can access:

```bash
curl -H "X-Api-Key: $POSTARA_API_KEY" \
  http://127.0.0.1:18080/mailboxes
```

The response includes `api_path` values that can be used directly:

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

List messages for a mailbox:

```bash
curl -H "X-Api-Key: $POSTARA_API_KEY" \
  http://127.0.0.1:18080/mailboxes/gmail-primary/messages?limit=12
```

Fetch one message:

```bash
curl -H "X-Api-Key: $POSTARA_API_KEY" \
  http://127.0.0.1:18080/mailboxes/gmail-primary/messages/{uid}
```
