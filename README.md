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
