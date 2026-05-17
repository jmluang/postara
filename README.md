# Courier

Courier is a multi-tenant IMAP-to-HTTP gateway. It exposes mailbox operations through a small HTTP API while keeping mailbox credentials and API keys separate.

## Local development

Create `.env` in the project root:

```dotenv
DATABASE_URL=postgresql://postgres.<project-ref>:<password>@aws-1-<region>.pooler.supabase.com:6543/postgres?pgbouncer=true
DIRECT_URL=postgresql://postgres.<project-ref>:<password>@aws-1-<region>.pooler.supabase.com:5432/postgres
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_KEY=<anon-or-service-role-key>
COURIER_SECRETS_DIR=/absolute/path/to/courier/secrets
```

`DATABASE_URL` is the runtime URL. If it has `pgbouncer=true`, Courier disables asyncpg prepared statement caching and lets the Supabase transaction pooler manage database connections. `DIRECT_URL` is used by Alembic migrations.

Install and migrate without Docker:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
set -a; . ./.env; set +a
.venv/bin/alembic upgrade head
```

Run the app:

```bash
scripts/run_local.sh
```

`scripts/run_local.sh` runs migrations before starting FastAPI. This public repository ships only the prebuilt `/app` frontend bundle in `frontend/dist`; frontend source is kept in a separate private repository.

Use `COURIER_PORT=18081 scripts/run_local.sh` to run on another port.

Open the built-in workspace at `http://127.0.0.1:18080/app`. Create the first user in the browser; that user becomes `owner`. Sign in, add mailboxes, create scoped API keys, browse folders/messages with your session, and open the protected OpenAPI JSON.

API keys are shown once when created. They are not stored in browser local storage. A key can be limited to one mailbox and to `read` and/or `mark_seen` scopes; the signed-in workspace can still browse its own mailboxes without needing a raw API key.

Owner routes live under `/owner/*` and use the same session login. Owners can inspect health, list users, disable or re-enable users, reset user passwords, and list all mailboxes.

```
┌────────────────────────────────────────────────────────────────┐
│ Courier                         Refresh               Account  │
├──────────────────┬─────────────────────────────────────────────┤
│ Mailboxes        │ Mailboxes                                   │
│ API Keys         │ ┌ Add mailbox ┐ ┌ Connected accounts       ┐ │
│ OpenAPI Docs     │ └ form        ┘ └ selectable mailbox list  ┘ │
│                  │ ┌ Folders     ┐ ┌ Messages                 ┐ │
│                  │ └ skeletons   ┘ └ loading + empty states   ┘ │
└──────────────────┴─────────────────────────────────────────────┘
```

Useful checks:

```bash
.venv/bin/python -m pytest tests -q
curl http://127.0.0.1:18080/health
```

## Container package

Pushing to `main` or a `v*.*.*` tag builds and publishes a multi-arch image to GitHub Container Registry:

```text
ghcr.io/<owner>/<repo>:latest
ghcr.io/<owner>/<repo>:sha-<commit>
ghcr.io/<owner>/<repo>:<version>
```

Run a published image with Compose:

```bash
export COURIER_IMAGE=ghcr.io/<owner>/<repo>:latest
docker compose pull courier
docker compose up -d
```
