#!/usr/bin/env bash
set -euo pipefail

COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-postara_smoke_$(date +%s)}"
POSTARA_HOST_BIND="${POSTARA_HOST_BIND:-127.0.0.1}"
POSTARA_HOST_PORT="${POSTARA_HOST_PORT:-18080}"
PYTHON_BIN="${PYTHON_BIN:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP_DIR="$(mktemp -d)"
CREATED_SECRETS=0

cleanup() {
  set +e
  COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME" \
  POSTARA_HOST_BIND="$POSTARA_HOST_BIND" \
  POSTARA_HOST_PORT="$POSTARA_HOST_PORT" \
    docker compose -f "$ROOT_DIR/docker-compose.yml" down -v >/dev/null 2>&1

  if [ "$CREATED_SECRETS" = "1" ]; then
    rm -f "$ROOT_DIR/secrets"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

detect_python() {
  if [ -n "$PYTHON_BIN" ]; then
    printf '%s\n' "$PYTHON_BIN"
  elif [ -x "$ROOT_DIR/.venv/bin/python" ]; then
    printf '%s\n' "$ROOT_DIR/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    command -v python3
  else
    echo "Missing Python interpreter." >&2
    exit 1
  fi
}

write_fernet_key() {
  "$1" - "$2" <<'PY'
import base64
import os
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii") + "\n")
PY
}

require_command docker
require_command openssl

cd "$ROOT_DIR"
python_bin="$(detect_python)"

if [ ! -e secrets ]; then
  mkdir -p "$TMP_DIR/secrets"
  write_fernet_key "$python_bin" "$TMP_DIR/secrets/fernet.key"
  openssl rand -base64 32 > "$TMP_DIR/secrets/token_hash.key"
  openssl rand -base64 24 > "$TMP_DIR/secrets/db_password.txt"
  chmod 0400 "$TMP_DIR"/secrets/*
  ln -s "$TMP_DIR/secrets" secrets
  CREATED_SECRETS=1
fi

export COMPOSE_PROJECT_NAME POSTARA_HOST_BIND POSTARA_HOST_PORT

docker compose -f docker-compose.yml build postara
docker compose -f docker-compose.yml up -d postgres postara

health_url="http://$POSTARA_HOST_BIND:$POSTARA_HOST_PORT/health"
for _ in $(seq 1 30); do
  if "$python_bin" - "$health_url" <<'PY'
import json
import sys
import urllib.request

try:
    with urllib.request.urlopen(sys.argv[1], timeout=2) as response:
        body = json.loads(response.read().decode("utf-8"))
    raise SystemExit(0 if response.status == 200 and body.get("status") == "ok" else 1)
except Exception:
    raise SystemExit(1)
PY
  then
    break
  fi
  sleep 2
done

"$python_bin" - "$health_url" <<'PY'
import json
import sys
import urllib.request

with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
    body = json.loads(response.read().decode("utf-8"))
if response.status != 200 or body.get("status") != "ok":
    raise SystemExit("Health check failed.")
PY

docker compose -f docker-compose.yml exec -T postgres \
  psql -U postara -d postara -tAc "SELECT to_regclass('app.accounts'), to_regclass('audit.events')" \
  | grep -q "app.accounts|audit.events"

"$python_bin" - "$POSTARA_HOST_BIND" "$POSTARA_HOST_PORT" <<'PY'
import json
import sys
import urllib.error
import urllib.request

base_url = f"http://{sys.argv[1]}:{sys.argv[2]}"

payload = json.dumps({
    "email": "smoke-user@example.com",
    "password": "secret123",
    "name": "Smoke",
}).encode("utf-8")
request = urllib.request.Request(
    base_url + "/auth/register",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=5) as response:
    body = json.loads(response.read().decode("utf-8"))
if response.status != 201 or body.get("user", {}).get("role") != "owner":
    raise SystemExit("User registration smoke check failed.")
session_token = body["session_token"]

payload = json.dumps({
    "name": "smoke",
    "email": "smoke@example.com",
    "provider": "gmail",
    "password": "invalid-smoke-password",
}).encode("utf-8")
request = urllib.request.Request(
    base_url + "/mailboxes",
    data=payload,
    headers={"Content-Type": "application/json", "Authorization": f"Bearer {session_token}"},
    method="POST",
)
try:
    urllib.request.urlopen(request, timeout=10)
except urllib.error.HTTPError as exc:
    body = json.loads(exc.read().decode("utf-8"))
    if exc.code == 422 and body.get("error", {}).get("code") == "credentials_invalid":
        raise SystemExit(0)
    raise
raise SystemExit("Invalid IMAP credentials should be rejected.")
PY

uid="$(docker compose -f docker-compose.yml exec -T postara id -u)"
if [ "$uid" != "1000" ]; then
  echo "Postara container must run as uid 1000, got $uid." >&2
  exit 1
fi

if docker compose -f docker-compose.yml exec -T postara sh -c 'touch /app/.readonly-test' >/dev/null 2>&1; then
  echo "Postara container root filesystem is writable." >&2
  exit 1
fi

echo "Docker smoke test completed."
