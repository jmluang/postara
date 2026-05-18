#!/bin/sh
set -eu

SECRETS_DIR="${POSTARA_SECRETS_DIR:-/etc/postara/secrets}"

require_secret() {
  path="$SECRETS_DIR/$1"
  if [ ! -f "$path" ]; then
    echo "Missing required secret: $path" >&2
    exit 1
  fi

  mode="$(stat -c '%a' "$path")"
  if [ "$mode" != "400" ]; then
    echo "Secret must have 0400 permissions: $path" >&2
    exit 1
  fi

  if [ ! -s "$path" ]; then
    echo "Secret must not be empty: $path" >&2
    exit 1
  fi
}

require_optional_secret() {
  path="$SECRETS_DIR/$1"
  if [ -e "$path" ]; then
    require_secret "$1"
  fi
}

require_secret "fernet.key"
require_optional_secret "fernet.key.v2"
require_secret "token_hash.key"
require_optional_secret "token_hash.key.v2"
require_optional_secret "db_password.txt"

DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${POSTGRES_DB:-postara}"
DB_USER="${POSTGRES_USER:-postara}"

until pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; do
  echo "Waiting for Postgres at $DB_HOST:$DB_PORT..." >&2
  sleep 2
done

if [ -f alembic.ini ]; then
  python -m alembic upgrade head
elif [ "${POSTARA_REQUIRE_ALEMBIC:-0}" = "1" ]; then
  echo "POSTARA_REQUIRE_ALEMBIC=1 but alembic.ini is missing." >&2
  exit 1
fi

exec "$@"
