#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
DATA_BACKUP_DIR="${DATA_BACKUP_DIR:-/backup/courier}"
SECRETS_SOURCE_DIR="${SECRETS_SOURCE_DIR:-/opt/courier}"
SECRETS_BACKUP_DIR="${SECRETS_BACKUP_DIR:-/backup-secrets}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

device_id() {
  stat -c '%d' "$1" 2>/dev/null || echo "unknown"
}

require_command docker
require_command tar
require_command stat
require_command find

mkdir -p "$DATA_BACKUP_DIR" "$SECRETS_BACKUP_DIR"

data_dir_real="$(cd "$DATA_BACKUP_DIR" && pwd -P)"
secrets_backup_real="$(cd "$SECRETS_BACKUP_DIR" && pwd -P)"
if [ "$data_dir_real" = "$secrets_backup_real" ]; then
  echo "Database backups and secrets backups must use different directories." >&2
  exit 1
fi

if [ "${ALLOW_SAME_BACKUP_DEVICE:-0}" != "1" ] \
  && [ "$(device_id "$data_dir_real")" = "$(device_id "$secrets_backup_real")" ]; then
  echo "Database backups and secrets backups must be on different devices." >&2
  echo "Set ALLOW_SAME_BACKUP_DEVICE=1 only for local development." >&2
  exit 1
fi

if [ ! -d "$SECRETS_SOURCE_DIR/secrets" ]; then
  echo "Secrets source directory does not contain a secrets/ child: $SECRETS_SOURCE_DIR" >&2
  exit 1
fi

db_backup="$DATA_BACKUP_DIR/db-$TIMESTAMP.dump"
secrets_backup="$SECRETS_BACKUP_DIR/secrets-$TIMESTAMP.tar.gz"

echo "Writing database backup to $db_backup"
docker compose -f "$COMPOSE_FILE" exec -T postgres pg_dump \
  -U courier \
  --format=custom \
  --schema=app \
  --schema=audit \
  courier > "$db_backup"
chmod 0600 "$db_backup"

echo "Writing secrets archive to $secrets_backup"
tar -czf "$secrets_backup" -C "$SECRETS_SOURCE_DIR" secrets
chmod 0600 "$secrets_backup"

find "$DATA_BACKUP_DIR" -type f -name 'db-*.dump' -mtime +"$RETENTION_DAYS" -delete
find "$SECRETS_BACKUP_DIR" -type f -name 'secrets-*.tar.gz' -mtime +"$RETENTION_DAYS" -delete

echo "Backup completed."
