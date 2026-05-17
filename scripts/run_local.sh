#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"
POSTARA_HOST="${POSTARA_HOST:-127.0.0.1}"
POSTARA_PORT="${POSTARA_PORT:-18080}"
RUN_MIGRATIONS="${RUN_MIGRATIONS:-1}"
BUILD_FRONTEND="${BUILD_FRONTEND:-0}"
PYTHON_BIN="${PYTHON_BIN:-}"

usage() {
  cat <<'EOF'
Usage: scripts/run_local.sh [--help]

Run Postara locally without Docker.

Environment:
  ENV_FILE        Path to env file. Default: .env
  PYTHON_BIN      Python executable. Default: .venv/bin/python, then python3
  POSTARA_HOST    Bind host. Default: 127.0.0.1
  POSTARA_PORT    Bind port. Default: 18080
  RUN_MIGRATIONS  Run alembic upgrade head before start. Default: 1
  BUILD_FRONTEND  Unsupported in this public repo. Default: 0
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

detect_python() {
  if [ -n "$PYTHON_BIN" ]; then
    if ! python_version_ok "$PYTHON_BIN"; then
      echo "PYTHON_BIN must point to Python 3.10 or newer: $PYTHON_BIN" >&2
      exit 1
    fi
    printf '%s\n' "$PYTHON_BIN"
  elif [ -x "$ROOT_DIR/.venv/bin/python" ]; then
    if ! python_version_ok "$ROOT_DIR/.venv/bin/python"; then
      echo "Recreating local Python environment with Python 3.10 or newer." >&2
      rm -rf "$ROOT_DIR/.venv"
      create_venv
      return
    fi
    printf '%s\n' "$ROOT_DIR/.venv/bin/python"
  else
    create_venv
  fi
}

python_version_ok() {
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

find_compatible_python() {
  local candidate
  for candidate in python3.13 python3.12 python3.11 python3.10 python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 /Library/Frameworks/Python.framework/Versions/3.10/bin/python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      candidate="$(command -v "$candidate")"
    elif [ ! -x "$candidate" ]; then
      continue
    fi

    if python_version_ok "$candidate"; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  echo "Missing Python 3.10 or newer." >&2
  exit 1
}

create_venv() {
  local python
  python="$(find_compatible_python)"
  echo "Creating local Python environment at $ROOT_DIR/.venv with $python" >&2
  "$python" -m venv "$ROOT_DIR/.venv"
  printf '%s\n' "$ROOT_DIR/.venv/bin/python"
}

ensure_dependencies() {
  if "$PYTHON_BIN" -c "import postara, uvicorn, alembic" >/dev/null 2>&1; then
    return
  fi

  echo "Installing local Python dependencies..." >&2
  "$PYTHON_BIN" -m pip install --upgrade pip setuptools wheel
  "$PYTHON_BIN" -m pip install -e '.[dev]'

  if ! "$PYTHON_BIN" -c "import postara, uvicorn, alembic" >/dev/null 2>&1; then
    echo "Failed to install local Python dependencies." >&2
    exit 1
  fi
}

cd "$ROOT_DIR"

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing env file: $ENV_FILE" >&2
  echo "Create .env first, or set ENV_FILE=/path/to/env." >&2
  exit 1
fi

PYTHON_BIN="$(detect_python)"

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

export POSTARA_SECRETS_DIR="${POSTARA_SECRETS_DIR:-$ROOT_DIR/secrets}"
mkdir -p "$POSTARA_SECRETS_DIR"

ensure_dependencies

if [ "$RUN_MIGRATIONS" = "1" ]; then
  "$PYTHON_BIN" -m alembic upgrade head
fi

if [ "$BUILD_FRONTEND" = "1" ]; then
  echo "BUILD_FRONTEND=1 is not supported in this public repo because frontend source is not included." >&2
  echo "Build the private frontend separately and copy its app-only dist into frontend/dist." >&2
  exit 1
fi

if [ ! -f "$ROOT_DIR/frontend/dist/index.html" ]; then
  echo "Missing frontend/dist/index.html." >&2
  echo "This public repo ships only the prebuilt /app frontend dist, not frontend source." >&2
  exit 1
fi

echo "Starting Postara at http://$POSTARA_HOST:$POSTARA_PORT/" >&2
echo "Create the first user in the browser; that user becomes owner." >&2
exec "$PYTHON_BIN" -m uvicorn postara.api:app --host "$POSTARA_HOST" --port "$POSTARA_PORT"
