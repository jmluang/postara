import os
import subprocess
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPT = ROOT_DIR / "scripts" / "run_local.sh"


def test_run_local_script_is_executable_and_exposes_help():
    assert os.access(SCRIPT, os.X_OK)

    result = subprocess.run(
        [str(SCRIPT), "--help"],
        cwd=ROOT_DIR,
        check=True,
        text=True,
        capture_output=True,
    )

    assert "Usage: scripts/run_local.sh" in result.stdout
    assert "COURIER_HOST" in result.stdout
    assert "COURIER_PORT" in result.stdout
    assert "BUILD_FRONTEND" in result.stdout
    assert "FRONTEND_NODE" not in result.stdout
    assert "RESET_ADMIN_TOKEN" not in result.stdout
    assert "ADMIN_TOKEN_OUTPUT" not in result.stdout


def test_run_local_script_loads_env_migrates_and_runs_uvicorn():
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"' in script
    assert "set -a" in script
    assert 'BUILD_FRONTEND="${BUILD_FRONTEND:-0}"' in script
    assert "BUILD_FRONTEND=1 is not supported" in script
    assert 'frontend/dist/index.html' in script
    assert '"$PYTHON_BIN" -m alembic upgrade head' in script
    assert '"$PYTHON_BIN" -m uvicorn courier.api:app' in script
    assert 'COURIER_PORT="${COURIER_PORT:-18080}"' in script
    assert "Create the first user in the browser" in script
    assert "ADMIN_TOKEN_OUTPUT" not in script
    assert "RESET_ADMIN_TOKEN" not in script
