from __future__ import annotations

import stat
from pathlib import Path


class SecretFileError(RuntimeError):
    pass


def ensure_secret_file(path: str | Path) -> bytes:
    secret_path = Path(path)
    if not secret_path.exists():
        raise SecretFileError(f"Secret file does not exist: {secret_path}")
    if not secret_path.is_file():
        raise SecretFileError(f"Secret path is not a file: {secret_path}")

    mode = stat.S_IMODE(secret_path.stat().st_mode)
    if mode != stat.S_IRUSR:
        raise SecretFileError(f"Secret file must have 0400 permissions: {secret_path}")

    data = secret_path.read_bytes().strip()
    if not data:
        raise SecretFileError(f"Secret file must not be empty: {secret_path}")
    return data
