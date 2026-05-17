from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from postara.config import Settings
from postara.crypto import CredentialCipher
from postara.security import hash_api_key
from postara.secrets import ensure_secret_file


_TOKEN_HASH_TEST_KEY = "pst_test_" + "0" * 8 + "." + "0" * 32


@dataclass(frozen=True)
class RuntimeSecrets:
    cipher: CredentialCipher
    token_hash_keys: dict[int, bytes]
    active_token_hash_version: int


def create_app_session_factory(settings: Settings) -> async_sessionmaker:
    engine = create_async_engine(
        settings.app_database_url,
        pool_pre_ping=True,
        **asyncpg_engine_kwargs(settings.app_database_url),
    )
    return async_sessionmaker(engine, expire_on_commit=False)


def create_audit_session_factory(settings: Settings) -> async_sessionmaker:
    engine = create_async_engine(
        settings.audit_database_url,
        pool_pre_ping=True,
        **asyncpg_engine_kwargs(settings.audit_database_url),
    )
    return async_sessionmaker(engine, expire_on_commit=False)


def asyncpg_engine_kwargs(url: str) -> dict:
    parsed = make_url(url)
    if parsed.drivername != "postgresql+asyncpg":
        return {}
    if str(parsed.query.get("prepared_statement_cache_size", "")) != "0":
        return {}
    return {
        "connect_args": {
            "statement_cache_size": 0,
            "prepared_statement_name_func": lambda: f"__asyncpg_{uuid4()}__",
        },
        "poolclass": NullPool,
    }


def load_runtime_secrets(settings: Settings) -> RuntimeSecrets:
    secrets_dir = Path(settings.secrets_dir)
    token_hash_keys = _load_versioned_secret(secrets_dir, "token_hash.key")
    active_token_hash_version = max(token_hash_keys)

    for token_hash_key in token_hash_keys.values():
        hash_api_key(_TOKEN_HASH_TEST_KEY, token_hash_key)

    return RuntimeSecrets(
        cipher=_load_credential_cipher(secrets_dir),
        token_hash_keys=token_hash_keys,
        active_token_hash_version=active_token_hash_version,
    )


def create_repository_account_service(settings: Settings):
    from postara.accounts import RepositoryAccountService

    runtime_secrets = load_runtime_secrets(settings)
    return RepositoryAccountService(
        create_app_session_factory(settings),
        audit_session_factory=create_audit_session_factory(settings),
        cipher=runtime_secrets.cipher,
        token_hash_keys=runtime_secrets.token_hash_keys,
        active_token_hash_version=runtime_secrets.active_token_hash_version,
    )


def create_repository_user_service(settings: Settings):
    from postara.users import RepositoryUserService

    runtime_secrets = load_runtime_secrets(settings)
    return RepositoryUserService(
        create_app_session_factory(settings),
        token_hash_keys=runtime_secrets.token_hash_keys,
        active_token_hash_version=runtime_secrets.active_token_hash_version,
    )


def default_cipher() -> CredentialCipher:
    return CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)


def _load_credential_cipher(secrets_dir: Path) -> CredentialCipher:
    keys = _load_versioned_secret(secrets_dir, "fernet.key")
    return CredentialCipher(keys, active_version=max(keys))


def _load_versioned_secret(secrets_dir: Path, filename: str) -> dict[int, bytes]:
    keys = {1: ensure_secret_file(secrets_dir / filename)}
    version = 2
    while True:
        path = secrets_dir / f"{filename}.v{version}"
        if not path.exists():
            break
        keys[version] = ensure_secret_file(path)
        version += 1
    return keys
