from __future__ import annotations

import os
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

from courier.secrets import ensure_secret_file

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    database_url: str = "postgresql+asyncpg://courier@postgres:5432/courier"
    direct_url: str | None = None
    app_database_url: str | None = None
    audit_database_url: str | None = None
    db_password_file: str | None = None
    app_schema: str = "app"
    audit_schema: str = "audit"
    imap_workers: int = 8
    imap_timeout_seconds: float = 30.0
    secrets_dir: str = Field(
        default="/etc/courier/secrets",
        validation_alias=AliasChoices("COURIER_SECRETS_DIR", "SECRETS_DIR"),
    )
    cors_allowed_origins: list[str] = []

    def __init__(self, **data):
        config_defaults = _load_config_defaults(os.environ.get("COURIER_CONFIG"))
        for key, value in config_defaults.items():
            if key not in data and key.upper() not in os.environ:
                data[key] = value
        super().__init__(**data)

    @model_validator(mode="after")
    def default_split_database_urls(self) -> "Settings":
        self.database_url = _asyncpg_url(self.database_url)
        if self.direct_url is not None:
            self.direct_url = _asyncpg_url(self.direct_url)
        if self.app_database_url is None:
            self.app_database_url = self.database_url
        else:
            self.app_database_url = _asyncpg_url(self.app_database_url)
        if self.audit_database_url is None:
            self.audit_database_url = self.database_url
        else:
            self.audit_database_url = _asyncpg_url(self.audit_database_url)
        if self.db_password_file:
            password = ensure_secret_file(Path(self.db_password_file)).decode("utf-8")
            self.database_url = _url_with_password(self.database_url, password)
            self.app_database_url = _url_with_password(self.app_database_url, password)
            self.audit_database_url = _url_with_password(self.audit_database_url, password)
        return self


def _url_with_password(url: str, password: str) -> str:
    parsed = make_url(url)
    if parsed.password is not None:
        return url
    return parsed.set(password=password).render_as_string(hide_password=False)


def _asyncpg_url(url: str) -> str:
    parsed = make_url(url)
    if parsed.drivername in {"postgres", "postgresql"}:
        parsed = parsed.set(drivername="postgresql+asyncpg")
    if parsed.drivername == "postgresql+asyncpg" and "pgbouncer" in parsed.query:
        parsed = parsed.difference_update_query(["pgbouncer"])
        parsed = parsed.update_query_dict({"prepared_statement_cache_size": "0"})
    if parsed.drivername == "postgresql+asyncpg":
        return parsed.render_as_string(hide_password=False)
    return url


def _load_config_defaults(config_path: str | None) -> dict:
    if not config_path:
        return {}
    path = Path(config_path)
    if not path.exists():
        return {}

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    database = data.get("database", {})
    secrets = data.get("secrets", {})
    imap = data.get("imap", {})
    defaults = {
        "database_url": database.get("app_url"),
        "app_database_url": database.get("app_url"),
        "audit_database_url": database.get("audit_url"),
        "db_password_file": database.get("password_file"),
        "app_schema": database.get("app_schema"),
        "audit_schema": database.get("audit_schema"),
        "secrets_dir": secrets.get("directory"),
        "imap_workers": imap.get("workers"),
        "imap_timeout_seconds": imap.get("read_timeout_seconds") or imap.get("connect_timeout_seconds"),
    }
    return {key: value for key, value in defaults.items() if value is not None}
