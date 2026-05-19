from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

from postara.secrets import ensure_secret_file

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    database_url: str = "postgresql+asyncpg://postara@postgres:5432/postara"
    direct_url: str | None = None
    app_database_url: str | None = None
    audit_database_url: str | None = None
    db_password_file: str | None = None
    app_schema: str = "app"
    audit_schema: str = "audit"
    imap_workers: int = 8
    imap_timeout_seconds: float = 30.0
    deployment_mode: Literal["self_host", "hosted"] = Field(
        default="self_host",
        validation_alias=AliasChoices("POSTARA_DEPLOYMENT_MODE", "DEPLOYMENT_MODE"),
    )
    google_oauth_client_id: str | None = Field(default=None, validation_alias="GOOGLE_OAUTH_CLIENT_ID")
    google_oauth_client_secret: str | None = Field(default=None, validation_alias="GOOGLE_OAUTH_CLIENT_SECRET")
    google_oauth_redirect_uri: str | None = Field(default=None, validation_alias="GOOGLE_OAUTH_REDIRECT_URI")
    google_oauth_scopes: list[str] = []
    oauth_state_secret_v1: str | None = Field(
        default=None,
        validation_alias=AliasChoices("OAUTH_STATE_SECRET_V1", "OAUTH_STATE_SECRET"),
    )
    oauth_state_active_version: int = Field(default=1, validation_alias="OAUTH_STATE_ACTIVE_VERSION")
    secrets_dir: str = Field(
        default="/etc/postara/secrets",
        validation_alias=AliasChoices("POSTARA_SECRETS_DIR", "SECRETS_DIR"),
    )
    cors_allowed_origins: list[str] = []
    auth_protection_enabled: bool = Field(default=True, validation_alias="AUTH_PROTECTION_ENABLED")
    auth_emergency_bypass: bool = Field(default=False, validation_alias="AUTH_EMERGENCY_BYPASS")
    auth_failure_limit: int = Field(default=5, validation_alias="AUTH_FAILURE_LIMIT")
    auth_challenge_threshold: int = Field(default=3, validation_alias="AUTH_CHALLENGE_THRESHOLD")
    auth_window_seconds: int = Field(default=300, validation_alias="AUTH_WINDOW_SECONDS")
    auth_lock_seconds: int = Field(default=300, validation_alias="AUTH_LOCK_SECONDS")
    turnstile_secret_key: str | None = Field(default=None, validation_alias="TURNSTILE_SECRET_KEY")
    trusted_proxy_cidrs: list[str] = []

    def __init__(self, **data):
        config_defaults = _load_config_defaults(os.environ.get("POSTARA_CONFIG"))
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
    security = data.get("security", {})
    defaults = {
        "database_url": database.get("app_url"),
        "app_database_url": database.get("app_url"),
        "audit_database_url": database.get("audit_url"),
        "db_password_file": database.get("password_file"),
        "app_schema": database.get("app_schema"),
        "audit_schema": database.get("audit_schema"),
        "deployment_mode": data.get("deployment_mode"),
        "google_oauth_client_id": data.get("google_oauth_client_id"),
        "google_oauth_client_secret": data.get("google_oauth_client_secret"),
        "google_oauth_redirect_uri": data.get("google_oauth_redirect_uri"),
        "google_oauth_scopes": data.get("google_oauth_scopes"),
        "oauth_state_secret_v1": data.get("oauth_state_secret_v1"),
        "oauth_state_active_version": data.get("oauth_state_active_version"),
        "secrets_dir": secrets.get("directory"),
        "imap_workers": imap.get("workers"),
        "imap_timeout_seconds": imap.get("read_timeout_seconds") or imap.get("connect_timeout_seconds"),
        "auth_protection_enabled": security.get("auth_protection_enabled"),
        "auth_emergency_bypass": security.get("auth_emergency_bypass"),
        "auth_failure_limit": security.get("auth_failure_limit"),
        "auth_challenge_threshold": security.get("auth_challenge_threshold"),
        "auth_window_seconds": security.get("auth_window_seconds"),
        "auth_lock_seconds": security.get("auth_lock_seconds"),
        "turnstile_secret_key": security.get("turnstile_secret_key"),
        "trusted_proxy_cidrs": security.get("trusted_proxy_cidrs"),
    }
    return {key: value for key, value in defaults.items() if value is not None}
