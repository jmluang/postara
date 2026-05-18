from postara.config import Settings


def test_settings_defaults_keep_app_and_audit_database_separate():
    settings = Settings()

    assert settings.app_database_url == settings.database_url
    assert settings.audit_database_url == settings.database_url
    assert settings.app_schema == "app"
    assert settings.audit_schema == "audit"
    assert settings.imap_workers == 8
    assert settings.deployment_mode == "self_host"


def test_settings_accepts_independent_audit_database_url():
    settings = Settings(
        database_url="postgresql+asyncpg://postara@postgres:5432/postara",
        audit_database_url="postgresql+asyncpg://audit@postgres:5432/postara_audit",
    )

    assert settings.app_database_url == "postgresql+asyncpg://postara@postgres:5432/postara"
    assert settings.audit_database_url == "postgresql+asyncpg://audit@postgres:5432/postara_audit"


def test_settings_reads_database_password_file(tmp_path):
    password_file = tmp_path / "db_password.txt"
    password_file.write_text("s3cr3t\n", encoding="utf-8")
    password_file.chmod(0o400)

    settings = Settings(
        database_url="postgresql+asyncpg://postara@postgres:5432/postara",
        db_password_file=str(password_file),
    )

    assert settings.database_url == "postgresql+asyncpg://postara:s3cr3t@postgres:5432/postara"
    assert settings.app_database_url == settings.database_url
    assert settings.audit_database_url == settings.database_url


def test_settings_reads_postara_toml(monkeypatch, tmp_path):
    config_file = tmp_path / "postara.toml"
    config_file.write_text(
        """
[database]
app_url = "postgresql+asyncpg://app@postgres:5432/appdb"
audit_url = "postgresql+asyncpg://audit@postgres:5432/auditdb"
app_schema = "custom_app"
audit_schema = "custom_audit"

[secrets]
directory = "/tmp/postara-secrets"

[imap]
workers = 3
read_timeout_seconds = 12
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("POSTARA_CONFIG", str(config_file))

    settings = Settings()

    assert settings.app_database_url == "postgresql+asyncpg://app@postgres:5432/appdb"
    assert settings.audit_database_url == "postgresql+asyncpg://audit@postgres:5432/auditdb"
    assert settings.app_schema == "custom_app"
    assert settings.audit_schema == "custom_audit"
    assert settings.secrets_dir == "/tmp/postara-secrets"
    assert settings.imap_workers == 3
    assert settings.imap_timeout_seconds == 12


def test_settings_normalizes_plain_postgres_urls_to_asyncpg():
    settings = Settings(
        database_url="postgresql://postara@postgres:5432/postara?pgbouncer=true",
        direct_url="postgres://postara@direct:5432/postara",
    )

    assert settings.database_url.startswith("postgresql+asyncpg://")
    assert "pgbouncer" not in settings.database_url
    assert "prepared_statement_cache_size=0" in settings.database_url
    assert settings.app_database_url.startswith("postgresql+asyncpg://")
    assert settings.audit_database_url.startswith("postgresql+asyncpg://")
    assert settings.direct_url.startswith("postgresql+asyncpg://")


def test_settings_accepts_hosted_deployment_mode(monkeypatch):
    monkeypatch.setenv("POSTARA_DEPLOYMENT_MODE", "hosted")

    settings = Settings()

    assert settings.deployment_mode == "hosted"
