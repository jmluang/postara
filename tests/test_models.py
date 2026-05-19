from datetime import datetime, timezone

from postara.models import (
    AccountORM,
    ApiKeyORM,
    AuditEventORM,
    AuditOutboxORM,
    AuthAttemptBucketORM,
    PendingMailboxVerificationORM,
    UserORM,
    UserSessionORM,
)


def test_models_use_separate_app_and_audit_schemas():
    assert AccountORM.__table__.schema == "app"
    assert AuditOutboxORM.__table__.schema == "app"
    assert AuditEventORM.__table__.schema == "audit"
    assert UserORM.__table__.schema == "app"
    assert AuthAttemptBucketORM.__table__.schema == "app"
    assert UserSessionORM.__table__.schema == "app"
    assert ApiKeyORM.__table__.schema == "app"
    assert PendingMailboxVerificationORM.__table__.schema == "app"


def test_schema_has_no_durable_message_tables():
    table_names = {table.name for table in AccountORM.metadata.sorted_tables}

    assert "messages" not in table_names
    assert "message_bodies" not in table_names
    assert "message_metadata" not in table_names


def test_account_dto_excludes_sensitive_fields():
    account = AccountORM(
        id=1,
        name="work",
        email="work@example.com",
        provider="gmail",
        auth_type="app_password",
        encrypted_password=b"ciphertext",
        key_version=1,
        imap_host="imap.gmail.com",
        imap_port=993,
        api_key_prefix="a8f3k29x",
        api_key_hash=b"digest",
        api_key_hash_version=1,
    )

    dto = account.to_dto()

    assert dto["email"] == "work@example.com"
    assert "encrypted_password" not in dto
    assert "api_key_hash" not in dto


def test_user_dto_hides_password_hash():
    user = UserORM(
        id=1,
        email="user@example.com",
        name="User",
        role="owner",
        password_hash="$argon2id$secret",
    )

    dto = user.to_dto()

    assert dto["email"] == "user@example.com"
    assert dto["role"] == "owner"
    assert "password_hash" not in dto


def test_api_key_dto_hides_hash_and_keeps_prefix():
    key = ApiKeyORM(
        id=1,
        user_id=2,
        name="Production",
        prefix="abc12345",
        key_hash=b"digest",
        hash_version=1,
    )

    dto = key.to_dto()

    assert dto["prefix"] == "abc12345"
    assert dto["status"] == "active"
    assert "key_hash" not in dto


def test_oauth_account_dto_hides_tokens_and_keeps_canonical_email():
    account = AccountORM(
        id=1,
        user_id=2,
        name="oauth-gmail",
        email="oauth@example.com",
        provider="gmail",
        auth_type="oauth2",
        encrypted_password=None,
        key_version=None,
        oauth_refresh_token=b"refresh",
        oauth_access_token=b"access",
        oauth_token_expires_at=datetime.now(timezone.utc),
        oauth_scopes=["openid", "email"],
        oauth_subject="google-sub",
        oauth_email="oauth@example.com",
        imap_host="imap.gmail.com",
        imap_port=993,
        api_key_prefix="abc12345",
        api_key_hash=b"digest",
        api_key_hash_version=1,
    )

    dto = account.to_dto()

    assert dto["auth_type"] == "oauth2"
    assert dto["email"] == "oauth@example.com"
    assert "oauth_refresh_token" not in dto
    assert "oauth_access_token" not in dto
    assert "encrypted_password" not in dto


def test_pending_mailbox_verification_dto_hides_password_and_code_hash():
    row = PendingMailboxVerificationORM(
        id="mailbox_verify_abc123",
        user_id=1,
        provider="gmail",
        auth_type="app_password",
        name="Work",
        email="work@example.com",
        encrypted_password=b"ciphertext",
        key_version=1,
        code_hash=b"hash",
        code_hash_version=1,
        attempts=0,
        status="verifying",
        expires_at=datetime.now(timezone.utc),
    )

    dto = row.to_dto()

    assert dto["id"] == "mailbox_verify_abc123"
    assert dto["status"] == "verifying"
    assert "encrypted_password" not in dto
    assert "code_hash" not in dto
