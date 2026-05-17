from postara.models import AccountORM, ApiKeyORM, AuditEventORM, AuditOutboxORM, UserORM, UserSessionORM


def test_models_use_separate_app_and_audit_schemas():
    assert AccountORM.__table__.schema == "app"
    assert AuditOutboxORM.__table__.schema == "app"
    assert AuditEventORM.__table__.schema == "audit"
    assert UserORM.__table__.schema == "app"
    assert UserSessionORM.__table__.schema == "app"
    assert ApiKeyORM.__table__.schema == "app"


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
