import base64
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from postara.crypto import CredentialCipher
from postara.accounts import MailboxVerificationFailedError, RepositoryAccountService
from postara.audit import AuditEvent
from postara.credentials import OAuth2Credential
from postara.models import AccountORM, AuditEventORM, AuditOutboxORM, Base, PendingMailboxVerificationORM
from postara.oauth import OAuthAccessTokenResult
from postara.repositories import AccountRepository, AuditOutboxRepository, AuditRepository, dispatch_audit_outbox


@pytest.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.execute(text("ATTACH DATABASE ':memory:' AS app"))
        await conn.execute(text("ATTACH DATABASE ':memory:' AS audit"))
        await conn.run_sync(Base.metadata.create_all)

    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


@pytest.mark.anyio
async def test_account_repository_persists_keyed_hash_and_hides_secrets(session_factory):
    cipher = CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)
    token_hash_key = base64.urlsafe_b64encode(b"repo-token-hash-key-material-32!!")

    async with session_factory() as session:
        repo = AccountRepository(session, cipher=cipher, token_hash_key=token_hash_key)
        account, raw_key = await repo.create(
            name="work",
            email="work@example.com",
            provider="gmail",
            password="app-password",
        )
        await session.commit()

    async with session_factory() as session:
        repo = AccountRepository(session, cipher=cipher, token_hash_key=token_hash_key)
        authenticated = await repo.get_by_api_key(raw_key)

        assert authenticated.id == account.id
        assert authenticated.to_dto()["email"] == "work@example.com"
        assert "encrypted_password" not in authenticated.to_dto()


@pytest.mark.anyio
async def test_audit_outbox_repository_enqueues_sanitized_event(session_factory):
    async with session_factory() as session:
        outbox = AuditOutboxRepository(session)
        await outbox.enqueue(
            {
                "action": "apikey.rotate",
                "extra": {"api_key": "raw", "safe": "ok"},
            }
        )
        await session.commit()

    async with session_factory() as session:
        row = (await session.scalars(select(AuditOutboxORM))).one()
        assert row.event["extra"] == {"api_key": "[REDACTED]", "safe": "ok"}


@pytest.mark.anyio
async def test_audit_outbox_repository_serializes_audit_event_timestamp(session_factory):
    timestamp = datetime.now(timezone.utc)

    async with session_factory() as session:
        outbox = AuditOutboxRepository(session)
        await outbox.enqueue(
            AuditEvent(
                timestamp=timestamp,
                action="mailbox.oauth_completed",
                actor_type="user",
                actor_id="1",
                client_ip="127.0.0.1",
                user_agent="tests",
                request_id="req_oauth",
                target_account_id=1,
                status="success",
                extra={"email": "user@example.com"},
            )
        )
        await session.commit()

    async with session_factory() as session:
        row = (await session.scalars(select(AuditOutboxORM))).one()
        assert row.event["timestamp"] == timestamp.isoformat()


@pytest.mark.anyio
async def test_audit_outbox_dispatches_to_audit_schema(session_factory):
    async with session_factory() as session:
        outbox = AuditOutboxRepository(session)
        await outbox.enqueue(
            {
                "action": "account.create",
                "actor_type": "admin",
                "actor_id": None,
                "client_ip": "127.0.0.1",
                "user_agent": "tests",
                "request_id": "req_1234567890abcdef",
                "target_account_id": 1,
                "status": "success",
                "extra": {"password": "secret", "safe": "ok"},
            }
        )
        await session.commit()

    delivered = await dispatch_audit_outbox(session_factory, session_factory)

    async with session_factory() as session:
        event = (await session.scalars(select(AuditEventORM))).one()
        outbox_row = (await session.scalars(select(AuditOutboxORM))).one()

        assert delivered == 1
        assert event.action == "account.create"
        assert event.extra == {"password": "[REDACTED]", "safe": "ok"}
        assert outbox_row.delivered_at is not None


@pytest.mark.anyio
async def test_audit_repository_purges_events_before_cutoff(session_factory):
    old_timestamp = datetime.now(timezone.utc) - timedelta(days=91)
    fresh_timestamp = datetime.now(timezone.utc)

    async with session_factory() as session:
        audit = AuditRepository(session)
        await audit.append(
            {
                "timestamp": old_timestamp,
                "action": "message.list",
                "actor_type": "account_key",
                "actor_id": "1",
                "client_ip": "127.0.0.1",
                "user_agent": "tests",
                "request_id": "req_old",
                "status": "success",
            }
        )
        await audit.append(
            {
                "timestamp": fresh_timestamp,
                "action": "message.list",
                "actor_type": "account_key",
                "actor_id": "1",
                "client_ip": "127.0.0.1",
                "user_agent": "tests",
                "request_id": "req_new",
                "status": "success",
            }
        )
        removed = await audit.purge_before(datetime.now(timezone.utc) - timedelta(days=90))
        await session.commit()

    async with session_factory() as session:
        events = list(await session.scalars(select(AuditEventORM).order_by(AuditEventORM.request_id)))

        assert removed == 1
        assert [event.request_id for event in events] == ["req_new"]


@pytest.mark.anyio
async def test_account_repository_verifies_stored_hash_version_after_rotation(session_factory):
    cipher = CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)
    token_hash_keys = {
        1: base64.urlsafe_b64encode(b"repo-token-hash-key-version-01!!"),
        2: base64.urlsafe_b64encode(b"repo-token-hash-key-version-02!!"),
    }

    async with session_factory() as session:
        repo = AccountRepository(
            session,
            cipher=cipher,
            token_hash_keys=token_hash_keys,
            active_token_hash_version=1,
        )
        account, old_key = await repo.create(
            name="work",
            email="work@example.com",
            provider="gmail",
            password="app-password",
        )
        await session.commit()

    async with session_factory() as session:
        repo = AccountRepository(
            session,
            cipher=cipher,
            token_hash_keys=token_hash_keys,
            active_token_hash_version=2,
        )
        authenticated = await repo.get_by_api_key(old_key)
        _account, new_key = await repo.rotate_api_key(account.id, old_key)
        await session.commit()

        assert authenticated.id == account.id

    async with session_factory() as session:
        repo = AccountRepository(
            session,
            cipher=cipher,
            token_hash_keys=token_hash_keys,
            active_token_hash_version=2,
        )
        rotated = await repo.get_by_api_key(new_key)

        assert rotated.api_key_hash_version == 2


def test_account_repository_requires_explicit_token_hash_key():
    cipher = CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)

    with pytest.raises(ValueError, match="Token hash keys are required"):
        AccountRepository(object(), cipher=cipher)


class FakeOAuthRefresher:
    def __init__(self) -> None:
        self.calls = []

    async def refresh_access_token(self, *, refresh_token: str, scopes: tuple[str, ...]) -> OAuthAccessTokenResult:
        self.calls.append((refresh_token, scopes))
        return OAuthAccessTokenResult(
            access_token="new-access-token",
            expires_at=datetime(2026, 5, 18, 16, 0, tzinfo=timezone.utc),
            scopes=scopes,
        )


@pytest.mark.anyio
async def test_repository_account_service_refreshes_expired_oauth_access_token(session_factory):
    cipher = CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)
    token_hash_key = base64.urlsafe_b64encode(b"repo-token-hash-key-material-32!!")
    refresher = FakeOAuthRefresher()
    service = RepositoryAccountService(
        session_factory,
        audit_session_factory=session_factory,
        cipher=cipher,
        token_hash_keys={1: token_hash_key},
        active_token_hash_version=1,
        oauth_refreshers={"gmail": refresher},
    )
    account = await service.create_with_oauth(
        user_id=1,
        name="gmail",
        email="typed@example.com",
        provider="gmail",
        refresh_token="refresh-token",
        access_token="old-access-token",
        expires_at=datetime(2026, 5, 18, 10, 0, tzinfo=timezone.utc),
        scopes=("openid", "email", "https://mail.google.com/"),
        subject="google-subject",
        oauth_email="provider@example.com",
    )

    credential = await service.get_credential_for_runtime(
        account.id,
        now=datetime(2026, 5, 18, 14, 0, tzinfo=timezone.utc),
    )

    assert credential == OAuth2Credential(
        access_token="new-access-token",
        scopes=("openid", "email", "https://mail.google.com/"),
        expires_at=datetime(2026, 5, 18, 16, 0, tzinfo=timezone.utc),
    )
    assert refresher.calls == [("refresh-token", ("openid", "email", "https://mail.google.com/"))]

    async with session_factory() as session:
        repo = AccountRepository(session, cipher=cipher, token_hash_key=token_hash_key)
        persisted = await repo.get_by_id(account.id)
        assert cipher.decrypt(persisted.oauth_access_token, persisted.key_version) == "new-access-token"


@pytest.mark.anyio
async def test_account_repository_allows_same_email_for_different_users(session_factory):
    cipher = CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)
    token_hash_key = base64.urlsafe_b64encode(b"repo-token-hash-key-material-32!!")

    async with session_factory() as session:
        repo = AccountRepository(session, cipher=cipher, token_hash_key=token_hash_key)
        first, _first_key = await repo.create(
            user_id=1,
            name="first",
            email="shared@example.com",
            provider="gmail",
            password="app-password",
        )
        second, _second_key = await repo.create(
            user_id=2,
            name="second",
            email="shared@example.com",
            provider="gmail",
            password="app-password",
        )
        await session.commit()

    async with session_factory() as session:
        accounts = list(await session.scalars(select(AccountORM).order_by(AccountORM.id)))

    assert [account.id for account in accounts] == [first.id, second.id]
    assert [account.email for account in accounts] == ["shared@example.com", "shared@example.com"]


@pytest.mark.anyio
async def test_account_repository_creates_oauth_account_with_provider_email(session_factory):
    cipher = CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)
    token_hash_key = base64.urlsafe_b64encode(b"repo-token-hash-key-material-32!!")

    async with session_factory() as session:
        repo = AccountRepository(session, cipher=cipher, token_hash_key=token_hash_key)
        account = await repo.create_with_oauth(
            user_id=1,
            name="oauth-gmail",
            email="typed@example.com",
            provider="gmail",
            refresh_token="refresh-token",
            access_token="access-token",
            expires_at=None,
            scopes=("openid", "email"),
            subject="google-sub",
            oauth_email="provider@example.com",
        )
        await session.commit()

    async with session_factory() as session:
        stored = (await session.scalars(select(AccountORM))).one()

        assert stored.id == account.id
        assert stored.auth_type == "oauth2"
        assert stored.email == "provider@example.com"
        assert stored.oauth_email == "provider@example.com"
        assert stored.oauth_subject == "google-sub"
        assert stored.oauth_scopes == ["openid", "email"]
        assert stored.encrypted_password is None
        assert stored.key_version is not None
        assert stored.oauth_refresh_token is not None
        assert stored.oauth_access_token is not None
        assert b"refresh-token" not in stored.oauth_refresh_token


@pytest.mark.anyio
async def test_account_repository_completes_pending_app_password_verification(session_factory):
    cipher = CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)
    token_hash_key = base64.urlsafe_b64encode(b"repo-token-hash-key-material-32!!")

    async with session_factory() as session:
        repo = AccountRepository(session, cipher=cipher, token_hash_key=token_hash_key)
        pending = await repo.create_pending_app_password_verification(
            user_id=1,
            name="work",
            email="work@example.com",
            provider="gmail",
            password="app-password",
            code="123456",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        )
        account = await repo.complete_pending_app_password_verification(
            user_id=1,
            verification_id=pending.id,
            code="123456",
        )
        await session.commit()

    async with session_factory() as session:
        stored_pending = (await session.scalars(select(PendingMailboxVerificationORM))).one()
        stored_account = (await session.scalars(select(AccountORM))).one()

        assert stored_pending.status == "verified"
        assert stored_pending.mailbox_id == account.id
        assert stored_pending.code_hash != b"123456"
        assert stored_pending.encrypted_password != b"app-password"
        assert stored_account.email == "work@example.com"
        assert stored_account.auth_type == "app_password"


@pytest.mark.anyio
async def test_account_repository_tracks_invalid_pending_verification_attempts(session_factory):
    cipher = CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)
    token_hash_key = base64.urlsafe_b64encode(b"repo-token-hash-key-material-32!!")

    async with session_factory() as session:
        repo = AccountRepository(session, cipher=cipher, token_hash_key=token_hash_key)
        pending = await repo.create_pending_app_password_verification(
            user_id=1,
            name="work",
            email="work@example.com",
            provider="gmail",
            password="app-password",
            code="123456",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        )
        with pytest.raises(MailboxVerificationFailedError):
            await repo.complete_pending_app_password_verification(user_id=1, verification_id=pending.id, code="000000")
        await session.commit()

    async with session_factory() as session:
        stored_pending = (await session.scalars(select(PendingMailboxVerificationORM))).one()

        assert stored_pending.status == "verifying"
        assert stored_pending.attempts == 1
