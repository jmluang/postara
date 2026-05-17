import base64
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from postara.crypto import CredentialCipher
from postara.models import AccountORM, AuditEventORM, AuditOutboxORM, Base
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
