from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from postara.accounts import AccountNotFoundError, DuplicateEmailError
from postara.audit import AuditEvent, sanitize_extra
from postara.crypto import CredentialCipher
from postara.models import AccountORM, AuditEventORM, AuditOutboxORM
from postara.security import generate_api_key, hash_api_key, parse_api_key, verify_api_key_hash


class AccountRepository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        cipher: CredentialCipher,
        token_hash_key: bytes | None = None,
        token_hash_keys: dict[int, bytes] | None = None,
        active_token_hash_version: int = 1,
    ) -> None:
        self._session = session
        self._cipher = cipher
        if token_hash_keys is None and token_hash_key is None:
            raise ValueError("Token hash keys are required.")
        if token_hash_keys is None:
            token_hash_keys = {active_token_hash_version: token_hash_key}
        if active_token_hash_version not in token_hash_keys:
            raise ValueError("Active token hash key version is not available.")
        self._token_hash_keys = token_hash_keys
        self._active_token_hash_version = active_token_hash_version

    async def create(
        self,
        *,
        name: str,
        email: str,
        provider: str,
        password: str,
        user_id: int | None = None,
    ) -> tuple[AccountORM, str]:
        if provider != "gmail":
            raise ValueError("Only gmail is supported in v0.1.")

        api_key = generate_api_key("live")
        parts = parse_api_key(api_key)
        encrypted = self._cipher.encrypt(password)
        account = AccountORM(
            user_id=user_id,
            name=name,
            email=email,
            provider=provider,
            auth_type="app_password",
            encrypted_password=encrypted.ciphertext,
            key_version=encrypted.key_version,
            imap_host="imap.gmail.com",
            imap_port=993,
            api_key_prefix=parts.prefix,
            api_key_hash=hash_api_key(api_key, self._active_token_hash_key()),
            api_key_hash_version=self._active_token_hash_version,
        )
        self._session.add(account)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise DuplicateEmailError(email) from exc
        return account, api_key

    async def assign_user(self, account_id: int, user_id: int) -> AccountORM:
        account = await self.get_by_id(account_id)
        account.user_id = user_id
        await self._session.flush()
        return account

    async def list(self) -> list[AccountORM]:
        result = await self._session.scalars(select(AccountORM).order_by(AccountORM.id))
        return list(result)

    async def list_for_user(self, user_id: int) -> list[AccountORM]:
        result = await self._session.scalars(
            select(AccountORM).where(AccountORM.user_id == user_id).order_by(AccountORM.id)
        )
        return list(result)

    async def get_by_id(self, account_id: int) -> AccountORM:
        account = await self._session.get(AccountORM, account_id)
        if account is None:
            raise AccountNotFoundError(account_id)
        return account

    async def get_for_user(self, user_id: int, account_id: int) -> AccountORM:
        account = await self.get_by_id(account_id)
        if account.user_id != user_id:
            raise AccountNotFoundError(account_id)
        return account

    async def get_by_api_key(self, raw_key: str) -> AccountORM:
        parts = parse_api_key(raw_key)
        result = await self._session.scalars(
            select(AccountORM).where(AccountORM.api_key_prefix == parts.prefix).limit(1)
        )
        account = result.first()
        if account is None:
            raise AccountNotFoundError("api key")
        token_hash_key = self._token_hash_keys.get(account.api_key_hash_version)
        if token_hash_key is None or not verify_api_key_hash(raw_key, account.api_key_hash, token_hash_key):
            raise AccountNotFoundError("api key")
        account.last_used_at = datetime.now(timezone.utc)
        await self._session.flush()
        return account

    async def require_key_for_account(self, account_id: int, raw_key: str) -> AccountORM:
        account = await self.get_by_api_key(raw_key)
        if account.id != account_id:
            raise AccountNotFoundError(account_id)
        return account

    async def rotate_api_key(self, account_id: int, raw_key: str | None = None) -> tuple[AccountORM, str]:
        account = await self.get_by_id(account_id)
        if raw_key is not None:
            await self.require_key_for_account(account_id, raw_key)

        new_key = generate_api_key("live")
        parts = parse_api_key(new_key)
        account.api_key_prefix = parts.prefix
        account.api_key_hash = hash_api_key(new_key, self._active_token_hash_key())
        account.api_key_hash_version = self._active_token_hash_version
        await self._session.flush()
        return account, new_key

    async def update_credentials(self, account_id: int, raw_key: str, password: str) -> AccountORM:
        account = await self.require_key_for_account(account_id, raw_key)
        encrypted = self._cipher.encrypt(password)
        account.encrypted_password = encrypted.ciphertext
        account.key_version = encrypted.key_version
        await self._session.flush()
        return account

    async def update_credentials_for_user(self, user_id: int, account_id: int, password: str) -> AccountORM:
        account = await self.get_for_user(user_id, account_id)
        encrypted = self._cipher.encrypt(password)
        account.encrypted_password = encrypted.ciphertext
        account.key_version = encrypted.key_version
        await self._session.flush()
        return account

    async def delete(self, account_id: int) -> None:
        account = await self.get_by_id(account_id)
        await self._session.delete(account)
        await self._session.flush()

    async def delete_for_user(self, user_id: int, account_id: int) -> None:
        account = await self.get_for_user(user_id, account_id)
        await self._session.delete(account)
        await self._session.flush()

    def _active_token_hash_key(self) -> bytes:
        return self._token_hash_keys[self._active_token_hash_version]


class AuditOutboxRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def enqueue(self, event: dict[str, Any] | AuditEvent) -> AuditOutboxORM:
        row = AuditOutboxORM(event=_audit_record(event))
        self._session.add(row)
        await self._session.flush()
        return row

    async def list_pending(self, limit: int = 100) -> list[AuditOutboxORM]:
        result = await self._session.scalars(
            select(AuditOutboxORM)
            .where(AuditOutboxORM.delivered_at.is_(None))
            .order_by(AuditOutboxORM.id)
            .limit(limit)
        )
        return list(result)

    async def mark_delivered(self, outbox_id: int) -> None:
        await self._session.execute(
            update(AuditOutboxORM)
            .where(AuditOutboxORM.id == outbox_id)
            .values(delivered_at=datetime.now(timezone.utc), last_error=None)
        )

    async def mark_failed(self, outbox_id: int, error: str) -> None:
        await self._session.execute(
            update(AuditOutboxORM)
            .where(AuditOutboxORM.id == outbox_id)
            .values(
                delivery_attempts=AuditOutboxORM.delivery_attempts + 1,
                last_error=sanitize_extra({"error": error})["error"],
            )
        )


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(self, event: dict[str, Any] | AuditEvent) -> AuditEventORM:
        event = _audit_record(event)
        row = AuditEventORM(
            timestamp=event.get("timestamp") or datetime.now(timezone.utc),
            actor_type=event["actor_type"],
            actor_id=event.get("actor_id"),
            client_ip=event["client_ip"],
            user_agent=event["user_agent"],
            action=event["action"],
            target_account_id=event.get("target_account_id"),
            status=event["status"],
            extra=sanitize_extra(event.get("extra") or {}),
            request_id=event["request_id"],
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def purge_before(self, cutoff: datetime) -> int:
        result = await self._session.execute(delete(AuditEventORM).where(AuditEventORM.timestamp < cutoff))
        return result.rowcount or 0


async def dispatch_audit_outbox(app_session_factory, audit_session_factory, *, limit: int = 100) -> int:
    delivered = 0
    async with app_session_factory() as app_session:
        pending = await AuditOutboxRepository(app_session).list_pending(limit)

    for item in pending:
        try:
            async with audit_session_factory() as audit_session:
                async with audit_session.begin():
                    await AuditRepository(audit_session).append(item.event)
            async with app_session_factory() as app_session:
                async with app_session.begin():
                    await AuditOutboxRepository(app_session).mark_delivered(item.id)
            delivered += 1
        except Exception as exc:
            async with app_session_factory() as app_session:
                async with app_session.begin():
                    await AuditOutboxRepository(app_session).mark_failed(item.id, str(exc))
    return delivered


def _audit_record(event: dict[str, Any] | AuditEvent) -> dict[str, Any]:
    if isinstance(event, AuditEvent):
        return event.to_record()
    return sanitize_extra(event)
