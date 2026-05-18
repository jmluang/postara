from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from postara.accounts import (
    AccountNotFoundError,
    DuplicateMailboxNameError,
    DuplicateEmailError,
    MailboxVerificationExpiredError,
    MailboxVerificationFailedError,
    MailboxVerificationNotFoundError,
    validate_mailbox_name,
)
from postara.audit import AuditEvent, sanitize_extra
from postara.crypto import CredentialCipher
from postara.models import AccountORM, AuditEventORM, AuditOutboxORM, PendingMailboxVerificationORM
from postara.security import (
    generate_api_key,
    hash_api_key,
    hash_verification_code,
    parse_api_key,
    verify_api_key_hash,
    verify_verification_code_hash,
)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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
        validate_mailbox_name(name)
        if provider != "gmail":
            raise ValueError("Only gmail is supported in v0.1.")
        await self._require_unique_account_fields(user_id=user_id, email=email, name=name)

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

    async def create_with_oauth(
        self,
        *,
        user_id: int,
        name: str,
        email: str,
        provider: str,
        refresh_token: str,
        access_token: str | None,
        expires_at: datetime | None,
        scopes: tuple[str, ...],
        subject: str | None,
        oauth_email: str,
    ) -> AccountORM:
        canonical_email = oauth_email or email
        validate_mailbox_name(name)
        await self._require_unique_account_fields(user_id=user_id, email=canonical_email, name=name)
        api_key = generate_api_key("live")
        parts = parse_api_key(api_key)
        encrypted_refresh = self._cipher.encrypt(refresh_token)
        encrypted_access = self._cipher.encrypt(access_token) if access_token is not None else None
        account = AccountORM(
            user_id=user_id,
            name=name,
            email=canonical_email,
            provider=provider,
            auth_type="oauth2",
            encrypted_password=None,
            key_version=encrypted_refresh.key_version,
            oauth_refresh_token=encrypted_refresh.ciphertext,
            oauth_access_token=encrypted_access.ciphertext if encrypted_access else None,
            oauth_token_expires_at=expires_at,
            oauth_scopes=list(scopes),
            oauth_subject=subject,
            oauth_email=canonical_email,
            imap_host="imap.gmail.com" if provider == "gmail" else "",
            imap_port=993 if provider == "gmail" else 0,
            api_key_prefix=parts.prefix,
            api_key_hash=hash_api_key(api_key, self._active_token_hash_key()),
            api_key_hash_version=self._active_token_hash_version,
        )
        self._session.add(account)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise DuplicateEmailError(canonical_email) from exc
        return account

    async def create_pending_app_password_verification(
        self,
        *,
        user_id: int,
        name: str,
        email: str,
        provider: str,
        password: str,
        code: str,
        expires_at: datetime,
    ) -> PendingMailboxVerificationORM:
        validate_mailbox_name(name)
        duplicate = await self._session.scalar(
            select(AccountORM.id).where(AccountORM.user_id == user_id, AccountORM.email == email).limit(1)
        )
        if duplicate is not None:
            raise DuplicateEmailError(email)
        duplicate_name = await self._session.scalar(
            select(AccountORM.id).where(AccountORM.user_id == user_id, AccountORM.name == name).limit(1)
        )
        if duplicate_name is not None:
            raise DuplicateMailboxNameError(name)

        encrypted = self._cipher.encrypt(password)
        code_hash_version, code_hash = hash_verification_code(
            code,
            self._active_token_hash_key(),
            version=self._active_token_hash_version,
        )
        verification = PendingMailboxVerificationORM(
            id="mbv_" + secrets.token_urlsafe(24),
            user_id=user_id,
            mailbox_id=None,
            provider=provider,
            auth_type="app_password",
            name=name,
            email=email,
            encrypted_password=encrypted.ciphertext,
            key_version=encrypted.key_version,
            code_hash=code_hash,
            code_hash_version=code_hash_version,
            attempts=0,
            status="verifying",
            expires_at=expires_at,
        )
        self._session.add(verification)
        await self._session.flush()
        return verification

    async def complete_pending_app_password_verification(
        self,
        *,
        user_id: int,
        verification_id: str,
        code: str,
    ) -> AccountORM:
        verification = await self._session.get(PendingMailboxVerificationORM, verification_id)
        if verification is None or verification.user_id != user_id or verification.status != "verifying":
            raise MailboxVerificationNotFoundError(verification_id)

        now = datetime.now(timezone.utc)
        if _as_utc(verification.expires_at) <= now:
            verification.status = "expired"
            await self._session.flush()
            raise MailboxVerificationExpiredError(verification_id)

        code_key = self._token_hash_keys.get(verification.code_hash_version)
        if code_key is None or not verify_verification_code_hash(code, verification.code_hash, code_key):
            verification.attempts += 1
            if verification.attempts >= 5:
                verification.status = "failed"
            await self._session.flush()
            raise MailboxVerificationFailedError(verification_id)

        password = self._cipher.decrypt(verification.encrypted_password, verification.key_version)
        account, _api_key = await self.create(
            user_id=user_id,
            name=verification.name,
            email=verification.email,
            provider=verification.provider,
            password=password,
        )
        verification.mailbox_id = account.id
        verification.status = "verified"
        verification.verified_at = now
        await self._session.flush()
        return account

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

    async def get_for_user_by_name(self, user_id: int, name: str) -> AccountORM:
        result = await self._session.scalars(
            select(AccountORM).where(AccountORM.user_id == user_id, AccountORM.name == name).limit(1)
        )
        account = result.first()
        if account is None:
            raise AccountNotFoundError(name)
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

    async def update_oauth_tokens(
        self,
        account_id: int,
        *,
        refresh_token: str,
        access_token: str,
        expires_at: datetime | None,
        scopes: tuple[str, ...],
    ) -> AccountORM:
        account = await self.get_by_id(account_id)
        encrypted_refresh = self._cipher.encrypt(refresh_token)
        encrypted_access = self._cipher.encrypt(access_token)
        account.oauth_refresh_token = encrypted_refresh.ciphertext
        account.oauth_access_token = encrypted_access.ciphertext
        account.key_version = encrypted_access.key_version
        account.oauth_token_expires_at = expires_at
        account.oauth_scopes = list(scopes)
        await self._session.flush()
        return account

    async def update_name_for_user(self, user_id: int, account_id: int, name: str) -> AccountORM:
        validate_mailbox_name(name)
        account = await self.get_for_user(user_id, account_id)
        duplicate_name = await self._session.scalar(
            select(AccountORM.id)
            .where(AccountORM.user_id == user_id, AccountORM.name == name, AccountORM.id != account_id)
            .limit(1)
        )
        if duplicate_name is not None:
            raise DuplicateMailboxNameError(name)
        account.name = name
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

    async def _require_unique_account_fields(self, *, user_id: int | None, email: str, name: str) -> None:
        duplicate_email = await self._session.scalar(
            select(AccountORM.id).where(AccountORM.user_id == user_id, AccountORM.email == email).limit(1)
        )
        if duplicate_email is not None:
            raise DuplicateEmailError(email)
        duplicate_name = await self._session.scalar(
            select(AccountORM.id).where(AccountORM.user_id == user_id, AccountORM.name == name).limit(1)
        )
        if duplicate_name is not None:
            raise DuplicateMailboxNameError(name)

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
            timestamp=_parse_datetime(event.get("timestamp")) or datetime.now(timezone.utc),
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


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    raise TypeError(f"Unsupported datetime value: {value!r}")
