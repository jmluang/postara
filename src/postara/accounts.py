from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from postara.audit import AuditEvent
from postara.credentials import AppPasswordCredential, OAuth2Credential
from postara.crypto import CredentialCipher
from postara.oauth import OAuthExchangeError
from postara.security import (
    generate_api_key,
    hash_api_key,
    hash_verification_code,
    parse_api_key,
    verify_api_key_hash,
    verify_verification_code_hash,
)


class AccountNotFoundError(LookupError):
    pass


class DuplicateEmailError(ValueError):
    pass


class DuplicateMailboxNameError(ValueError):
    pass


MAILBOX_NAME_PATTERN = re.compile(r"^[A-Za-z0-9-]+$")


def validate_mailbox_name(name: str) -> None:
    if not MAILBOX_NAME_PATTERN.fullmatch(name):
        raise ValueError("Mailbox API name must contain only letters, numbers, and hyphens.")


class MailboxVerificationNotFoundError(LookupError):
    pass


class MailboxVerificationExpiredError(ValueError):
    pass


class MailboxVerificationFailedError(ValueError):
    pass


class MailboxReconnectRequiredError(RuntimeError):
    pass


@dataclass
class AccountRecord:
    id: int
    user_id: int | None
    name: str
    email: str
    provider: str
    auth_type: str
    encrypted_password: bytes | None
    key_version: int | None
    imap_host: str
    imap_port: int
    api_key_prefix: str
    api_key_hash: bytes
    api_key_hash_version: int
    created_at: datetime
    last_used_at: datetime | None = None
    oauth_refresh_token: bytes | None = None
    oauth_access_token: bytes | None = None
    oauth_token_expires_at: datetime | None = None
    oauth_scopes: list[str] | None = None
    oauth_subject: str | None = None
    oauth_email: str | None = None

    def to_dto(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "email": self.email,
            "provider": self.provider,
            "auth_type": self.auth_type,
            "imap_host": self.imap_host,
            "imap_port": self.imap_port,
            "api_key_prefix": self.api_key_prefix,
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }


@dataclass
class PendingMailboxVerificationRecord:
    id: str
    user_id: int
    mailbox_id: int | None
    provider: str
    auth_type: str
    name: str
    email: str
    encrypted_password: bytes
    key_version: int
    code_hash: bytes
    code_hash_version: int
    attempts: int
    status: str
    expires_at: datetime
    created_at: datetime
    verified_at: datetime | None = None

    def to_dto(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "mailbox_id": self.mailbox_id,
            "provider": self.provider,
            "auth_type": self.auth_type,
            "name": self.name,
            "email": self.email,
            "attempts": self.attempts,
            "status": self.status,
            "expires_at": self.expires_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }


class AccountService:
    def __init__(self, cipher: CredentialCipher | None = None, token_hash_key: bytes | None = None) -> None:
        self._cipher = cipher or CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)
        # In-memory service is for tests/local demos; repository services must load real runtime secrets.
        self._token_hash_key = token_hash_key or base64.urlsafe_b64encode(b"test-token-hash-key-material-32!!")
        self._next_id = 1
        self._accounts: dict[int, AccountRecord] = {}
        self._pending_verifications: dict[str, PendingMailboxVerificationRecord] = {}

    def create(
        self,
        *,
        name: str,
        email: str,
        provider: str,
        password: str,
        user_id: int | None = None,
    ) -> tuple[AccountRecord, str]:
        validate_mailbox_name(name)
        if any(account.email == email and account.user_id == user_id for account in self._accounts.values()):
            raise DuplicateEmailError(email)
        if any(account.name == name and account.user_id == user_id for account in self._accounts.values()):
            raise DuplicateMailboxNameError(name)
        if provider != "gmail":
            raise ValueError("Only gmail is supported in v0.1.")

        api_key = generate_api_key("live")
        parts = parse_api_key(api_key)
        encrypted = self._cipher.encrypt(password)
        account = AccountRecord(
            id=self._next_id,
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
            api_key_hash=hash_api_key(api_key, self._token_hash_key),
            api_key_hash_version=1,
            created_at=datetime.now(timezone.utc),
        )
        self._next_id += 1
        self._accounts[account.id] = account
        return account, api_key

    def create_with_app_password(
        self,
        *,
        user_id: int,
        name: str,
        email: str,
        provider: str,
        password: str,
    ) -> AccountRecord:
        account, _api_key = self.create(name=name, email=email, provider=provider, password=password, user_id=user_id)
        return account

    def create_for_user(
        self,
        *,
        user_id: int,
        name: str,
        email: str,
        provider: str,
        password: str,
    ) -> AccountRecord:
        return self.create_with_app_password(
            user_id=user_id,
            name=name,
            email=email,
            provider=provider,
            password=password,
        )

    def start_app_password_verification(
        self,
        *,
        user_id: int,
        name: str,
        email: str,
        provider: str,
        password: str,
        code: str,
        expires_at: datetime | None = None,
    ) -> PendingMailboxVerificationRecord:
        validate_mailbox_name(name)
        if any(account.email == email and account.user_id == user_id for account in self._accounts.values()):
            raise DuplicateEmailError(email)
        if any(account.name == name and account.user_id == user_id for account in self._accounts.values()):
            raise DuplicateMailboxNameError(name)
        encrypted = self._cipher.encrypt(password)
        code_hash_version, code_hash = hash_verification_code(code, self._token_hash_key, version=1)
        now = datetime.now(timezone.utc)
        verification = PendingMailboxVerificationRecord(
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
            expires_at=expires_at or now + timedelta(minutes=15),
            created_at=now,
        )
        self._pending_verifications[verification.id] = verification
        return verification

    def complete_app_password_verification(
        self,
        *,
        user_id: int,
        verification_id: str,
        code: str,
    ) -> AccountRecord:
        verification = self._pending_verifications.get(verification_id)
        if verification is None or verification.user_id != user_id or verification.status != "verifying":
            raise MailboxVerificationNotFoundError(verification_id)

        now = datetime.now(timezone.utc)
        if verification.expires_at <= now:
            verification.status = "expired"
            raise MailboxVerificationExpiredError(verification_id)

        if not verify_verification_code_hash(code, verification.code_hash, self._token_hash_key):
            verification.attempts += 1
            if verification.attempts >= 5:
                verification.status = "failed"
            raise MailboxVerificationFailedError(verification_id)

        password = self._cipher.decrypt(verification.encrypted_password, verification.key_version)
        account = self.create_with_app_password(
            user_id=user_id,
            name=verification.name,
            email=verification.email,
            provider=verification.provider,
            password=password,
        )
        verification.mailbox_id = account.id
        verification.status = "verified"
        verification.verified_at = now
        return account

    def create_with_oauth(
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
    ) -> AccountRecord:
        canonical_email = oauth_email or email
        validate_mailbox_name(name)
        if any(account.email == canonical_email and account.user_id == user_id for account in self._accounts.values()):
            existing_email = next(
                account for account in self._accounts.values() if account.email == canonical_email and account.user_id == user_id
            )
            if existing_email.name != name:
                raise DuplicateEmailError(canonical_email)
        existing = next((account for account in self._accounts.values() if account.name == name and account.user_id == user_id), None)
        if existing is not None:
            if existing.auth_type != "oauth2" or existing.provider != provider:
                raise DuplicateMailboxNameError(name)
            encrypted_refresh = self._cipher.encrypt(refresh_token)
            encrypted_access = self._cipher.encrypt(access_token) if access_token is not None else None
            existing.email = canonical_email
            existing.encrypted_password = None
            existing.key_version = encrypted_refresh.key_version
            existing.oauth_refresh_token = encrypted_refresh.ciphertext
            existing.oauth_access_token = encrypted_access.ciphertext if encrypted_access else None
            existing.oauth_token_expires_at = expires_at
            existing.oauth_scopes = list(scopes)
            existing.oauth_subject = subject
            existing.oauth_email = canonical_email
            return existing
        if provider != "gmail":
            raise ValueError("Only gmail OAuth is supported in this implementation phase.")

        api_key = generate_api_key("live")
        parts = parse_api_key(api_key)
        encrypted_refresh = self._cipher.encrypt(refresh_token)
        encrypted_access = self._cipher.encrypt(access_token) if access_token is not None else None
        account = AccountRecord(
            id=self._next_id,
            user_id=user_id,
            name=name,
            email=canonical_email,
            provider=provider,
            auth_type="oauth2",
            encrypted_password=None,
            key_version=encrypted_refresh.key_version,
            imap_host="imap.gmail.com",
            imap_port=993,
            api_key_prefix=parts.prefix,
            api_key_hash=hash_api_key(api_key, self._token_hash_key),
            api_key_hash_version=1,
            created_at=datetime.now(timezone.utc),
            oauth_refresh_token=encrypted_refresh.ciphertext,
            oauth_access_token=encrypted_access.ciphertext if encrypted_access else None,
            oauth_token_expires_at=expires_at,
            oauth_scopes=list(scopes),
            oauth_subject=subject,
            oauth_email=canonical_email,
        )
        self._next_id += 1
        self._accounts[account.id] = account
        return account

    def list(self) -> list[AccountRecord]:
        return list(self._accounts.values())

    def list_for_user(self, user_id: int) -> list[AccountRecord]:
        return [account for account in self._accounts.values() if account.user_id == user_id]

    def get(self, account_id: int) -> AccountRecord:
        account = self._accounts.get(account_id)
        if account is None:
            raise AccountNotFoundError(account_id)
        return account

    def get_for_user(self, user_id: int, account_id: int) -> AccountRecord:
        account = self.get(account_id)
        if account.user_id != user_id:
            raise AccountNotFoundError(account_id)
        return account

    def get_for_user_by_name(self, user_id: int, name: str) -> AccountRecord:
        for account in self._accounts.values():
            if account.user_id == user_id and account.name == name:
                return account
        raise AccountNotFoundError(name)

    def authenticate_key(self, raw_key: str) -> AccountRecord:
        parts = parse_api_key(raw_key)
        for account in self._accounts.values():
            if account.api_key_prefix != parts.prefix:
                continue
            if verify_api_key_hash(raw_key, account.api_key_hash, self._token_hash_key):
                account.last_used_at = datetime.now(timezone.utc)
                return account
        raise AccountNotFoundError("api key")

    def require_key_for_account(self, account_id: int, raw_key: str) -> AccountRecord:
        account = self.authenticate_key(raw_key)
        if account.id != account_id:
            raise AccountNotFoundError(account_id)
        return account

    def rotate_key(self, account_id: int, raw_key: str | None = None) -> tuple[AccountRecord, str]:
        account = self.get(account_id)
        if raw_key is not None:
            self.require_key_for_account(account_id, raw_key)

        new_key = generate_api_key("live")
        parts = parse_api_key(new_key)
        account.api_key_prefix = parts.prefix
        account.api_key_hash = hash_api_key(new_key, self._token_hash_key)
        account.api_key_hash_version = 1
        return account, new_key

    def update_credentials(self, account_id: int, raw_key: str, password: str) -> AccountRecord:
        account = self.require_key_for_account(account_id, raw_key)
        encrypted = self._cipher.encrypt(password)
        account.encrypted_password = encrypted.ciphertext
        account.key_version = encrypted.key_version
        return account

    def update_credentials_for_user(self, user_id: int, account_id: int, password: str) -> AccountRecord:
        account = self.get_for_user(user_id, account_id)
        encrypted = self._cipher.encrypt(password)
        account.encrypted_password = encrypted.ciphertext
        account.key_version = encrypted.key_version
        return account

    def update_name_for_user(self, user_id: int, account_id: int, name: str) -> AccountRecord:
        validate_mailbox_name(name)
        account = self.get_for_user(user_id, account_id)
        if any(item.id != account_id and item.user_id == user_id and item.name == name for item in self._accounts.values()):
            raise DuplicateMailboxNameError(name)
        account.name = name
        return account

    def get_password_for_imap(self, account_id: int) -> str:
        account = self.get(account_id)
        if account.encrypted_password is None or account.key_version is None:
            raise AccountNotFoundError(account_id)
        return self._cipher.decrypt(account.encrypted_password, account.key_version)

    def get_credential_for_runtime(self, account_id: int) -> AppPasswordCredential | OAuth2Credential:
        account = self.get(account_id)
        if account.auth_type == "app_password":
            if account.encrypted_password is None or account.key_version is None:
                raise AccountNotFoundError(account_id)
            return AppPasswordCredential(password=self._cipher.decrypt(account.encrypted_password, account.key_version))
        if account.auth_type == "oauth2":
            if account.oauth_access_token is None or account.key_version is None:
                raise MailboxReconnectRequiredError(account_id)
            return OAuth2Credential(
                access_token=self._cipher.decrypt(account.oauth_access_token, account.key_version),
                scopes=tuple(account.oauth_scopes or ()),
                expires_at=account.oauth_token_expires_at,
            )
        raise AccountNotFoundError(account_id)

    def delete(self, account_id: int) -> None:
        if account_id not in self._accounts:
            raise AccountNotFoundError(account_id)
        del self._accounts[account_id]

    def delete_for_user(self, user_id: int, account_id: int) -> None:
        self.get_for_user(user_id, account_id)
        self.delete(account_id)

    def record_message_seen(self, *args, **kwargs) -> None:
        return None


class RepositoryAccountService:
    def __init__(
        self,
        session_factory,
        *,
        audit_session_factory,
        cipher: CredentialCipher,
        token_hash_keys: dict[int, bytes],
        active_token_hash_version: int,
        oauth_refreshers: dict[str, object] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit_session_factory = audit_session_factory
        self._cipher = cipher
        self._token_hash_keys = token_hash_keys
        self._active_token_hash_version = active_token_hash_version
        self._oauth_refreshers = oauth_refreshers or {}

    def _repo(self, session):
        from postara.repositories import AccountRepository

        return AccountRepository(
            session,
            cipher=self._cipher,
            token_hash_keys=self._token_hash_keys,
            active_token_hash_version=self._active_token_hash_version,
        )

    async def create(self, *, name: str, email: str, provider: str, password: str, audit_context: dict | None = None):
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                account, api_key = await repo.create(
                    name=name,
                    email=email,
                    provider=provider,
                    password=password,
                )
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="account.create",
                        status="success",
                        target_account_id=account.id,
                        extra={"email": account.email},
                    )
                )
        return account, api_key

    async def create_for_user(
        self,
        *,
        user_id: int,
        name: str,
        email: str,
        provider: str,
        password: str,
        audit_context: dict | None = None,
    ):
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                account, _api_key = await repo.create(
                    user_id=user_id,
                    name=name,
                    email=email,
                    provider=provider,
                    password=password,
                )
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="account.create",
                        status="success",
                        target_account_id=account.id,
                        extra={"email": account.email},
                    )
                )
        return account

    async def create_with_app_password(
        self,
        *,
        user_id: int,
        name: str,
        email: str,
        provider: str,
        password: str,
        audit_context: dict | None = None,
    ):
        return await self.create_for_user(
            user_id=user_id,
            name=name,
            email=email,
            provider=provider,
            password=password,
            audit_context=audit_context,
        )

    async def start_app_password_verification(
        self,
        *,
        user_id: int,
        name: str,
        email: str,
        provider: str,
        password: str,
        code: str,
        expires_at: datetime,
        audit_context: dict | None = None,
    ):
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                verification = await repo.create_pending_app_password_verification(
                    user_id=user_id,
                    name=name,
                    email=email,
                    provider=provider,
                    password=password,
                    code=code,
                    expires_at=expires_at,
                )
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="mailbox.app_password_verify_sent",
                        status="success",
                        extra={"email": email, "provider": provider, "auth_type": "app_password"},
                    )
                )
        return verification

    async def complete_app_password_verification(
        self,
        *,
        user_id: int,
        verification_id: str,
        code: str,
        audit_context: dict | None = None,
    ):
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                account = await repo.complete_pending_app_password_verification(
                    user_id=user_id,
                    verification_id=verification_id,
                    code=code,
                )
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="mailbox.app_password_verify_completed",
                        status="success",
                        target_account_id=account.id,
                        extra={"email": account.email, "provider": account.provider, "auth_type": "app_password"},
                    )
                )
        return account

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
        audit_context: dict | None = None,
    ):
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                account = await repo.create_with_oauth(
                    user_id=user_id,
                    name=name,
                    email=email,
                    provider=provider,
                    refresh_token=refresh_token,
                    access_token=access_token,
                    expires_at=expires_at,
                    scopes=scopes,
                    subject=subject,
                    oauth_email=oauth_email,
                )
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="mailbox.oauth_completed",
                        status="success",
                        target_account_id=account.id,
                        extra={"email": account.email, "provider": provider, "auth_type": "oauth2"},
                    )
                )
        return account

    async def list(self):
        async with self._session_factory() as session:
            return await self._repo(session).list()

    async def list_for_user(self, user_id: int):
        async with self._session_factory() as session:
            return await self._repo(session).list_for_user(user_id)

    async def get_for_user(self, user_id: int, account_id: int):
        async with self._session_factory() as session:
            return await self._repo(session).get_for_user(user_id, account_id)

    async def get_for_user_by_name(self, user_id: int, name: str):
        async with self._session_factory() as session:
            return await self._repo(session).get_for_user_by_name(user_id, name)

    async def update_name_for_user(
        self,
        user_id: int,
        account_id: int,
        name: str,
        audit_context: dict | None = None,
    ):
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                account = await repo.update_name_for_user(user_id, account_id, name)
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="mailbox.name_updated",
                        status="success",
                        target_account_id=account.id,
                        extra={"name": account.name},
                    )
                )
        return account

    async def require_key_for_account(self, account_id: int, raw_key: str):
        async with self._session_factory() as session:
            async with session.begin():
                return await self._repo(session).require_key_for_account(account_id, raw_key)

    async def rotate_key(self, account_id: int, raw_key: str | None = None, audit_context: dict | None = None):
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                account, api_key = await repo.rotate_api_key(account_id, raw_key)
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="apikey.rotate" if raw_key else "apikey.rotate.forced",
                        status="success",
                        target_account_id=account.id,
                    )
                )
        return account, api_key

    async def update_credentials(
        self,
        account_id: int,
        raw_key: str,
        password: str,
        audit_context: dict | None = None,
    ):
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                account = await repo.update_credentials(account_id, raw_key, password)
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="credentials.update",
                        status="success",
                        target_account_id=account.id,
                    )
                )
        return account

    async def update_credentials_for_user(
        self,
        user_id: int,
        account_id: int,
        password: str,
        audit_context: dict | None = None,
    ):
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                account = await repo.update_credentials_for_user(user_id, account_id, password)
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="credentials.update",
                        status="success",
                        target_account_id=account.id,
                    )
                )
        return account

    async def get_password_for_imap(self, account_id: int) -> str:
        async with self._session_factory() as session:
            account = await self._repo(session).get_by_id(account_id)
            return self._cipher.decrypt(account.encrypted_password, account.key_version)

    async def get_credential_for_runtime(
        self,
        account_id: int,
        *,
        now: datetime | None = None,
    ) -> AppPasswordCredential | OAuth2Credential:
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                account = await repo.get_by_id(account_id)
                if account.auth_type == "app_password":
                    if account.encrypted_password is None or account.key_version is None:
                        raise AccountNotFoundError(account_id)
                    return AppPasswordCredential(
                        password=self._cipher.decrypt(account.encrypted_password, account.key_version)
                    )
                if account.auth_type == "oauth2":
                    if account.oauth_access_token is None or account.key_version is None:
                        raise MailboxReconnectRequiredError(account_id)
                    scopes = tuple(account.oauth_scopes or ())
                    if self._oauth_token_needs_refresh(account.oauth_token_expires_at, now=now):
                        account, scopes = await self._refresh_oauth_access_token(repo, account, scopes)
                        await outbox.enqueue(
                            self._audit_event(
                                None,
                                action="mailbox.oauth_token_refreshed",
                                status="success",
                                target_account_id=account.id,
                                extra={"provider": account.provider, "auth_type": "oauth2"},
                            )
                        )
                    return OAuth2Credential(
                        access_token=self._cipher.decrypt(account.oauth_access_token, account.key_version),
                        scopes=scopes,
                        expires_at=account.oauth_token_expires_at,
                    )
                raise AccountNotFoundError(account_id)

    def _oauth_token_needs_refresh(self, expires_at: datetime | None, *, now: datetime | None = None) -> bool:
        if expires_at is None:
            return False
        current_time = now or datetime.now(timezone.utc)
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at <= current_time + timedelta(minutes=5)

    async def _refresh_oauth_access_token(self, repo, account, scopes: tuple[str, ...]):
        refresher = self._oauth_refreshers.get(account.provider)
        if refresher is None or account.oauth_refresh_token is None or account.key_version is None:
            raise MailboxReconnectRequiredError(account.id)
        refresh_token = self._cipher.decrypt(account.oauth_refresh_token, account.key_version)
        try:
            result = await refresher.refresh_access_token(refresh_token=refresh_token, scopes=scopes)
        except OAuthExchangeError as exc:
            raise MailboxReconnectRequiredError(account.id) from exc
        account = await repo.update_oauth_tokens(
            account.id,
            refresh_token=refresh_token,
            access_token=result.access_token,
            expires_at=result.expires_at,
            scopes=result.scopes,
        )
        return account, result.scopes

    async def delete(self, account_id: int, audit_context: dict | None = None) -> None:
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                await repo.delete(account_id)
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="account.delete",
                        status="success",
                        target_account_id=account_id,
                    )
                )

    async def delete_for_user(self, user_id: int, account_id: int, audit_context: dict | None = None) -> None:
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                repo = self._repo(session)
                outbox = AuditOutboxRepository(session)
                await repo.delete_for_user(user_id, account_id)
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="account.delete",
                        status="success",
                        target_account_id=account_id,
                    )
                )

    async def record_message_seen(
        self,
        account_id: int,
        uid: str,
        seen: bool,
        audit_context: dict | None = None,
    ) -> None:
        from postara.repositories import AuditOutboxRepository

        async with self._session_factory() as session:
            async with session.begin():
                outbox = AuditOutboxRepository(session)
                await outbox.enqueue(
                    self._audit_event(
                        audit_context,
                        action="message.mark_seen",
                        status="success",
                        target_account_id=account_id,
                        extra={"uid": uid, "seen": seen},
                    )
                )

    def _audit_event(
        self,
        context: dict | None,
        *,
        action: str,
        status: str,
        target_account_id: int | None = None,
        extra: dict | None = None,
    ) -> AuditEvent:
        context = context or {}
        return AuditEvent(
            action=action,
            actor_type=context.get("actor_type", "anonymous"),
            actor_id=context.get("actor_id"),
            client_ip=context.get("client_ip", "0.0.0.0"),
            user_agent=context.get("user_agent", "unknown"),
            request_id=context.get("request_id", "system"),
            target_account_id=target_account_id,
            status=status,
            extra=extra or {},
        )
