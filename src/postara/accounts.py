from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone

from postara.audit import AuditEvent
from postara.crypto import CredentialCipher
from postara.security import generate_api_key, hash_api_key, parse_api_key, verify_api_key_hash


class AccountNotFoundError(LookupError):
    pass


class DuplicateEmailError(ValueError):
    pass


@dataclass
class AccountRecord:
    id: int
    user_id: int | None
    name: str
    email: str
    provider: str
    auth_type: str
    encrypted_password: bytes
    key_version: int
    imap_host: str
    imap_port: int
    api_key_prefix: str
    api_key_hash: bytes
    api_key_hash_version: int
    created_at: datetime
    last_used_at: datetime | None = None

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


class AccountService:
    def __init__(self, cipher: CredentialCipher | None = None, token_hash_key: bytes | None = None) -> None:
        self._cipher = cipher or CredentialCipher({1: CredentialCipher.generate_key()}, active_version=1)
        # In-memory service is for tests/local demos; repository services must load real runtime secrets.
        self._token_hash_key = token_hash_key or base64.urlsafe_b64encode(b"test-token-hash-key-material-32!!")
        self._next_id = 1
        self._accounts: dict[int, AccountRecord] = {}

    def create(
        self,
        *,
        name: str,
        email: str,
        provider: str,
        password: str,
        user_id: int | None = None,
    ) -> tuple[AccountRecord, str]:
        if any(account.email == email and account.user_id == user_id for account in self._accounts.values()):
            raise DuplicateEmailError(email)
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

    def create_for_user(
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

    def get_password_for_imap(self, account_id: int) -> str:
        account = self.get(account_id)
        return self._cipher.decrypt(account.encrypted_password, account.key_version)

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
    ) -> None:
        self._session_factory = session_factory
        self._audit_session_factory = audit_session_factory
        self._cipher = cipher
        self._token_hash_keys = token_hash_keys
        self._active_token_hash_version = active_token_hash_version

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

    async def list(self):
        async with self._session_factory() as session:
            return await self._repo(session).list()

    async def list_for_user(self, user_id: int):
        async with self._session_factory() as session:
            return await self._repo(session).list_for_user(user_id)

    async def get_for_user(self, user_id: int, account_id: int):
        async with self._session_factory() as session:
            return await self._repo(session).get_for_user(user_id, account_id)

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
