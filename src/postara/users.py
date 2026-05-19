from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from postara.models import ApiKeyORM, UserORM, UserSessionORM
from postara.security import (
    generate_api_key,
    generate_session_token,
    hash_api_key,
    hash_password,
    hash_session_token,
    parse_api_key,
    parse_session_token,
    verify_api_key_hash,
    verify_password,
    verify_session_token_hash,
)

_DUMMY_PASSWORD_HASH = hash_password("postara-dummy-password")


class DuplicateUserEmailError(ValueError):
    pass


class InvalidUserCredentialsError(ValueError):
    pass


class SessionNotFoundError(LookupError):
    pass


class ApiKeyNotFoundError(LookupError):
    pass


@dataclass
class SessionRecord:
    user_id: int
    digest: bytes
    expires_at: datetime
    revoked_at: datetime | None = None


@dataclass
class UserRecord:
    id: int
    email: str
    name: str
    password_hash: str
    role: str
    created_at: datetime
    last_login_at: datetime | None = None
    disabled_at: datetime | None = None

    def to_dto(self) -> dict:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "disabled_at": self.disabled_at.isoformat() if self.disabled_at else None,
        }


@dataclass
class ApiKeyRecord:
    id: int
    user_id: int
    mailbox_id: int | None
    scopes: list[str]
    name: str
    prefix: str
    key_hash: bytes
    hash_version: int
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    def to_dto(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "mailbox_id": self.mailbox_id,
            "scopes": self.scopes,
            "name": self.name,
            "prefix": self.prefix,
            "status": "disabled" if self.revoked_at else "active",
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "disabled_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }


class UserService:
    def __init__(self, token_hash_key: bytes | None = None) -> None:
        # In-memory service is for tests/local demos; repository services must load real runtime secrets.
        self._token_hash_key = token_hash_key or base64.urlsafe_b64encode(b"user-api-key-material-32-bytes!!")
        self._next_user_id = 1
        self._next_api_key_id = 1
        self._users: dict[int, UserRecord] = {}
        self._sessions: dict[str, SessionRecord] = {}
        self._api_keys: dict[int, ApiKeyRecord] = {}

    def register(self, *, email: str, password: str, name: str) -> tuple[UserRecord, str]:
        normalized_email = _normalize_user_email(email)
        if any(user.email == normalized_email for user in self._users.values()):
            raise DuplicateUserEmailError(normalized_email)
        now = datetime.now(timezone.utc)
        user = UserRecord(
            id=self._next_user_id,
            email=normalized_email,
            name=name,
            password_hash=hash_password(password),
            role="owner" if not self._users else "member",
            created_at=now,
        )
        self._next_user_id += 1
        self._users[user.id] = user
        return user, self.create_session(user.id)

    def login(self, *, email: str, password: str) -> tuple[UserRecord, str]:
        normalized_email = _normalize_user_email(email)
        user = next((item for item in self._users.values() if item.email == normalized_email), None)
        if user is None:
            verify_password(password, _DUMMY_PASSWORD_HASH)
            raise InvalidUserCredentialsError(normalized_email)
        if user.disabled_at is not None or not verify_password(password, user.password_hash):
            raise InvalidUserCredentialsError(normalized_email)
        user.last_login_at = datetime.now(timezone.utc)
        return user, self.create_session(user.id)

    def create_session(self, user_id: int) -> str:
        token = generate_session_token()
        prefix, digest = hash_session_token(token)
        self._sessions[prefix] = SessionRecord(
            user_id=user_id,
            digest=digest,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        return token

    def authenticate_session(self, raw_token: str) -> UserRecord:
        prefix, _secret = parse_session_token(raw_token)
        session = self._sessions.get(prefix)
        now = datetime.now(timezone.utc)
        if session is None:
            raise SessionNotFoundError(prefix)
        if (
            session.revoked_at is not None
            or session.expires_at <= now
            or not verify_session_token_hash(raw_token, session.digest)
        ):
            raise SessionNotFoundError(prefix)
        user = self._users.get(session.user_id)
        if user is None or user.disabled_at is not None:
            raise SessionNotFoundError(prefix)
        return user

    def revoke_session(self, raw_token: str) -> None:
        prefix, _secret = parse_session_token(raw_token)
        session = self._sessions.get(prefix)
        if session is not None:
            session.revoked_at = datetime.now(timezone.utc)

    def change_password(
        self,
        user_id: int,
        *,
        current_password: str,
        new_password: str,
        current_session_token: str | None = None,
    ) -> None:
        user = self._users.get(user_id)
        if user is None or not verify_password(current_password, user.password_hash):
            raise InvalidUserCredentialsError(user_id)
        user.password_hash = hash_password(new_password)
        self._revoke_other_sessions(user_id, current_session_token=current_session_token)

    def update_profile(self, user_id: int, *, name: str) -> UserRecord:
        user = self._users.get(user_id)
        if user is None:
            raise SessionNotFoundError(user_id)
        user.name = name
        return user

    def list_users(self) -> list[UserRecord]:
        return sorted(self._users.values(), key=lambda user: user.id)

    def update_user_status(self, user_id: int, status: str) -> UserRecord:
        user = self._users.get(user_id)
        if user is None:
            raise SessionNotFoundError(user_id)
        if status == "disabled":
            user.disabled_at = datetime.now(timezone.utc)
        elif status == "active":
            user.disabled_at = None
        else:
            raise ValueError(status)
        return user

    def reset_password(self, user_id: int, *, new_password: str) -> None:
        user = self._users.get(user_id)
        if user is None:
            raise SessionNotFoundError(user_id)
        user.password_hash = hash_password(new_password)
        self._revoke_other_sessions(user_id, current_session_token=None)

    def _revoke_other_sessions(self, user_id: int, *, current_session_token: str | None) -> None:
        current_prefix = None
        if current_session_token:
            try:
                current_prefix, _secret = parse_session_token(current_session_token)
            except Exception:
                current_prefix = None
        now = datetime.now(timezone.utc)
        for prefix, session in self._sessions.items():
            if session.user_id == user_id and prefix != current_prefix and session.revoked_at is None:
                session.revoked_at = now

    def create_api_key(
        self,
        user_id: int,
        *,
        name: str,
        mailbox_id: int | None = None,
        scopes: list[str] | None = None,
    ) -> tuple[ApiKeyRecord, str]:
        raw_key = generate_api_key("live")
        parts = parse_api_key(raw_key)
        record = ApiKeyRecord(
            id=self._next_api_key_id,
            user_id=user_id,
            mailbox_id=mailbox_id,
            scopes=scopes or ["read"],
            name=name,
            prefix=parts.prefix,
            key_hash=hash_api_key(raw_key, self._token_hash_key),
            hash_version=1,
            created_at=datetime.now(timezone.utc),
        )
        self._next_api_key_id += 1
        self._api_keys[record.id] = record
        return record, raw_key

    def list_api_keys(self, user_id: int) -> list[ApiKeyRecord]:
        return [key for key in self._api_keys.values() if key.user_id == user_id]

    def authenticate_api_key(self, raw_key: str) -> ApiKeyRecord:
        parts = parse_api_key(raw_key)
        for key in self._api_keys.values():
            if key.prefix != parts.prefix or key.revoked_at is not None:
                continue
            if verify_api_key_hash(raw_key, key.key_hash, self._token_hash_key):
                key.last_used_at = datetime.now(timezone.utc)
                return key
        raise ApiKeyNotFoundError("api key")

    def revoke_api_key(self, user_id: int, api_key_id: int) -> None:
        self.delete_api_key(user_id, api_key_id)

    def delete_api_key(self, user_id: int, api_key_id: int) -> None:
        key = self._api_keys.get(api_key_id)
        if key is None or key.user_id != user_id:
            raise ApiKeyNotFoundError(api_key_id)
        del self._api_keys[api_key_id]

    def update_api_key_status(self, user_id: int, api_key_id: int, status: str) -> ApiKeyRecord:
        key = self._api_keys.get(api_key_id)
        if key is None or key.user_id != user_id:
            raise ApiKeyNotFoundError(api_key_id)
        if status == "disabled":
            key.revoked_at = datetime.now(timezone.utc)
        elif status == "active":
            key.revoked_at = None
        else:
            raise ValueError(status)
        return key


class RepositoryUserService:
    def __init__(
        self,
        session_factory,
        *,
        token_hash_keys: dict[int, bytes],
        active_token_hash_version: int,
    ) -> None:
        self._session_factory = session_factory
        self._token_hash_keys = token_hash_keys
        self._active_token_hash_version = active_token_hash_version

    async def register(self, *, email: str, password: str, name: str):
        normalized_email = _normalize_user_email(email)
        async with self._session_factory() as session:
            async with session.begin():
                count = await session.scalar(select(func.count(UserORM.id)))
                user = UserORM(
                    email=normalized_email,
                    name=name,
                    password_hash=hash_password(password),
                    role="owner" if count == 0 else "member",
                )
                session.add(user)
                try:
                    await session.flush()
                except IntegrityError as exc:
                    raise DuplicateUserEmailError(normalized_email) from exc
                token = await self._create_session(session, user.id)
                return user, token

    async def login(self, *, email: str, password: str):
        normalized_email = _normalize_user_email(email)
        async with self._session_factory() as session:
            async with session.begin():
                user = (await session.scalars(select(UserORM).where(UserORM.email == normalized_email).limit(1))).first()
                if user is None:
                    verify_password(password, _DUMMY_PASSWORD_HASH)
                    raise InvalidUserCredentialsError(normalized_email)
                if user.disabled_at is not None or not verify_password(password, user.password_hash):
                    raise InvalidUserCredentialsError(normalized_email)
                user.last_login_at = datetime.now(timezone.utc)
                token = await self._create_session(session, user.id)
                return user, token

    async def _create_session(self, session, user_id: int) -> str:
        token = generate_session_token()
        prefix, digest = hash_session_token(token)
        session.add(
            UserSessionORM(
                user_id=user_id,
                token_prefix=prefix,
                token_hash=digest,
                expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            )
        )
        await session.flush()
        return token

    async def authenticate_session(self, raw_token: str):
        prefix, _secret = parse_session_token(raw_token)
        async with self._session_factory() as session:
            async with session.begin():
                row = (
                    await session.scalars(
                        select(UserSessionORM).where(UserSessionORM.token_prefix == prefix).limit(1)
                    )
                ).first()
                now = datetime.now(timezone.utc)
                if (
                    row is None
                    or row.revoked_at is not None
                    or row.expires_at <= now
                    or not verify_session_token_hash(raw_token, row.token_hash)
                ):
                    raise SessionNotFoundError(prefix)
                user = await session.get(UserORM, row.user_id)
                if user is None or user.disabled_at is not None:
                    raise SessionNotFoundError(prefix)
                row.last_used_at = now
                return user

    async def revoke_session(self, raw_token: str) -> None:
        prefix, _secret = parse_session_token(raw_token)
        async with self._session_factory() as session:
            async with session.begin():
                row = (
                    await session.scalars(
                        select(UserSessionORM).where(UserSessionORM.token_prefix == prefix).limit(1)
                    )
                ).first()
                if row is not None:
                    row.revoked_at = datetime.now(timezone.utc)

    async def change_password(
        self,
        user_id: int,
        *,
        current_password: str,
        new_password: str,
        current_session_token: str | None = None,
    ) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                user = await session.get(UserORM, user_id)
                if user is None or not verify_password(current_password, user.password_hash):
                    raise InvalidUserCredentialsError(user_id)
                user.password_hash = hash_password(new_password)
                await self._revoke_other_sessions(
                    session,
                    user_id,
                    current_session_token=current_session_token,
                )

    async def update_profile(self, user_id: int, *, name: str):
        async with self._session_factory() as session:
            async with session.begin():
                user = await session.get(UserORM, user_id)
                if user is None:
                    raise SessionNotFoundError(user_id)
                user.name = name
                return user

    async def list_users(self):
        async with self._session_factory() as session:
            result = await session.scalars(select(UserORM).order_by(UserORM.id))
            return list(result)

    async def update_user_status(self, user_id: int, status: str):
        async with self._session_factory() as session:
            async with session.begin():
                user = await session.get(UserORM, user_id)
                if user is None:
                    raise SessionNotFoundError(user_id)
                if status == "disabled":
                    user.disabled_at = datetime.now(timezone.utc)
                elif status == "active":
                    user.disabled_at = None
                else:
                    raise ValueError(status)
                return user

    async def reset_password(self, user_id: int, *, new_password: str) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                user = await session.get(UserORM, user_id)
                if user is None:
                    raise SessionNotFoundError(user_id)
                user.password_hash = hash_password(new_password)
                await self._revoke_other_sessions(session, user_id, current_session_token=None)

    async def _revoke_other_sessions(self, session, user_id: int, *, current_session_token: str | None) -> None:
        current_prefix = None
        if current_session_token:
            try:
                current_prefix, _secret = parse_session_token(current_session_token)
            except Exception:
                current_prefix = None
        now = datetime.now(timezone.utc)
        rows = await session.scalars(
            select(UserSessionORM)
            .where(UserSessionORM.user_id == user_id)
            .where(UserSessionORM.revoked_at.is_(None))
        )
        for row in rows:
            if row.token_prefix != current_prefix:
                row.revoked_at = now

    async def create_api_key(
        self,
        user_id: int,
        *,
        name: str,
        mailbox_id: int | None = None,
        scopes: list[str] | None = None,
    ):
        raw_key = generate_api_key("live")
        parts = parse_api_key(raw_key)
        async with self._session_factory() as session:
            async with session.begin():
                key = ApiKeyORM(
                    user_id=user_id,
                    mailbox_id=mailbox_id,
                    scopes=scopes or ["read"],
                    name=name,
                    prefix=parts.prefix,
                    key_hash=hash_api_key(raw_key, self._active_token_hash_key()),
                    hash_version=self._active_token_hash_version,
                )
                session.add(key)
                await session.flush()
                return key, raw_key

    async def list_api_keys(self, user_id: int):
        async with self._session_factory() as session:
            result = await session.scalars(
                select(ApiKeyORM)
                .where(ApiKeyORM.user_id == user_id)
                .order_by(ApiKeyORM.id)
            )
            return list(result)

    async def authenticate_api_key(self, raw_key: str):
        parts = parse_api_key(raw_key)
        async with self._session_factory() as session:
            async with session.begin():
                key = (
                    await session.scalars(select(ApiKeyORM).where(ApiKeyORM.prefix == parts.prefix).limit(1))
                ).first()
                if key is None or key.revoked_at is not None:
                    raise ApiKeyNotFoundError("api key")
                token_hash_key = self._token_hash_keys.get(key.hash_version)
                if token_hash_key is None or not verify_api_key_hash(raw_key, key.key_hash, token_hash_key):
                    raise ApiKeyNotFoundError("api key")
                key.last_used_at = datetime.now(timezone.utc)
                return key

    async def revoke_api_key(self, user_id: int, api_key_id: int) -> None:
        await self.delete_api_key(user_id, api_key_id)

    async def delete_api_key(self, user_id: int, api_key_id: int) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                key = await session.get(ApiKeyORM, api_key_id)
                if key is None or key.user_id != user_id:
                    raise ApiKeyNotFoundError(api_key_id)
                await session.delete(key)

    async def update_api_key_status(self, user_id: int, api_key_id: int, status: str):
        async with self._session_factory() as session:
            async with session.begin():
                key = await session.get(ApiKeyORM, api_key_id)
                if key is None or key.user_id != user_id:
                    raise ApiKeyNotFoundError(api_key_id)
                if status == "disabled":
                    key.revoked_at = datetime.now(timezone.utc)
                elif status == "active":
                    key.revoked_at = None
                else:
                    raise ValueError(status)
                await session.flush()
                return key

    def _active_token_hash_key(self) -> bytes:
        return self._token_hash_keys[self._active_token_hash_version]


def _normalize_user_email(email: str) -> str:
    return email.strip().lower()
