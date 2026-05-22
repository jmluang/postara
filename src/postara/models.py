from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Integer, JSON, LargeBinary, SmallInteger, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


JSON_TYPE = JSON().with_variant(JSONB(), "postgresql")
INET_TYPE = String().with_variant(INET(), "postgresql")
ID_TYPE = Integer().with_variant(BigInteger(), "postgresql")


class UserORM(Base):
    __tablename__ = "users"
    __table_args__ = {"schema": "app"}

    id: Mapped[int] = mapped_column(ID_TYPE, primary_key=True)
    email: Mapped[str] = mapped_column(Text, unique=True, index=True)
    name: Mapped[str] = mapped_column(Text)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text, default="member")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dto(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
            "disabled_at": self.disabled_at,
        }


class AuthAttemptBucketORM(Base):
    __tablename__ = "auth_attempt_buckets"
    __table_args__ = (
        UniqueConstraint("bucket_type", "bucket_key", name="uq_app_auth_attempt_buckets_type_key"),
        {"schema": "app"},
    )

    id: Mapped[int] = mapped_column(ID_TYPE, primary_key=True)
    bucket_type: Mapped[str] = mapped_column(Text, index=True)
    bucket_key: Mapped[str] = mapped_column(Text, index=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    challenge_required_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class UserSessionORM(Base):
    __tablename__ = "user_sessions"
    __table_args__ = {"schema": "app"}

    id: Mapped[int] = mapped_column(ID_TYPE, primary_key=True)
    user_id: Mapped[int] = mapped_column(ID_TYPE, index=True)
    token_prefix: Mapped[str] = mapped_column(String(8), unique=True, index=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ApiKeyORM(Base):
    __tablename__ = "api_keys"
    __table_args__ = {"schema": "app"}

    id: Mapped[int] = mapped_column(ID_TYPE, primary_key=True)
    user_id: Mapped[int] = mapped_column(ID_TYPE, index=True)
    mailbox_id: Mapped[int | None] = mapped_column(ID_TYPE, nullable=True, index=True)
    scopes: Mapped[list[str]] = mapped_column(JSON_TYPE, default=list)
    name: Mapped[str] = mapped_column(Text)
    prefix: Mapped[str] = mapped_column(String(8), unique=True, index=True)
    key_hash: Mapped[bytes] = mapped_column(LargeBinary)
    hash_version: Mapped[int] = mapped_column(SmallInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dto(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "mailbox_id": self.mailbox_id,
            "scopes": self.scopes or [],
            "name": self.name,
            "prefix": self.prefix,
            "status": "disabled" if self.revoked_at else "active",
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "disabled_at": self.revoked_at,
            "revoked_at": self.revoked_at,
        }


class AccountORM(Base):
    __tablename__ = "accounts"
    __table_args__ = (
        UniqueConstraint("user_id", "email", name="uq_app_accounts_user_id_email"),
        UniqueConstraint("user_id", "name", name="uq_app_accounts_user_id_name"),
        {"schema": "app"},
    )

    id: Mapped[int] = mapped_column(ID_TYPE, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ID_TYPE, nullable=True, index=True)
    name: Mapped[str] = mapped_column(Text)
    email: Mapped[str] = mapped_column(Text, index=True)
    provider: Mapped[str] = mapped_column(Text, default="gmail")
    auth_type: Mapped[str] = mapped_column(Text, default="app_password")
    encrypted_password: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    key_version: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    oauth_refresh_token: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    oauth_access_token: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    oauth_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    oauth_scopes: Mapped[list[str] | None] = mapped_column(JSON_TYPE, nullable=True)
    oauth_subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    oauth_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    imap_host: Mapped[str] = mapped_column(Text)
    imap_port: Mapped[int] = mapped_column(Integer)
    api_key_prefix: Mapped[str] = mapped_column(String(8), unique=True, index=True)
    api_key_hash: Mapped[bytes] = mapped_column(LargeBinary)
    api_key_hash_version: Mapped[int] = mapped_column(SmallInteger)
    previous_api_key_hash: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    previous_api_key_hash_version: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    previous_valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    health_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="unknown")
    health_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    health_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    def to_dto(self) -> dict[str, Any]:
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
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "health": {
                "status": self.health_status,
                "checked_at": self.health_checked_at,
                "detail": self.health_detail,
            },
        }


class PendingMailboxVerificationORM(Base):
    __tablename__ = "pending_mailbox_verifications"
    __table_args__ = {"schema": "app"}

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ID_TYPE, index=True)
    mailbox_id: Mapped[int | None] = mapped_column(ID_TYPE, nullable=True, index=True)
    provider: Mapped[str] = mapped_column(Text)
    auth_type: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    email: Mapped[str] = mapped_column(Text, index=True)
    encrypted_password: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(SmallInteger)
    code_hash: Mapped[bytes] = mapped_column(LargeBinary)
    code_hash_version: Mapped[int] = mapped_column(SmallInteger, default=1)
    attempts: Mapped[int] = mapped_column(SmallInteger, default=0)
    status: Mapped[str] = mapped_column(Text, default="verifying", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dto(self) -> dict[str, Any]:
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
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "verified_at": self.verified_at,
        }


class AuditOutboxORM(Base):
    __tablename__ = "audit_outbox"
    __table_args__ = {"schema": "app"}

    id: Mapped[int] = mapped_column(ID_TYPE, primary_key=True)
    event: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivery_attempts: Mapped[int] = mapped_column(SmallInteger, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditEventORM(Base):
    __tablename__ = "events"
    __table_args__ = {"schema": "audit"}

    id: Mapped[int] = mapped_column(ID_TYPE, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor_type: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    client_ip: Mapped[str] = mapped_column(INET_TYPE)
    user_agent: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text, index=True)
    target_account_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    status: Mapped[str] = mapped_column(Text)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict)
    request_id: Mapped[str] = mapped_column(Text, index=True)
