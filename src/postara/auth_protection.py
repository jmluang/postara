from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from postara.models import AuthAttemptBucketORM


class AuthRateLimited(RuntimeError):
    pass


class AuthChallengeRequired(RuntimeError):
    pass


class AuthChallengeFailed(RuntimeError):
    pass


@dataclass(frozen=True)
class AuthProtectionConfig:
    enabled: bool = True
    challenge_enabled: bool = False
    failure_limit: int = 5
    challenge_threshold: int = 3
    window_seconds: int = 300
    lock_seconds: int = 300


@dataclass
class AuthAttemptBucket:
    bucket_type: str
    bucket_key: str
    failure_count: int
    window_started_at: datetime
    locked_until: datetime | None = None
    challenge_required_at: datetime | None = None
    last_failure_at: datetime | None = None


def normalize_email_key(email: str) -> str:
    return email.strip().lower()


def normalize_ip_key(client_ip: str) -> str:
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return client_ip.strip().lower() or "unknown"
    if isinstance(address, ipaddress.IPv6Address):
        return str(ipaddress.ip_network(f"{address}/64", strict=False).network_address) + "/64"
    return str(address)


def resolve_client_ip(*, peer_ip: str, headers: dict[str, str], trusted_proxy_cidrs: list[str]) -> str:
    if not _is_trusted_proxy(peer_ip, trusted_proxy_cidrs):
        return peer_ip
    cf_ip = headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    forwarded_for = headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return peer_ip


def _is_trusted_proxy(peer_ip: str, trusted_proxy_cidrs: list[str]) -> bool:
    if not trusted_proxy_cidrs:
        return False
    try:
        address = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    for cidr in trusted_proxy_cidrs:
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


class InMemoryAuthAttemptStore:
    def __init__(self) -> None:
        self._buckets: dict[tuple[str, str], AuthAttemptBucket] = {}

    async def get(self, bucket_type: str, bucket_key: str) -> AuthAttemptBucket | None:
        return self._buckets.get((bucket_type, bucket_key))

    async def upsert(self, bucket: AuthAttemptBucket) -> None:
        self._buckets[(bucket.bucket_type, bucket.bucket_key)] = bucket

    async def clear(self, bucket_type: str, bucket_key: str) -> None:
        self._buckets.pop((bucket_type, bucket_key), None)

    async def purge_expired(self, cutoff: datetime) -> int:
        expired = [
            key
            for key, bucket in self._buckets.items()
            if bucket.window_started_at < cutoff and (bucket.locked_until is None or bucket.locked_until < cutoff)
        ]
        for key in expired:
            self._buckets.pop(key, None)
        return len(expired)


class SqlAuthAttemptStore:
    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    async def get(self, bucket_type: str, bucket_key: str) -> AuthAttemptBucket | None:
        async with self._session_factory() as session:
            row = (
                await session.scalars(
                    select(AuthAttemptBucketORM)
                    .where(AuthAttemptBucketORM.bucket_type == bucket_type)
                    .where(AuthAttemptBucketORM.bucket_key == bucket_key)
                    .limit(1)
                )
            ).first()
            if row is None:
                return None
            return _bucket_from_row(row)

    async def upsert(self, bucket: AuthAttemptBucket) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                row = (
                    await session.scalars(
                        select(AuthAttemptBucketORM)
                        .where(AuthAttemptBucketORM.bucket_type == bucket.bucket_type)
                        .where(AuthAttemptBucketORM.bucket_key == bucket.bucket_key)
                        .limit(1)
                    )
                ).first()
                if row is None:
                    session.add(_row_from_bucket(bucket))
                    await session.flush()
                    return
                row.failure_count = bucket.failure_count
                row.window_started_at = bucket.window_started_at
                row.locked_until = bucket.locked_until
                row.challenge_required_at = bucket.challenge_required_at
                row.last_failure_at = bucket.last_failure_at
                row.updated_at = datetime.now(timezone.utc)

    async def clear(self, bucket_type: str, bucket_key: str) -> None:
        async with self._session_factory() as session:
            async with session.begin():
                await session.execute(
                    delete(AuthAttemptBucketORM)
                    .where(AuthAttemptBucketORM.bucket_type == bucket_type)
                    .where(AuthAttemptBucketORM.bucket_key == bucket_key)
                )

    async def purge_expired(self, cutoff: datetime) -> int:
        async with self._session_factory() as session:
            async with session.begin():
                result = await session.execute(
                    delete(AuthAttemptBucketORM)
                    .where(AuthAttemptBucketORM.window_started_at < cutoff)
                    .where(
                        (AuthAttemptBucketORM.locked_until.is_(None))
                        | (AuthAttemptBucketORM.locked_until < cutoff)
                    )
                )
                return result.rowcount or 0


class AuthAttemptLimiter:
    def __init__(self, store, config: AuthProtectionConfig) -> None:
        self._store = store
        self._config = config

    async def check(self, *, action: str, email: str, client_ip: str, challenge_token: str | None = None) -> None:
        if not self._config.enabled:
            return
        for bucket_type, bucket_key in self._bucket_keys(action=action, email=email, client_ip=client_ip):
            bucket = await self._active_bucket(bucket_type, bucket_key)
            if bucket is None:
                continue
            now = datetime.now(timezone.utc)
            if bucket.locked_until and bucket.locked_until > now:
                raise AuthRateLimited("Authentication is temporarily rate limited.")
            if self._config.challenge_enabled and bucket.failure_count >= self._config.challenge_threshold:
                if not challenge_token:
                    raise AuthChallengeRequired("Authentication challenge is required.")
                raise AuthChallengeFailed("Authentication challenge failed.")

    async def record_failure(self, *, action: str, email: str, client_ip: str) -> None:
        if not self._config.enabled:
            return
        for bucket_type, bucket_key in self._bucket_keys(action=action, email=email, client_ip=client_ip):
            await self._record_bucket_failure(bucket_type, bucket_key)

    async def clear(self, *, action: str, email: str, client_ip: str) -> None:
        if not self._config.enabled:
            return
        for bucket_type, bucket_key in self._bucket_keys(action=action, email=email, client_ip=client_ip):
            await self._store.clear(bucket_type, bucket_key)

    async def purge_expired(self) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._config.window_seconds + self._config.lock_seconds)
        return await self._store.purge_expired(cutoff)

    def _bucket_keys(self, *, action: str, email: str, client_ip: str) -> list[tuple[str, str]]:
        normalized_action = "register" if action == "register" else "login"
        return [
            (f"{normalized_action}:email", normalize_email_key(email)),
            (f"{normalized_action}:ip", normalize_ip_key(client_ip)),
        ]

    async def _active_bucket(self, bucket_type: str, bucket_key: str) -> AuthAttemptBucket | None:
        bucket = await self._store.get(bucket_type, bucket_key)
        if bucket is None:
            return None
        now = datetime.now(timezone.utc)
        if bucket.window_started_at + timedelta(seconds=self._config.window_seconds) <= now:
            if bucket.locked_until is None or bucket.locked_until <= now:
                await self._store.clear(bucket_type, bucket_key)
                return None
        return bucket

    async def _record_bucket_failure(self, bucket_type: str, bucket_key: str) -> None:
        now = datetime.now(timezone.utc)
        bucket = await self._active_bucket(bucket_type, bucket_key)
        if bucket is None:
            bucket = AuthAttemptBucket(
                bucket_type=bucket_type,
                bucket_key=bucket_key,
                failure_count=0,
                window_started_at=now,
            )
        bucket.failure_count += 1
        bucket.last_failure_at = now
        if self._config.challenge_enabled and bucket.failure_count >= self._config.challenge_threshold:
            bucket.challenge_required_at = bucket.challenge_required_at or now
        if bucket.failure_count > self._config.failure_limit:
            bucket.locked_until = now + timedelta(seconds=self._config.lock_seconds)
        await self._store.upsert(bucket)
        if bucket.locked_until and bucket.locked_until > now:
            raise AuthRateLimited("Authentication is temporarily rate limited.")


def _bucket_from_row(row: AuthAttemptBucketORM) -> AuthAttemptBucket:
    return AuthAttemptBucket(
        bucket_type=row.bucket_type,
        bucket_key=row.bucket_key,
        failure_count=row.failure_count,
        window_started_at=row.window_started_at,
        locked_until=row.locked_until,
        challenge_required_at=row.challenge_required_at,
        last_failure_at=row.last_failure_at,
    )


def _row_from_bucket(bucket: AuthAttemptBucket) -> AuthAttemptBucketORM:
    return AuthAttemptBucketORM(
        bucket_type=bucket.bucket_type,
        bucket_key=bucket.bucket_key,
        failure_count=bucket.failure_count,
        window_started_at=bucket.window_started_at,
        locked_until=bucket.locked_until,
        challenge_required_at=bucket.challenge_required_at,
        last_failure_at=bucket.last_failure_at,
    )
