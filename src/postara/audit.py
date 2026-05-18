from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any


SENSITIVE_PREFIXES = (
    "password",
    "token",
    "key",
    "secret",
    "credential",
    "body",
    "content",
    "html",
)


def _is_sensitive(key: str) -> bool:
    normalized = key.lower()
    return any(prefix in normalized for prefix in SENSITIVE_PREFIXES)


def sanitize_extra(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            clean[key] = "[REDACTED]" if _is_sensitive(str(key)) else sanitize_extra(item)
        return clean
    if isinstance(value, list):
        return [sanitize_extra(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return deepcopy(value)


@dataclass(frozen=True)
class AuditEvent:
    action: str
    actor_type: str
    actor_id: str | None
    status: str
    request_id: str
    client_ip: str
    user_agent: str
    target_account_id: int | None = None
    extra: dict[str, Any] | None = None
    timestamp: datetime | None = None

    def sanitized(self) -> "AuditEvent":
        return replace(
            self,
            timestamp=self.timestamp or datetime.now(timezone.utc),
            extra=sanitize_extra(self.extra or {}),
        )

    def to_record(self) -> dict[str, Any]:
        event = self.sanitized()
        return {
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "action": event.action,
            "actor_type": event.actor_type,
            "actor_id": event.actor_id,
            "client_ip": event.client_ip,
            "user_agent": event.user_agent,
            "request_id": event.request_id,
            "target_account_id": event.target_account_id,
            "status": event.status,
            "extra": event.extra or {},
        }


@dataclass
class AuditOutboxItem:
    event: AuditEvent
    created_at: datetime
    delivered_at: datetime | None = None
    delivery_attempts: int = 0
    last_error: str | None = None


class AuditOutbox:
    def __init__(self) -> None:
        self.pending: list[AuditOutboxItem] = []

    def enqueue(self, event: AuditEvent) -> AuditOutboxItem:
        item = AuditOutboxItem(
            event=event.sanitized(),
            created_at=datetime.now(timezone.utc),
        )
        self.pending.append(item)
        return item
