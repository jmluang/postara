from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime


class ProviderError(Exception):
    pass


class AuthenticationError(ProviderError):
    pass


class ProviderConnectionError(ProviderError):
    pass


class FolderNotFoundError(ProviderError):
    pass


class MessageNotFoundError(ProviderError):
    pass


class RateLimitedError(ProviderError):
    pass


class UnsupportedProviderFeature(ProviderError):
    def __init__(self, fields: list[str]) -> None:
        self.fields = fields
        super().__init__(f"Unsupported query fields: {', '.join(fields)}")


@dataclass(frozen=True)
class Folder:
    semantic_name: str
    native_name: str
    delimiter: str
    flags: list[str]


@dataclass(frozen=True)
class MessageQuery:
    limit: int = 20
    cursor: str | None = None
    unread_only: bool = False
    since: datetime | None = None
    before: datetime | None = None
    from_address: str | None = None
    subject_contains: str | None = None
    text_contains: str | None = None
    has_attachment: bool | None = None


@dataclass(frozen=True)
class MessageSummary:
    uid: str
    subject: str | None
    from_address: str | None
    date: datetime | None
    seen: bool
    has_attachments: bool


@dataclass(frozen=True)
class Message:
    uid: str
    subject: str | None
    from_address: str | None
    date: datetime | None
    text: str | None
    html: str | None
    seen: bool
    attachments: list[dict]


def coerce_message_date(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return parsedate_to_datetime(value)
    return None
