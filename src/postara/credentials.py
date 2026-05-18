from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AppPasswordCredential:
    password: str


@dataclass(frozen=True)
class OAuth2Credential:
    access_token: str
    scopes: tuple[str, ...]
    expires_at: datetime | None
