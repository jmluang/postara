from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ErrorResponse:
    code: str
    message: str
    request_id: str
    details: dict[str, Any] = field(default_factory=dict)
    documentation_url: str | None = None

    def to_body(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "request_id": self.request_id,
            "details": self.details,
        }
        if self.documentation_url:
            payload["documentation_url"] = self.documentation_url
        return {"error": payload}
