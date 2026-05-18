from __future__ import annotations

from dataclasses import dataclass


class OutboundEmailError(RuntimeError):
    pass


@dataclass(frozen=True)
class OutboundEmail:
    to: str
    subject: str
    text: str


class InMemoryOutboundEmailClient:
    def __init__(self) -> None:
        self.sent: list[OutboundEmail] = []

    def send(self, email: OutboundEmail) -> None:
        self.sent.append(email)
