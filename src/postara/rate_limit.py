from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock


class RateLimitExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class RateLimitRule:
    limit: int
    window_seconds: float


class InMemoryRateLimiter:
    def __init__(
        self,
        *,
        api_key_rule: RateLimitRule = RateLimitRule(limit=60, window_seconds=60),
        auth_failure_rule: RateLimitRule = RateLimitRule(limit=5, window_seconds=300),
    ) -> None:
        self._api_key_rule = api_key_rule
        self._auth_failure_rule = auth_failure_rule
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check_api_key(self, key_prefix: str) -> None:
        self._add_or_raise(("api_key", key_prefix), self._api_key_rule)

    def check_auth_failures(self, client_ip: str) -> None:
        self._check(("auth_failure", client_ip), self._auth_failure_rule)

    def record_auth_failure(self, client_ip: str) -> None:
        self._add_or_raise(("auth_failure", client_ip), self._auth_failure_rule)

    def _add_or_raise(self, bucket: tuple[str, str], rule: RateLimitRule) -> None:
        with self._lock:
            events = self._events[bucket]
            self._prune(events, rule)
            if len(events) >= rule.limit:
                raise RateLimitExceeded("Rate limit exceeded.")
            events.append(time.monotonic())

    def _check(self, bucket: tuple[str, str], rule: RateLimitRule) -> None:
        with self._lock:
            events = self._events[bucket]
            self._prune(events, rule)
            if len(events) >= rule.limit:
                raise RateLimitExceeded("Rate limit exceeded.")

    def _prune(self, events: deque[float], rule: RateLimitRule) -> None:
        cutoff = time.monotonic() - rule.window_seconds
        while events and events[0] <= cutoff:
            events.popleft()
