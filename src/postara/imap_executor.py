from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import BoundedSemaphore
from typing import TypeVar


T = TypeVar("T")


class ImapExecutionTimeout(TimeoutError):
    pass


class ImapExecutor:
    def __init__(self, max_workers: int = 8, per_account_limit: int = 2, timeout_seconds: float = 30.0) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="postara-imap")
        self._per_account_limit = per_account_limit
        self._timeout_seconds = timeout_seconds
        self._account_locks: dict[int, BoundedSemaphore] = {}

    def _lock_for(self, account_id: int) -> BoundedSemaphore:
        lock = self._account_locks.get(account_id)
        if lock is None:
            lock = BoundedSemaphore(self._per_account_limit)
            self._account_locks[account_id] = lock
        return lock

    def run(self, account_id: int, func: Callable[[], T], timeout_seconds: float | None = None) -> T:
        lock = self._lock_for(account_id)

        def guarded() -> T:
            with lock:
                return func()

        future = self._pool.submit(guarded)
        try:
            return future.result(timeout=timeout_seconds or self._timeout_seconds)
        except TimeoutError as exc:
            future.cancel()
            raise ImapExecutionTimeout("IMAP operation timed out.") from exc

    def shutdown(self) -> None:
        self._pool.shutdown(wait=True, cancel_futures=True)
