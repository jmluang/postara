from __future__ import annotations

import imaplib

from imap_tools import MailBox
from imap_tools.errors import MailboxLoginError

from postara.config import Settings
from postara.imap_executor import ImapExecutionTimeout, ImapExecutor
from postara.providers.base import AuthenticationError, MessageQuery, ProviderConnectionError
from postara.providers.gmail import GmailAdapter
from postara.providers.registry import ProviderRegistry


class MailboxRuntime:
    def __init__(
        self,
        *,
        executor: ImapExecutor | None = None,
        adapter: GmailAdapter | None = None,
        registry: ProviderRegistry | None = None,
        settings: Settings | None = None,
    ) -> None:
        settings = settings or Settings()
        self._executor = executor or ImapExecutor(
            max_workers=settings.imap_workers,
            timeout_seconds=settings.imap_timeout_seconds,
        )
        self._registry = registry or ProviderRegistry.default()
        self._adapter = adapter
        self._timeout_seconds = settings.imap_timeout_seconds

    def _adapter_for(self, account):
        if self._adapter is not None:
            return self._adapter
        return self._registry.get(account.provider)

    def _with_mailbox(self, account, password: str, callback):
        def work():
            try:
                with MailBox(
                    account.imap_host,
                    port=account.imap_port,
                    timeout=self._timeout_seconds,
                ).login(account.email, password) as mailbox:
                    return callback(mailbox)
            except (imaplib.IMAP4.error, MailboxLoginError) as exc:
                raise AuthenticationError("IMAP authentication failed.") from exc
            except OSError as exc:
                raise ProviderConnectionError("IMAP connection failed.") from exc

        try:
            return self._executor.run(account.id, work)
        except ImapExecutionTimeout as exc:
            raise ProviderConnectionError("IMAP operation timed out.") from exc

    def validate_credentials(self, *, email: str, password: str, imap_host: str, imap_port: int) -> None:
        def work():
            try:
                with MailBox(
                    imap_host,
                    port=imap_port,
                    timeout=self._timeout_seconds,
                ).login(email, password):
                    return None
            except (imaplib.IMAP4.error, MailboxLoginError) as exc:
                raise AuthenticationError("IMAP authentication failed.") from exc
            except OSError as exc:
                raise ProviderConnectionError("IMAP connection failed.") from exc

        try:
            return self._executor.run(0, work)
        except ImapExecutionTimeout as exc:
            raise ProviderConnectionError("IMAP operation timed out.") from exc

    def list_messages(self, account, password: str, folder: str, query: MessageQuery):
        return self._with_mailbox(
            account,
            password,
            lambda mailbox: self._adapter_for(account).list_messages(mailbox, folder, query),
        )

    def list_folders(self, account, password: str):
        return self._with_mailbox(
            account,
            password,
            lambda mailbox: self._adapter_for(account).list_folders(mailbox),
        )

    def fetch_message(self, account, password: str, folder: str, uid: str):
        return self._with_mailbox(
            account,
            password,
            lambda mailbox: self._adapter_for(account).fetch_message(mailbox, folder, uid),
        )

    def mark_seen(self, account, password: str, folder: str, uid: str, seen: bool) -> None:
        return self._with_mailbox(
            account,
            password,
            lambda mailbox: self._adapter_for(account).mark_seen(mailbox, folder, uid, seen),
        )
