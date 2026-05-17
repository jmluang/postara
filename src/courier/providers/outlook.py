from __future__ import annotations


class OutlookAdapter:
    provider = "outlook"

    def validate_query(self, _query) -> None:
        raise NotImplementedError("Outlook provider is registered for v0.3+ implementation.")

    def list_folders(self, _mailbox):
        raise NotImplementedError("Outlook provider is registered for v0.3+ implementation.")

    def list_messages(self, _mailbox, _folder, _query):
        raise NotImplementedError("Outlook provider is registered for v0.3+ implementation.")

    def fetch_message(self, _mailbox, _folder, _uid):
        raise NotImplementedError("Outlook provider is registered for v0.3+ implementation.")

    def mark_seen(self, _mailbox, _folder, _uid, _seen) -> None:
        raise NotImplementedError("Outlook provider is registered for v0.3+ implementation.")
