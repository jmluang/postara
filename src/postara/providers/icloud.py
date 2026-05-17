from __future__ import annotations


class IcloudAdapter:
    provider = "icloud"

    def validate_query(self, _query) -> None:
        raise NotImplementedError("iCloud provider is registered for v0.2+ implementation.")

    def list_folders(self, _mailbox):
        raise NotImplementedError("iCloud provider is registered for v0.2+ implementation.")

    def list_messages(self, _mailbox, _folder, _query):
        raise NotImplementedError("iCloud provider is registered for v0.2+ implementation.")

    def fetch_message(self, _mailbox, _folder, _uid):
        raise NotImplementedError("iCloud provider is registered for v0.2+ implementation.")

    def mark_seen(self, _mailbox, _folder, _uid, _seen) -> None:
        raise NotImplementedError("iCloud provider is registered for v0.2+ implementation.")
