from __future__ import annotations

from postara.providers.base import (
    Folder,
    Message,
    MessageQuery,
    MessageSummary,
    UnsupportedProviderFeature,
    coerce_message_date,
)


class GmailAdapter:
    provider = "gmail"
    supported_query_fields = {
        "limit",
        "cursor",
        "unread_only",
        "since",
        "before",
        "from_address",
    }

    def validate_query(self, query: MessageQuery) -> None:
        unsupported: list[str] = []
        for field in ("subject_contains", "text_contains", "has_attachment"):
            value = getattr(query, field)
            if value not in (None, False, ""):
                unsupported.append(field)

        if unsupported:
            raise UnsupportedProviderFeature(unsupported)

    def default_folders(self) -> list[Folder]:
        return [
            Folder("INBOX", "INBOX", "/", []),
            Folder("SENT", "[Gmail]/Sent Mail", "/", []),
            Folder("DRAFTS", "[Gmail]/Drafts", "/", []),
            Folder("TRASH", "[Gmail]/Trash", "/", []),
            Folder("SPAM", "[Gmail]/Spam", "/", []),
        ]

    def list_messages(self, mailbox, folder: str, query: MessageQuery) -> list[MessageSummary]:
        self.validate_query(query)
        mailbox.folder.set(folder)
        criteria = self._criteria(query)
        mails = mailbox.fetch(criteria, limit=query.limit, reverse=True, mark_seen=False)
        return [self._summary(mail) for mail in mails]

    def list_folders(self, mailbox) -> list[Folder]:
        return [
            Folder(
                semantic_name=self._semantic_folder_name(info.name),
                native_name=info.name,
                delimiter=info.delim,
                flags=list(info.flags),
            )
            for info in mailbox.folder.list()
        ]

    def fetch_message(self, mailbox, folder: str, uid: str) -> Message | None:
        uid_number = self._uid_number(uid)
        mailbox.folder.set(folder)
        mails = list(mailbox.fetch(f"UID {uid_number}", limit=1, reverse=False, mark_seen=False))
        if not mails:
            return None
        mail = mails[0]
        return Message(
            uid=str(mail.uid),
            subject=getattr(mail, "subject", None),
            from_address=getattr(mail, "from_", None),
            date=coerce_message_date(getattr(mail, "date", None)),
            text=getattr(mail, "text", None),
            html=getattr(mail, "html", None),
            seen=self._seen(mail),
            attachments=[self._attachment_metadata(attachment) for attachment in getattr(mail, "attachments", ())],
        )

    def mark_seen(self, mailbox, folder: str, uid: str, seen: bool) -> None:
        uid_number = self._uid_number(uid)
        mailbox.folder.set(folder)
        mailbox.flag([uid_number], "\\Seen", seen)

    def _criteria(self, query: MessageQuery) -> str:
        parts = ["ALL"]
        if query.cursor:
            cursor = self._uid_number(query.cursor)
            if cursor > 1:
                parts.append(f"UID 1:{cursor - 1}")
            else:
                parts.append("UID 0")
        if query.unread_only:
            parts.append("UNSEEN")
        if query.since:
            parts.append("SINCE " + query.since.strftime("%d-%b-%Y"))
        if query.before:
            parts.append("BEFORE " + query.before.strftime("%d-%b-%Y"))
        if query.from_address:
            parts.append(f'FROM "{query.from_address}"')
        return " ".join(parts)

    def _summary(self, mail) -> MessageSummary:
        return MessageSummary(
            uid=str(mail.uid),
            subject=getattr(mail, "subject", None),
            from_address=getattr(mail, "from_", None),
            date=coerce_message_date(getattr(mail, "date", None)),
            seen=self._seen(mail),
            has_attachments=bool(getattr(mail, "attachments", ())),
        )

    def _seen(self, mail) -> bool:
        return "\\Seen" in set(getattr(mail, "flags", ()))

    def _attachment_metadata(self, attachment) -> dict:
        return {
            "filename": getattr(attachment, "filename", None),
            "content_type": getattr(attachment, "content_type", None),
            "size": getattr(attachment, "size", None),
        }

    def _uid_number(self, uid: str) -> int:
        try:
            value = int(uid)
        except (TypeError, ValueError) as exc:
            from postara.providers.base import MessageNotFoundError

            raise MessageNotFoundError("Invalid message uid.") from exc
        if value <= 0:
            from postara.providers.base import MessageNotFoundError

            raise MessageNotFoundError("Invalid message uid.")
        return value

    def _semantic_folder_name(self, native_name: str) -> str:
        normalized = native_name.lower()
        mapping = {
            "inbox": "INBOX",
            "[gmail]/sent mail": "SENT",
            "[gmail]/drafts": "DRAFTS",
            "[gmail]/trash": "TRASH",
            "[gmail]/spam": "SPAM",
        }
        return mapping.get(normalized, "CUSTOM")
