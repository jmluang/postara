from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from postara.providers.base import MessageQuery, MessageNotFoundError
from postara.providers.gmail import GmailAdapter


@dataclass
class FakeFolderInfo:
    name: str
    delim: str = "/"
    flags: tuple[str, ...] = ()


@dataclass
class FakeMail:
    uid: str
    subject: str = "Hello"
    from_: str = "sender@example.com"
    date: datetime = datetime(2026, 5, 16, tzinfo=timezone.utc)
    flags: tuple[str, ...] = ("\\Seen",)
    attachments: tuple[object, ...] = ()
    text: str = "plain"
    html: str = "<p>html</p>"


class FakeFolder:
    def __init__(self):
        self.selected = None

    def set(self, name):
        self.selected = name

    def list(self):
        return [
            FakeFolderInfo("INBOX"),
            FakeFolderInfo("[Gmail]/Sent Mail", flags=("\\Sent",)),
            FakeFolderInfo("[Gmail]", flags=("\\Noselect",)),
            FakeFolderInfo("[Gmail]/垃圾邮件", flags=("\\Junk",)),
            FakeFolderInfo("[Gmail]/已删除邮件"),
            FakeFolderInfo("[Gmail]/所有邮件", flags=("\\All",)),
            FakeFolderInfo("Receipts"),
        ]


class FakeMailbox:
    def __init__(self, mails):
        self.folder = FakeFolder()
        self.mails = mails
        self.fetch_args = None
        self.flag_calls = []

    def fetch(self, criteria, limit=None, reverse=False, mark_seen=False):
        self.fetch_args = {
            "criteria": criteria,
            "limit": limit,
            "reverse": reverse,
            "mark_seen": mark_seen,
        }
        return self.mails

    def flag(self, uids, flag, value):
        uid_list = list(uids)
        for uid in uid_list:
            if not isinstance(uid, str):
                raise TypeError(f'uid "{uid}" is not string')
        self.flag_calls.append((uid_list, flag, value))


def test_list_messages_maps_imap_mail_to_summary():
    mailbox = FakeMailbox([FakeMail(uid="42")])
    adapter = GmailAdapter()

    messages = adapter.list_messages(mailbox, "INBOX", MessageQuery(limit=10))

    assert mailbox.folder.selected == "INBOX"
    assert mailbox.fetch_args["limit"] == 10
    assert mailbox.fetch_args["reverse"] is True
    assert messages[0].uid == "42"
    assert messages[0].seen is True


def test_fetch_message_returns_full_body_and_attachment_metadata():
    attachment = type("Attachment", (), {"filename": "a.pdf", "content_type": "application/pdf", "size": 123})()
    mailbox = FakeMailbox([FakeMail(uid="42", attachments=(attachment,))])
    adapter = GmailAdapter()

    message = adapter.fetch_message(mailbox, "INBOX", "42")

    assert message is not None
    assert message.html == "<p>html</p>"
    assert message.attachments == [{"filename": "a.pdf", "content_type": "application/pdf", "size": 123}]


def test_mark_seen_uses_imap_seen_flag():
    mailbox = FakeMailbox([])
    adapter = GmailAdapter()

    adapter.mark_seen(mailbox, "INBOX", "42", True)

    assert mailbox.folder.selected == "INBOX"
    assert mailbox.flag_calls == [(["42"], "\\Seen", True)]


def test_mark_seen_rejects_invalid_uid():
    mailbox = FakeMailbox([])
    adapter = GmailAdapter()

    with pytest.raises(MessageNotFoundError):
        adapter.mark_seen(mailbox, "INBOX", "bad uid", True)

    assert mailbox.flag_calls == []


def test_list_folders_maps_gmail_semantic_names():
    mailbox = FakeMailbox([])
    adapter = GmailAdapter()

    folders = adapter.list_folders(mailbox)

    assert folders[0].semantic_name == "INBOX"
    assert folders[1].semantic_name == "SENT"
    assert folders[2].semantic_name == "SPAM"
    assert folders[2].native_name == "[Gmail]/垃圾邮件"
    assert folders[3].semantic_name == "TRASH"
    assert folders[4].semantic_name == "ALL"
    assert folders[5].semantic_name == "CUSTOM"
    assert folders[5].native_name == "Receipts"
    assert "[Gmail]" not in [folder.native_name for folder in folders]
