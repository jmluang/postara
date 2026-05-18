from types import SimpleNamespace

import pytest
from imap_tools.errors import MailboxLoginError

from postara.credentials import AppPasswordCredential, OAuth2Credential
from postara.mailbox import MailboxRuntime
from postara.providers.base import AuthenticationError


class ImmediateExecutor:
    def run(self, _account_id, callback):
        return callback()


class RejectingMailBox:
    def __init__(self, *_args, **_kwargs):
        pass

    def login(self, *_args, **_kwargs):
        raise MailboxLoginError(command_result=("NO", [b"invalid credentials"]), expected="OK")


class RecordingMailBox:
    calls = []

    def __init__(self, host, *, port, timeout):
        self.host = host
        self.port = port
        self.timeout = timeout

    def login(self, email, password):
        self.calls.append(("login", self.host, self.port, email, password))
        return self

    def xoauth2(self, email, access_token):
        self.calls.append(("xoauth2", self.host, self.port, email, access_token))
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class FolderAdapter:
    def list_folders(self, _mailbox):
        return ["INBOX"]


def account():
    return SimpleNamespace(id=1, email="work@example.com", provider="gmail", imap_host="imap.gmail.com", imap_port=993)


def test_validate_credentials_maps_imap_tools_login_error(monkeypatch):
    monkeypatch.setattr("postara.mailbox.MailBox", RejectingMailBox)
    runtime = MailboxRuntime(executor=ImmediateExecutor())

    with pytest.raises(AuthenticationError):
        runtime.validate_credentials(
            email="work@example.com",
            password="wrong-password",
            imap_host="imap.gmail.com",
            imap_port=993,
        )


def test_runtime_uses_normal_login_for_app_password(monkeypatch):
    RecordingMailBox.calls = []
    monkeypatch.setattr("postara.mailbox.MailBox", RecordingMailBox)
    runtime = MailboxRuntime(executor=ImmediateExecutor(), adapter=FolderAdapter())

    folders = runtime.list_folders(account(), AppPasswordCredential(password="app-password"))

    assert folders == ["INBOX"]
    assert RecordingMailBox.calls == [("login", "imap.gmail.com", 993, "work@example.com", "app-password")]


def test_runtime_uses_xoauth2_for_oauth(monkeypatch):
    RecordingMailBox.calls = []
    monkeypatch.setattr("postara.mailbox.MailBox", RecordingMailBox)
    runtime = MailboxRuntime(executor=ImmediateExecutor(), adapter=FolderAdapter())

    folders = runtime.list_folders(account(), OAuth2Credential(access_token="access-token", scopes=("email",), expires_at=None))

    assert folders == ["INBOX"]
    assert RecordingMailBox.calls == [("xoauth2", "imap.gmail.com", 993, "work@example.com", "access-token")]
