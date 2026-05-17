import pytest
from imap_tools.errors import MailboxLoginError

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
