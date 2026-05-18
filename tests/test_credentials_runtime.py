from datetime import datetime, timezone

import pytest

from postara.accounts import AccountService, MailboxReconnectRequiredError
from postara.credentials import AppPasswordCredential, OAuth2Credential


def test_runtime_credential_types_are_explicit():
    password = AppPasswordCredential(password="app-password")
    oauth = OAuth2Credential(
        access_token="access-token",
        scopes=("openid", "email"),
        expires_at=datetime(2026, 5, 17, tzinfo=timezone.utc),
    )

    assert password.password == "app-password"
    assert oauth.access_token == "access-token"
    assert oauth.scopes == ("openid", "email")


def test_account_service_resolves_app_password_runtime_credential():
    service = AccountService()
    account = service.create_with_app_password(
        user_id=1,
        name="work",
        email="work@example.com",
        provider="gmail",
        password="app-password",
    )

    credential = service.get_credential_for_runtime(account.id)

    assert credential == AppPasswordCredential(password="app-password")


def test_account_service_resolves_oauth_runtime_credential():
    service = AccountService()
    account = service.create_with_oauth(
        user_id=1,
        name="gmail",
        email="typed@example.com",
        provider="gmail",
        refresh_token="refresh-token",
        access_token="access-token",
        expires_at=None,
        scopes=("openid", "email"),
        subject="google-subject",
        oauth_email="provider@example.com",
    )

    credential = service.get_credential_for_runtime(account.id)

    assert credential == OAuth2Credential(access_token="access-token", scopes=("openid", "email"), expires_at=None)


def test_account_service_marks_oauth_mailbox_reconnect_required_without_access_token():
    service = AccountService()
    account = service.create_with_oauth(
        user_id=1,
        name="gmail",
        email="typed@example.com",
        provider="gmail",
        refresh_token="refresh-token",
        access_token=None,
        expires_at=None,
        scopes=("openid", "email"),
        subject="google-subject",
        oauth_email="provider@example.com",
    )

    with pytest.raises(MailboxReconnectRequiredError):
        service.get_credential_for_runtime(account.id)
