import pytest

from postara.accounts import AccountService, MailboxReconnectRequiredError


def test_in_memory_account_service_creates_oauth_account_with_provider_email():
    service = AccountService()

    account = service.create_with_oauth(
        user_id=1,
        name="oauth-gmail",
        email="typed@example.com",
        provider="gmail",
        refresh_token="refresh-token",
        access_token="access-token",
        expires_at=None,
        scopes=("openid", "email"),
        subject="google-sub",
        oauth_email="provider@example.com",
    )

    assert account.auth_type == "oauth2"
    assert account.email == "provider@example.com"
    assert account.encrypted_password is None
    assert account.oauth_refresh_token is not None


def test_new_account_starts_with_unknown_health():
    service = AccountService()

    account, _api_key = service.create(
        name="work",
        email="work@example.com",
        provider="gmail",
        password="app-password",
        user_id=1,
    )

    assert account.health_status == "unknown"
    assert account.health_checked_at is None


def test_get_credential_for_runtime_marks_mailbox_healthy_on_success():
    service = AccountService()
    account, _api_key = service.create(
        name="work",
        email="work@example.com",
        provider="gmail",
        password="app-password",
        user_id=1,
    )

    service.get_credential_for_runtime(account.id)

    stored = service.get(account.id)
    assert stored.health_status == "ok"
    assert stored.health_detail is None
    assert stored.health_checked_at is not None


def test_get_credential_for_runtime_marks_reconnect_required_on_oauth_failure():
    service = AccountService()
    account = service.create_with_oauth(
        user_id=1,
        name="oauth-gmail",
        email="typed@example.com",
        provider="gmail",
        refresh_token="refresh-token",
        access_token=None,
        expires_at=None,
        scopes=("openid", "email"),
        subject="google-sub",
        oauth_email="provider@example.com",
    )

    with pytest.raises(MailboxReconnectRequiredError):
        service.get_credential_for_runtime(account.id)

    stored = service.get(account.id)
    assert stored.health_status == "reconnect_required"
    # detail is a controlled enum code, never raw provider text or secrets.
    assert stored.health_detail == "credentials_missing"
