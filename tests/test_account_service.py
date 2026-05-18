from postara.accounts import AccountService


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
