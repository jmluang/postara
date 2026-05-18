import re

import pytest
from fastapi.testclient import TestClient

from postara.accounts import AccountService
from postara.api import _LazyAccountService, create_app
from postara.config import Settings
from postara.oauth import OAuthTokenResult
from postara.outbound_email import InMemoryOutboundEmailClient
from postara.providers.base import AuthenticationError
from postara.users import UserService


class FakeMailboxRuntime:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.validated = []

    def validate_credentials(self, **kwargs):
        self.validated.append(kwargs)
        if not self.valid:
            raise AuthenticationError("invalid credentials")


class FakeOAuthClient:
    def __init__(self) -> None:
        self.authorization_calls = []
        self.exchange_calls = []

    def authorization_url(self, *, state: str, redirect_uri: str, scopes: tuple[str, ...]) -> str:
        self.authorization_calls.append({"state": state, "redirect_uri": redirect_uri, "scopes": scopes})
        return f"https://accounts.example.test/auth?state={state}&redirect_uri={redirect_uri}"

    def exchange_code(self, *, code: str, redirect_uri: str) -> OAuthTokenResult:
        self.exchange_calls.append({"code": code, "redirect_uri": redirect_uri})
        return OAuthTokenResult(
            refresh_token="refresh-token",
            access_token="access-token",
            expires_at=None,
            scopes=("openid", "email", "https://mail.google.com/"),
            subject="google-subject",
            email="provider@example.com",
        )


def workspace_client(
    *,
    deployment_mode: str = "self_host",
    runtime: FakeMailboxRuntime | None = None,
    outbound_email: InMemoryOutboundEmailClient | None = None,
    oauth_clients: dict | None = None,
) -> TestClient:
    return TestClient(
        create_app(
            accounts=AccountService(),
            users=UserService(),
            mailbox_runtime=runtime or FakeMailboxRuntime(),
            outbound_email=outbound_email,
            oauth_clients=oauth_clients,
            settings=Settings(deployment_mode=deployment_mode),
        )
    )


def register(client: TestClient, email: str = "user@example.com") -> str:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "secret123", "name": email},
    )
    assert response.status_code == 201
    return response.json()["session_token"]


def mailbox_payload(email: str = "user@example.com") -> dict:
    return {
        "name": "Work",
        "email": email,
        "provider": "gmail",
        "password": "app-password",
    }


def test_self_host_mode_keeps_single_step_app_password_creation():
    runtime = FakeMailboxRuntime()
    client = workspace_client(runtime=runtime)
    token = register(client)

    response = client.post(
        "/mailboxes",
        headers={"Authorization": f"Bearer {token}"},
        json=mailbox_payload(),
    )

    assert response.status_code == 201
    assert response.json()["mailbox"]["auth_type"] == "app_password"
    assert runtime.validated[0]["email"] == "user@example.com"


def test_hosted_mode_blocks_single_step_app_password_creation():
    runtime = FakeMailboxRuntime()
    client = workspace_client(deployment_mode="hosted", runtime=runtime)
    token = register(client)

    response = client.post(
        "/mailboxes",
        headers={"Authorization": f"Bearer {token}"},
        json=mailbox_payload(),
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "unsupported_auth_flow"
    assert runtime.validated == []


def test_hosted_mode_verifies_app_password_before_creating_mailbox():
    outbound_email = InMemoryOutboundEmailClient()
    client = workspace_client(deployment_mode="hosted", outbound_email=outbound_email)
    token = register(client)

    start = client.post(
        "/mailboxes/verify-start",
        headers={"Authorization": f"Bearer {token}"},
        json={**mailbox_payload(), "accepted_owner_terms": True},
    )

    assert start.status_code == 201
    verification_id = start.json()["verification_id"]
    assert verification_id
    assert len(outbound_email.sent) == 1
    code = re.search(r"\b([0-9]{6})\b", outbound_email.sent[0].text).group(1)

    complete = client.post(
        "/mailboxes/verify-complete",
        headers={"Authorization": f"Bearer {token}"},
        json={"verification_id": verification_id, "code": code},
    )

    assert complete.status_code == 201
    assert complete.json()["mailbox"]["email"] == "user@example.com"
    assert complete.json()["mailbox"]["auth_type"] == "app_password"


def test_hosted_mode_rejects_invalid_verification_code():
    outbound_email = InMemoryOutboundEmailClient()
    client = workspace_client(deployment_mode="hosted", outbound_email=outbound_email)
    token = register(client)
    start = client.post(
        "/mailboxes/verify-start",
        headers={"Authorization": f"Bearer {token}"},
        json={**mailbox_payload(), "accepted_owner_terms": True},
    )

    response = client.post(
        "/mailboxes/verify-complete",
        headers={"Authorization": f"Bearer {token}"},
        json={"verification_id": start.json()["verification_id"], "code": "000000"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "verification_failed"


def test_hosted_mode_enforces_owner_terms_and_first_mailbox_email_match():
    client = workspace_client(deployment_mode="hosted")
    token = register(client)

    terms = client.post(
        "/mailboxes/verify-start",
        headers={"Authorization": f"Bearer {token}"},
        json={**mailbox_payload(), "accepted_owner_terms": False},
    )
    mismatch = client.post(
        "/mailboxes/verify-start",
        headers={"Authorization": f"Bearer {token}"},
        json={**mailbox_payload("other@example.com"), "accepted_owner_terms": True},
    )

    assert terms.status_code == 400
    assert terms.json()["error"]["code"] == "owner_terms_required"
    assert mismatch.status_code == 400
    assert mismatch.json()["error"]["code"] == "mailbox_email_mismatch"


def test_oauth_start_requires_user_session():
    client = workspace_client()

    response = client.post("/mailboxes/oauth/gmail/start", json={"name": "Gmail"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "auth_missing"


def test_oauth_start_rejects_provider_without_oauth_support():
    client = workspace_client()
    token = register(client)

    response = client.post(
        "/mailboxes/oauth/icloud/start",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "iCloud"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "oauth_not_supported"


def test_oauth_start_returns_google_authorization_url():
    oauth_client = FakeOAuthClient()
    client = workspace_client(oauth_clients={"gmail": oauth_client})
    token = register(client)

    response = client.post(
        "/mailboxes/oauth/gmail/start",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Gmail"},
    )

    assert response.status_code == 200
    assert response.json()["authorization_url"].startswith("https://accounts.example.test/auth?")
    assert oauth_client.authorization_calls[0]["scopes"] == ("openid", "email", "https://mail.google.com/")


def test_oauth_callback_rejects_invalid_state_with_spa_redirect():
    client = workspace_client(oauth_clients={"gmail": FakeOAuthClient()})

    response = client.get(
        "/mailboxes/oauth/gmail/callback",
        params={"code": "auth-code", "state": "invalid"},
        follow_redirects=False,
    )

    assert response.status_code == 307
    assert response.headers["location"] == "/app?mailbox_oauth=error&code=oauth_state_invalid"


def test_oauth_callback_creates_mailbox_with_provider_email_and_redirects():
    oauth_client = FakeOAuthClient()
    client = workspace_client(oauth_clients={"gmail": oauth_client})
    token = register(client, email="typed@example.com")
    start = client.post(
        "/mailboxes/oauth/gmail/start",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Gmail"},
    )
    state = oauth_client.authorization_calls[0]["state"]

    response = client.get(
        "/mailboxes/oauth/gmail/callback",
        params={"code": "auth-code", "state": state},
        follow_redirects=False,
    )
    mailboxes = client.get("/mailboxes", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 307
    assert response.headers["location"] == "/app?mailbox_oauth=success&mailbox_id=1"
    assert mailboxes.json()["mailboxes"][0]["email"] == "provider@example.com"
    assert mailboxes.json()["mailboxes"][0]["auth_type"] == "oauth2"


@pytest.mark.anyio
async def test_lazy_account_service_forwards_oauth_creation(monkeypatch):
    class FakeRepositoryAccountService:
        async def create_with_oauth(self, **kwargs):
            return kwargs

    monkeypatch.setattr(
        "postara.api.create_repository_account_service",
        lambda _settings: FakeRepositoryAccountService(),
    )
    service = _LazyAccountService(Settings())

    result = await service.create_with_oauth(
        user_id=1,
        name="Gmail",
        email="provider@example.com",
        provider="gmail",
        refresh_token="refresh-token",
        access_token="access-token",
        expires_at=None,
        scopes=("openid", "email"),
        subject="google-subject",
        oauth_email="provider@example.com",
        audit_context={"request_id": "req_test"},
    )

    assert result["provider"] == "gmail"
    assert result["oauth_email"] == "provider@example.com"
