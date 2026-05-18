from __future__ import annotations

from dataclasses import dataclass

from postara.providers.gmail import GmailAdapter
from postara.providers.icloud import IcloudAdapter
from postara.providers.outlook import OutlookAdapter


@dataclass(frozen=True)
class OAuthProviderConfig:
    authorization_url: str
    token_url: str
    userinfo_url: str | None
    default_scopes: tuple[str, ...]
    callback_path: str


@dataclass(frozen=True)
class ProviderCapabilities:
    name: str
    display_name: str
    supported_auth_types: tuple[str, ...]
    default_imap_host: str | None
    default_imap_port: int | None
    oauth: OAuthProviderConfig | None
    runtime: str

    def supports_auth_type(self, auth_type: str) -> bool:
        return auth_type in self.supported_auth_types


@dataclass(frozen=True)
class ProviderDefaults:
    imap_host: str
    imap_port: int


class ProviderRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, object] = {}
        self._capabilities: dict[str, ProviderCapabilities] = {}

    def register(self, name: str, adapter: object, capabilities: ProviderCapabilities) -> None:
        self._adapters[name] = adapter
        self._capabilities[name] = capabilities

    def get(self, name: str):
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise ValueError(f"Unsupported provider: {name}") from exc

    def capabilities_for(self, name: str) -> ProviderCapabilities:
        try:
            return self._capabilities[name]
        except KeyError as exc:
            raise ValueError(f"Unsupported provider: {name}") from exc

    def defaults_for(self, name: str) -> ProviderDefaults:
        capabilities = self.capabilities_for(name)
        if capabilities.default_imap_host is None or capabilities.default_imap_port is None:
            raise ValueError(f"Provider has no IMAP defaults: {name}")
        return ProviderDefaults(capabilities.default_imap_host, capabilities.default_imap_port)

    @classmethod
    def default(cls) -> "ProviderRegistry":
        registry = cls()
        gmail_oauth = OAuthProviderConfig(
            authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
            default_scopes=("openid", "email", "https://mail.google.com/"),
            callback_path="/mailboxes/oauth/gmail/callback",
        )
        microsoft_oauth = OAuthProviderConfig(
            authorization_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
            userinfo_url="https://graph.microsoft.com/v1.0/me",
            default_scopes=("openid", "email", "offline_access", "https://graph.microsoft.com/Mail.Read"),
            callback_path="/mailboxes/oauth/outlook/callback",
        )
        registry.register(
            "gmail",
            GmailAdapter(),
            ProviderCapabilities(
                name="gmail",
                display_name="Gmail",
                supported_auth_types=("app_password", "oauth2"),
                default_imap_host="imap.gmail.com",
                default_imap_port=993,
                oauth=gmail_oauth,
                runtime="imap_xoauth2",
            ),
        )
        registry.register(
            "icloud",
            IcloudAdapter(),
            ProviderCapabilities(
                name="icloud",
                display_name="iCloud Mail",
                supported_auth_types=("app_password",),
                default_imap_host="imap.mail.me.com",
                default_imap_port=993,
                oauth=None,
                runtime="imap_password",
            ),
        )
        registry.register(
            "outlook",
            OutlookAdapter(),
            ProviderCapabilities(
                name="outlook",
                display_name="Outlook",
                supported_auth_types=("oauth2",),
                default_imap_host=None,
                default_imap_port=None,
                oauth=microsoft_oauth,
                runtime="graph_api",
            ),
        )
        registry.register(
            "hotmail",
            OutlookAdapter(),
            ProviderCapabilities(
                name="hotmail",
                display_name="Hotmail",
                supported_auth_types=("oauth2",),
                default_imap_host=None,
                default_imap_port=None,
                oauth=microsoft_oauth,
                runtime="graph_api",
            ),
        )
        return registry
