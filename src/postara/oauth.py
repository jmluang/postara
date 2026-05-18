from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from urllib.parse import urlencode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from postara.providers.registry import OAuthProviderConfig
from postara.security import _decode_key_material


class OAuthStateError(ValueError):
    pass


class OAuthExchangeError(RuntimeError):
    def __init__(self, message: str, *, provider_error: str | None = None, response_text: str | None = None) -> None:
        super().__init__(message)
        self.provider_error = provider_error
        self.response_text = response_text


@dataclass(frozen=True)
class OAuthState:
    version: int
    nonce: str
    user_id: int
    provider: str
    name: str
    expires_at: datetime


@dataclass(frozen=True)
class OAuthTokenResult:
    refresh_token: str
    access_token: str | None
    expires_at: datetime | None
    scopes: tuple[str, ...]
    subject: str | None
    email: str


@dataclass(frozen=True)
class OAuthAccessTokenResult:
    access_token: str
    expires_at: datetime | None
    scopes: tuple[str, ...]


class OAuthStateCodec:
    def __init__(self, *, keys: dict[int, bytes | str], active_version: int) -> None:
        if active_version not in keys:
            raise ValueError("Active OAuth state key version is not available.")
        self._keys = keys
        self._active_version = active_version

    def sign(self, *, user_id: int, provider: str, name: str, expires_at: datetime) -> str:
        payload = {
            "version": self._active_version,
            "nonce": secrets.token_urlsafe(18),
            "user_id": user_id,
            "provider": provider,
            "name": name,
            "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
        }
        payload_bytes = _json_bytes(payload)
        signature = _sign(payload_bytes, self._keys[self._active_version])
        return _b64(payload_bytes) + "." + _b64(signature)

    def verify(self, raw_state: str, *, provider: str) -> OAuthState:
        try:
            payload_part, signature_part = raw_state.split(".", 1)
            payload_bytes = _unb64(payload_part)
            payload = json.loads(payload_bytes.decode("utf-8"))
            version = int(payload["version"])
            key = self._keys[version]
            expected = _sign(payload_bytes, key)
            actual = _unb64(signature_part)
        except Exception as exc:
            raise OAuthStateError("Invalid OAuth state.") from exc

        if not hmac.compare_digest(actual, expected):
            raise OAuthStateError("Invalid OAuth state signature.")
        if payload.get("provider") != provider:
            raise OAuthStateError("OAuth state provider mismatch.")

        expires_at = datetime.fromisoformat(payload["expires_at"])
        if expires_at <= datetime.now(timezone.utc):
            raise OAuthStateError("OAuth state expired.")

        return OAuthState(
            version=version,
            nonce=str(payload["nonce"]),
            user_id=int(payload["user_id"]),
            provider=str(payload["provider"]),
            name=str(payload["name"]),
            expires_at=expires_at,
        )


class GoogleOAuthClient:
    def __init__(
        self,
        *,
        config: OAuthProviderConfig,
        client_id: str,
        client_secret: str,
    ) -> None:
        self._config = config
        self._client_id = client_id
        self._client_secret = client_secret

    def authorization_url(self, *, state: str, redirect_uri: str, scopes: tuple[str, ...]) -> str:
        params = {
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
        }
        return f"{self._config.authorization_url}?{urlencode(params)}"

    async def exchange_code(self, *, code: str, redirect_uri: str) -> OAuthTokenResult:
        async with httpx.AsyncClient(timeout=20) as client:
            token_response = await client.post(
                self._config.token_url,
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
            )
            if token_response.is_error:
                _raise_oauth_exchange_error("OAuth token exchange failed.", token_response)
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")
            if not access_token or not refresh_token:
                raise OAuthExchangeError(
                    "OAuth token response did not include required tokens.",
                    provider_error="missing_token",
                    response_text=json.dumps(_redacted_token_response(token_data), sort_keys=True),
                )

            userinfo = {}
            if self._config.userinfo_url:
                user_response = await client.get(
                    self._config.userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if user_response.is_error:
                    _raise_oauth_exchange_error("OAuth userinfo request failed.", user_response)
                userinfo = user_response.json()

        email = userinfo.get("email")
        if not email:
            raise OAuthExchangeError("OAuth userinfo response did not include email.", provider_error="missing_email")
        expires_in = token_data.get("expires_in")
        expires_at = None
        if isinstance(expires_in, int):
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        scopes = tuple(str(token_data.get("scope") or "").split()) or self._config.default_scopes
        return OAuthTokenResult(
            refresh_token=refresh_token,
            access_token=access_token,
            expires_at=expires_at,
            scopes=scopes,
            subject=userinfo.get("sub"),
            email=email,
        )

    async def refresh_access_token(
        self,
        *,
        refresh_token: str,
        scopes: tuple[str, ...],
    ) -> OAuthAccessTokenResult:
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                token_response = await client.post(
                    self._config.token_url,
                    data={
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "refresh_token": refresh_token,
                        "grant_type": "refresh_token",
                    },
                )
            except httpx.RequestError as exc:
                raise OAuthExchangeError("OAuth token refresh request failed.") from exc
            if token_response.is_error:
                _raise_oauth_exchange_error("OAuth token refresh failed.", token_response)
            token_data = token_response.json()

        access_token = token_data.get("access_token")
        if not access_token:
            raise OAuthExchangeError(
                "OAuth token refresh response did not include an access token.",
                provider_error="missing_token",
                response_text=json.dumps(_redacted_token_response(token_data), sort_keys=True),
            )
        expires_in = token_data.get("expires_in")
        expires_at = None
        if isinstance(expires_in, int):
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        refreshed_scopes = tuple(str(token_data.get("scope") or "").split()) or scopes
        return OAuthAccessTokenResult(
            access_token=access_token,
            expires_at=expires_at,
            scopes=refreshed_scopes,
        )


def _raise_oauth_exchange_error(message: str, response: httpx.Response) -> None:
    provider_error = None
    try:
        provider_error = response.json().get("error")
    except Exception:
        provider_error = None
    raise OAuthExchangeError(
        message,
        provider_error=provider_error,
        response_text=response.text[:1000],
    )


def _redacted_token_response(payload: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(payload)
    for key in ("access_token", "refresh_token", "id_token"):
        if key in redacted:
            redacted[key] = "[REDACTED]"
    return redacted


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sign(payload: bytes, key: bytes | str) -> bytes:
    return hmac.new(_decode_key_material(key), payload, hashlib.sha256).digest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))
