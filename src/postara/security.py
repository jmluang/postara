from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError


TOKEN_RE = re.compile(r"^pst_(?P<kind>live|test)_(?P<prefix>[0-9A-Za-z]{8})\.(?P<secret>[0-9A-Za-z]{32})$")
SESSION_RE = re.compile(r"^pst_session_(?P<prefix>[0-9A-Za-z]{8})\.(?P<secret>[0-9A-Za-z]{48})$")
BASE62_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class TokenFormatError(ValueError):
    pass


@dataclass(frozen=True)
class ApiKeyParts:
    kind: str
    prefix: str
    secret: str


def _base62(length: int) -> str:
    return "".join(secrets.choice(BASE62_ALPHABET) for _ in range(length))


def generate_api_key(kind: str = "live") -> str:
    if kind not in {"live", "test"}:
        raise ValueError(f"Unsupported token kind: {kind}")

    return f"pst_{kind}_{_base62(8)}.{_base62(32)}"


def hash_password(raw_password: str) -> str:
    return PasswordHasher().hash(raw_password)


def verify_password(raw_password: str, password_hash: str) -> bool:
    try:
        return PasswordHasher().verify(password_hash, raw_password)
    except VerificationError:
        return False


def generate_session_token() -> str:
    return f"pst_session_{_base62(8)}.{_base62(48)}"


def parse_session_token(raw_token: str) -> tuple[str, str]:
    match = SESSION_RE.fullmatch(raw_token)
    if not match:
        raise TokenFormatError("Invalid Postara session token format.")
    return match.group("prefix"), match.group("secret")


def hash_session_token(raw_token: str) -> tuple[str, bytes]:
    prefix, _secret = parse_session_token(raw_token)
    digest = hashlib.sha256(raw_token.encode("utf-8")).digest()
    return prefix, digest


def verify_session_token_hash(raw_token: str, expected_hash: bytes) -> bool:
    try:
        _prefix, actual = hash_session_token(raw_token)
    except TokenFormatError:
        return False
    return hmac.compare_digest(actual, expected_hash)


def parse_api_key(raw_key: str) -> ApiKeyParts:
    match = TOKEN_RE.fullmatch(raw_key)
    if not match:
        raise TokenFormatError("Invalid Postara token format.")

    return ApiKeyParts(
        kind=match.group("kind"),
        prefix=match.group("prefix"),
        secret=match.group("secret"),
    )


def _decode_key_material(key_material: bytes | str) -> bytes:
    raw = key_material.encode("ascii") if isinstance(key_material, str) else key_material
    try:
        decoded = base64.urlsafe_b64decode(raw)
    except Exception:
        decoded = raw

    if len(decoded) < 32:
        raise ValueError("TOKEN_HASH_KEY must contain at least 32 bytes of entropy.")

    return decoded


def hash_api_key(raw_key: str, token_hash_key: bytes | str) -> bytes:
    parse_api_key(raw_key)
    return hmac.new(
        key=_decode_key_material(token_hash_key),
        msg=raw_key.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()


def verify_api_key_hash(raw_key: str, expected_hash: bytes, token_hash_key: bytes | str) -> bool:
    try:
        actual = hash_api_key(raw_key, token_hash_key)
    except (TokenFormatError, ValueError):
        return False

    return hmac.compare_digest(actual, expected_hash)


def generate_verification_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(6))


def hash_verification_code(raw_code: str, key: bytes | str, *, version: int) -> tuple[int, bytes]:
    if not re.fullmatch(r"[0-9]{6}", raw_code):
        raise TokenFormatError("Invalid verification code format.")
    digest = hmac.new(
        key=_decode_key_material(key),
        msg=raw_code.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    return version, digest


def verify_verification_code_hash(raw_code: str, expected_hash: bytes, key: bytes | str) -> bool:
    try:
        _version, actual = hash_verification_code(raw_code, key, version=1)
    except (TokenFormatError, ValueError):
        return False
    return hmac.compare_digest(actual, expected_hash)


def redact_token_for_display(raw_key: str) -> str:
    parts = parse_api_key(raw_key)
    return f"pst_{parts.kind}_{parts.prefix}..."
