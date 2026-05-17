import base64

from postara.security import (
    ApiKeyParts,
    TokenFormatError,
    generate_session_token,
    hash_api_key,
    hash_password,
    hash_session_token,
    parse_api_key,
    redact_token_for_display,
    verify_api_key_hash,
    verify_password,
    verify_session_token_hash,
)
from helpers import sample_api_key


def test_api_key_parser_accepts_real_shape_and_extracts_parts():
    raw = sample_api_key()

    parts = parse_api_key(raw)

    assert parts == ApiKeyParts(
        kind="live",
        prefix="a8f3k29x",
        secret="7B2pQ9zRm4nKvY8wL5cE3hT1jX6dF0sN",
    )


def test_api_key_parser_rejects_placeholder_examples():
    try:
        parse_api_key("pst_live_<prefix>.<secret>")
    except TokenFormatError:
        return

    raise AssertionError("placeholder token must not parse as a real token")


def test_api_key_hash_uses_keyed_hmac_and_constant_verify():
    raw = sample_api_key()
    key_v1 = base64.urlsafe_b64encode(b"1" * 32)
    key_v2 = base64.urlsafe_b64encode(b"2" * 32)

    digest = hash_api_key(raw, key_v1)

    assert verify_api_key_hash(raw, digest, key_v1)
    assert not verify_api_key_hash(raw, digest, key_v2)
    assert not verify_api_key_hash(raw.replace("N", "M"), digest, key_v1)


def test_redact_token_for_display_keeps_only_safe_prefix():
    assert redact_token_for_display(sample_api_key()) == "pst_live_a8f3k29x..."


def test_password_hash_verifies_without_storing_plaintext():
    password_hash = hash_password("correct horse battery staple")

    assert "correct horse" not in password_hash
    assert verify_password("correct horse battery staple", password_hash)
    assert not verify_password("wrong password", password_hash)


def test_session_token_hash_is_prefix_addressable_and_constant_verify():
    token = generate_session_token()
    prefix, digest = hash_session_token(token)

    assert token.startswith("pst_session_")
    assert len(prefix) == 8
    assert verify_session_token_hash(token, digest)
    assert not verify_session_token_hash(token + "x", digest)
