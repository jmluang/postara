import base64
from datetime import datetime, timedelta, timezone

import pytest

from postara.oauth import OAuthStateCodec, OAuthStateError


STATE_KEY = base64.urlsafe_b64encode(b"x" * 32)


def test_oauth_state_roundtrips_with_key_version():
    codec = OAuthStateCodec(keys={1: STATE_KEY}, active_version=1)

    raw = codec.sign(
        user_id=12,
        provider="gmail",
        name="Work",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    state = codec.verify(raw, provider="gmail")

    assert state.user_id == 12
    assert state.provider == "gmail"
    assert state.name == "Work"
    assert state.version == 1


def test_oauth_state_rejects_wrong_provider():
    codec = OAuthStateCodec(keys={1: STATE_KEY}, active_version=1)
    raw = codec.sign(
        user_id=12,
        provider="gmail",
        name="Work",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )

    with pytest.raises(OAuthStateError):
        codec.verify(raw, provider="outlook")


def test_oauth_state_rejects_expired_state():
    codec = OAuthStateCodec(keys={1: STATE_KEY}, active_version=1)
    raw = codec.sign(
        user_id=12,
        provider="gmail",
        name="Work",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    with pytest.raises(OAuthStateError):
        codec.verify(raw, provider="gmail")
