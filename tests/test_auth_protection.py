import pytest

from postara.auth_protection import (
    AuthAttemptLimiter,
    AuthChallengeRequired,
    AuthProtectionConfig,
    AuthRateLimited,
    InMemoryAuthAttemptStore,
    normalize_email_key,
    normalize_ip_key,
    resolve_client_ip,
)


def test_bucket_keys_are_normalized():
    assert normalize_email_key("  User@Example.COM ") == "user@example.com"
    assert normalize_ip_key("203.0.113.10") == "203.0.113.10"
    assert normalize_ip_key("2001:db8:abcd:12:1111:2222:3333:4444") == "2001:db8:abcd:12::/64"
    assert normalize_ip_key("2001:db8:abcd:12:ffff::1") == "2001:db8:abcd:12::/64"


def test_forwarded_headers_are_ignored_without_trusted_proxy():
    assert (
        resolve_client_ip(
            peer_ip="198.51.100.3",
            headers={"x-forwarded-for": "1.2.3.4", "cf-connecting-ip": "5.6.7.8"},
            trusted_proxy_cidrs=[],
        )
        == "198.51.100.3"
    )


def test_forwarded_headers_are_used_for_trusted_proxy():
    assert (
        resolve_client_ip(
            peer_ip="10.0.0.9",
            headers={"x-forwarded-for": "1.2.3.4, 10.0.0.9"},
            trusted_proxy_cidrs=["10.0.0.0/8"],
        )
        == "1.2.3.4"
    )
    assert (
        resolve_client_ip(
            peer_ip="10.0.0.9",
            headers={"cf-connecting-ip": "5.6.7.8", "x-forwarded-for": "1.2.3.4"},
            trusted_proxy_cidrs=["10.0.0.0/8"],
        )
        == "5.6.7.8"
    )


@pytest.mark.anyio
async def test_limiter_uses_email_and_ipv6_normalization():
    limiter = AuthAttemptLimiter(
        InMemoryAuthAttemptStore(),
        AuthProtectionConfig(failure_limit=1, window_seconds=300, lock_seconds=300),
    )

    await limiter.record_failure(
        action="login",
        email="User@Example.com",
        client_ip="2001:db8:abcd:12::1",
    )

    with pytest.raises(AuthRateLimited):
        await limiter.record_failure(
            action="login",
            email=" user@example.COM ",
            client_ip="2001:db8:abcd:12::2",
        )


@pytest.mark.anyio
async def test_limiter_requires_challenge_before_lockout():
    limiter = AuthAttemptLimiter(
        InMemoryAuthAttemptStore(),
        AuthProtectionConfig(
            challenge_enabled=True,
            challenge_threshold=1,
            failure_limit=5,
            window_seconds=300,
            lock_seconds=300,
        ),
    )

    await limiter.record_failure(action="login", email="user@example.com", client_ip="203.0.113.10")

    with pytest.raises(AuthChallengeRequired):
        await limiter.check(action="login", email="user@example.com", client_ip="203.0.113.10")


@pytest.mark.anyio
async def test_limiter_can_be_bypassed():
    limiter = AuthAttemptLimiter(
        InMemoryAuthAttemptStore(),
        AuthProtectionConfig(enabled=False, failure_limit=0),
    )

    await limiter.check(action="login", email="user@example.com", client_ip="203.0.113.10")
    await limiter.record_failure(action="login", email="user@example.com", client_ip="203.0.113.10")
