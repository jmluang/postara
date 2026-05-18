import pytest

from postara.providers.registry import ProviderRegistry


def test_default_registry_only_exposes_implemented_providers():
    registry = ProviderRegistry.default()

    assert registry.get("gmail").provider == "gmail"
    with pytest.raises(ValueError, match="Unsupported provider"):
        registry.get("unknown")


def test_default_registry_exposes_provider_capabilities():
    registry = ProviderRegistry.default()

    gmail = registry.capabilities_for("gmail")
    icloud = registry.capabilities_for("icloud")
    hotmail = registry.capabilities_for("hotmail")

    assert gmail.supports_auth_type("app_password")
    assert gmail.supports_auth_type("oauth2")
    assert gmail.runtime == "imap_xoauth2"
    assert gmail.default_imap_host == "imap.gmail.com"
    assert gmail.default_imap_port == 993

    assert icloud.supports_auth_type("app_password")
    assert not icloud.supports_auth_type("oauth2")
    assert icloud.runtime == "imap_password"
    assert icloud.default_imap_host == "imap.mail.me.com"
    assert icloud.default_imap_port == 993

    assert hotmail.supports_auth_type("oauth2")
    assert hotmail.runtime == "graph_api"


def test_default_registry_rejects_unknown_provider_capabilities():
    registry = ProviderRegistry.default()

    with pytest.raises(ValueError, match="Unsupported provider"):
        registry.capabilities_for("unknown")
