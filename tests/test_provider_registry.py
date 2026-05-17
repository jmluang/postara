import pytest

from courier.providers.registry import ProviderRegistry


def test_default_registry_only_exposes_implemented_providers():
    registry = ProviderRegistry.default()

    assert registry.get("gmail").provider == "gmail"
    with pytest.raises(ValueError, match="Unsupported provider"):
        registry.get("icloud")
