from __future__ import annotations

from dataclasses import dataclass

from courier.providers.gmail import GmailAdapter


@dataclass(frozen=True)
class ProviderDefaults:
    imap_host: str
    imap_port: int


class ProviderRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, object] = {}
        self._defaults: dict[str, ProviderDefaults] = {}

    def register(self, name: str, adapter: object, defaults: ProviderDefaults) -> None:
        self._adapters[name] = adapter
        self._defaults[name] = defaults

    def get(self, name: str):
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise ValueError(f"Unsupported provider: {name}") from exc

    def defaults_for(self, name: str) -> ProviderDefaults:
        if name not in self._defaults:
            raise ValueError(f"Unsupported provider: {name}")
        return self._defaults[name]

    @classmethod
    def default(cls) -> "ProviderRegistry":
        registry = cls()
        registry.register("gmail", GmailAdapter(), ProviderDefaults("imap.gmail.com", 993))
        return registry
