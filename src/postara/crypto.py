from __future__ import annotations

from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken


class CredentialCipherError(RuntimeError):
    pass


@dataclass(frozen=True)
class EncryptedCredential:
    ciphertext: bytes
    key_version: int


class CredentialCipher:
    def __init__(self, keys: dict[int, bytes], active_version: int) -> None:
        if active_version not in keys:
            raise ValueError("Active key version is not available.")
        self._keys = keys
        self._active_version = active_version

    @staticmethod
    def generate_key() -> bytes:
        return Fernet.generate_key()

    def encrypt(self, plaintext: str) -> EncryptedCredential:
        ciphertext = Fernet(self._keys[self._active_version]).encrypt(plaintext.encode("utf-8"))
        return EncryptedCredential(ciphertext=ciphertext, key_version=self._active_version)

    def decrypt(self, ciphertext: bytes, key_version: int) -> str:
        key = self._keys.get(key_version)
        if key is None:
            raise CredentialCipherError(f"FERNET_KEY version {key_version} is unavailable.")

        try:
            return Fernet(key).decrypt(ciphertext).decode("utf-8")
        except InvalidToken as exc:
            raise CredentialCipherError("Encrypted credential could not be decrypted.") from exc
