import os
import stat

from postara.config import Settings
from postara.crypto import CredentialCipher
from postara.database import load_runtime_secrets
from postara.secrets import SecretFileError, ensure_secret_file


def test_secret_file_must_not_be_writable(tmp_path):
    secret_file = tmp_path / "token_hash.key"
    secret_file.write_text("secret", encoding="utf-8")
    secret_file.chmod(0o644)

    try:
        ensure_secret_file(secret_file)
    except SecretFileError as exc:
        assert "writable" in str(exc)
        return

    raise AssertionError("writable secret files must be rejected")


def test_secret_file_accepts_0400(tmp_path):
    secret_file = tmp_path / "token_hash.key"
    secret_file.write_text("secret", encoding="utf-8")
    secret_file.chmod(stat.S_IRUSR)

    assert ensure_secret_file(secret_file) == b"secret"


def test_secret_file_accepts_docker_read_only_mode(tmp_path):
    secret_file = tmp_path / "token_hash.key"
    secret_file.write_text("secret", encoding="utf-8")
    secret_file.chmod(0o444)

    assert ensure_secret_file(secret_file) == b"secret"


def test_credential_cipher_round_trips_password_without_plaintext_leak():
    key = CredentialCipher.generate_key()
    cipher = CredentialCipher({1: key}, active_version=1)

    encrypted = cipher.encrypt("app-password")

    assert encrypted.key_version == 1
    assert b"app-password" not in encrypted.ciphertext
    assert cipher.decrypt(encrypted.ciphertext, encrypted.key_version) == "app-password"


def write_secret(path, value: bytes | str):
    data = value.encode("utf-8") if isinstance(value, str) else value
    path.write_bytes(data)
    path.chmod(stat.S_IRUSR)


def test_runtime_secrets_load_latest_versions(tmp_path):
    write_secret(tmp_path / "fernet.key", CredentialCipher.generate_key())
    write_secret(tmp_path / "fernet.key.v2", CredentialCipher.generate_key())
    write_secret(tmp_path / "token_hash.key", "a" * 44)
    write_secret(tmp_path / "token_hash.key.v2", "b" * 44)

    runtime = load_runtime_secrets(Settings(secrets_dir=str(tmp_path)))
    encrypted = runtime.cipher.encrypt("app-password")

    assert encrypted.key_version == 2
    assert runtime.active_token_hash_version == 2
    assert sorted(runtime.token_hash_keys) == [1, 2]
