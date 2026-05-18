import base64

from postara.security import generate_verification_code, hash_verification_code, verify_verification_code_hash


CODE_KEY = base64.urlsafe_b64encode(b"x" * 32)


def test_verification_code_is_six_digits_and_hash_verifies():
    code = generate_verification_code()
    version, digest = hash_verification_code(code, CODE_KEY, version=1)

    assert code.isdigit()
    assert len(code) == 6
    assert version == 1
    assert verify_verification_code_hash(code, digest, CODE_KEY)
    assert not verify_verification_code_hash("000000", digest, CODE_KEY)
