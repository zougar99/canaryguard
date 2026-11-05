from canaryguard import cryptostore


def test_roundtrip():
    ciphertext = cryptostore.encrypt("hunter2")
    assert ciphertext != "hunter2"
    assert cryptostore.is_encrypted(ciphertext)
    assert cryptostore.decrypt(ciphertext) == "hunter2"


def test_none_and_plaintext():
    assert cryptostore.encrypt(None) is None
    assert cryptostore.decrypt("legacy-plain") == "legacy-plain"
    assert not cryptostore.is_encrypted("legacy-plain")


def test_double_encrypt_is_stable():
    once = cryptostore.encrypt("abc")
    assert cryptostore.encrypt(once) == once


def test_generate_key_shape():
    key = cryptostore.generate_key()
    from cryptography.fernet import Fernet

    Fernet(key.encode("ascii"))  # must not raise
