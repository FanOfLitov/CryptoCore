from src.kdf.pbkdf2 import pbkdf2


def test_pbkdf2_rfc6070():
    password = b"password"
    salt = b"salt"
    iterations = 1
    dklen = 32

    dk = pbkdf2(password, salt, iterations, dklen)
    expected = bytes.fromhex(
        "120fb6cffcf8b32c43e7225256c4f837"
        "a86548c92ccc35480805987cb70be17b"
    )

    assert dk == expected
    print("PBKDF2 RFC test passed!")


if __name__ == "__main__":
    test_pbkdf2_rfc6070()
