from src.kdf.hkdf import hkdf_extract, hkdf_expand


def test_hkdf_rfc5869():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42

    prk = hkdf_extract(salt, ikm)
    okm = hkdf_expand(prk, info, length)

    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    assert okm == expected
    print("HKDF RFC test passed!")


if __name__ == "__main__":
    test_hkdf_rfc5869()
