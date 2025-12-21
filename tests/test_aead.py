#!/usr/bin/env python3
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.aead.etm import TAG_LEN
from src.modes.cbc import cbc_encrypt, cbc_decrypt
from src.modes.ctr import ctr_encrypt, ctr_decrypt
from src.aead.etm import etm_encrypt, etm_decrypt


def tamper(data: bytes, index: int) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


def test_aead_roundtrip_and_tamper(encrypt_func, decrypt_func, name: str):
    print(f"Testing AEAD EtM for {name}...")

    master_key = os.urandom(48)
    plaintext = b"Hello AEAD! " * 20

    out = etm_encrypt(encrypt_func, master_key, plaintext)
    recovered = etm_decrypt(decrypt_func, master_key, out)
    assert recovered == plaintext, "Roundtrip failed"

    # Tamper ciphertext (somewhere before tag)
    out_t = tamper(out, 10)
    try:
        etm_decrypt(decrypt_func, master_key, out_t)
        assert False, "Tamper (ciphertext) should fail"
    except ValueError:
        pass

    # Tamper tag (last byte)
    out_t = tamper(out, len(out) - 1)
    try:
        etm_decrypt(decrypt_func, master_key, out_t)
        assert False, "Tamper (tag) should fail"
    except ValueError:
        pass

    # Tamper IV/nonce (first byte)
    out_t = tamper(out, 0)
    try:
        etm_decrypt(decrypt_func, master_key, out_t)
        assert False, "Tamper (IV/nonce) should fail"
    except ValueError:
        pass

    print("  ✓ OK")


def main():
    test_aead_roundtrip_and_tamper(cbc_encrypt, cbc_decrypt, "CBC")
    test_aead_roundtrip_and_tamper(ctr_encrypt, ctr_decrypt, "CTR")
    print("\n AEAD tests passed!")


if __name__ == "__main__":
    main()
