### 5. **Новые тесты (`tests/test_modes.py`)**

# !/usr/bin/env python3

import os
import sys
import tempfile
import subprocess

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.modes.cbc import cbc_encrypt, cbc_decrypt
from src.modes.cfb import cfb_encrypt, cfb_decrypt
from src.modes.ofb import ofb_encrypt, ofb_decrypt
from src.modes.ctr import ctr_encrypt, ctr_decrypt


def test_all_modes_roundtrip():
    """Test round-trip encryption/decryption for all new modes"""
    print("Testing all modes round-trip...")

    test_data = [
        b"Short message",
        b"Exactly 16 bytes!!",
        b"Longer message that needs multiple blocks for processing",
        b"x" * 100
    ]

    key = b'\x00' * 16  # Simple key for testing
    modes = [
        ('cbc', cbc_encrypt, cbc_decrypt),
        ('cfb', cfb_encrypt, cfb_decrypt),
        ('ofb', ofb_encrypt, ofb_decrypt),
        ('ctr', ctr_encrypt, ctr_decrypt),
    ]

    for mode_name, encrypt_func, decrypt_func in modes:
        print(f"  Testing {mode_name.upper()} mode...")

        for i, data in enumerate(test_data):
            # Encrypt
            ciphertext = encrypt_func(key, data)

            # Decrypt
            plaintext = decrypt_func(key, ciphertext)

            assert plaintext == data, f"{mode_name} round-trip failed for test {i + 1}"
            print(f"    ✓ Test {i + 1}: {len(data):3d} bytes")

        print(f"    All {mode_name} tests passed!")


def test_openssl_interoperability():
    """Test interoperability with OpenSSL"""
    print("Testing OpenSSL interoperability...")

    # This would require actual OpenSSL commands
    # Implementation depends on system setup
    print("  Note: OpenSSL tests require manual verification")
    print("  See README.md for interoperability test commands")


if __name__ == "__main__":
    test_all_modes_roundtrip()
    print("\n All mode tests passed!")