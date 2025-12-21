#!/usr/bin/env python3

import os
import sys
import tempfile

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from file_io import read_file_binary, write_file_binary
from src.modes.ecb import ecb_encrypt, ecb_decrypt
from src.file_io import pkcs7_pad, pkcs7_unpad

def test_padding():
    print("Testing PKCS#7 padding...")

    # Test various data lengths
    test_cases = [
        b"",  # Empty
        b"A",  # 1 byte
        b"Hello",  # 5 bytes
        b"Hello World!",  # 12 bytes
        b"16 bytes exactly"  # 16 bytes (exact multiple)
    ]

    for data in test_cases:
        padded = pkcs7_pad(data)
        unpadded = pkcs7_unpad(padded)

        assert unpadded == data, f"Padding round-trip failed for {data}"
        print(f"  ✓ {len(data):2d} bytes -> {len(padded):2d} bytes -> {len(unpadded):2d} bytes")

    print("  All padding tests passed!")


def test_encrypt_decrypt_roundtrip():

    print("Testing encrypt/decrypt round-trip...")

    # Test data of various sizes
    test_data = [
        b"Short",
        b"Exactly 16 bytes!!",
        b"This is a longer message that will need padding for sure!",
        b"x" * 100  # 100 bytes
    ]

    key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

    for i, data in enumerate(test_data):
        # Encrypt
        ciphertext = ecb_encrypt(key, data)

        # Decrypt
        plaintext = ecb_decrypt(key, ciphertext)

        assert plaintext == data, f"Round-trip failed for test case {i + 1}"
        print(f"  ✓ Test case {i + 1}: {len(data):3d} bytes -> {len(ciphertext):3d} bytes -> {len(plaintext):3d} bytes")

    print("  All round-trip tests passed!")


def test_file_operations():
    print("Testing file operations...")

    # Create temporary files
    with tempfile.NamedTemporaryFile(delete=False) as original_file:
        original_path = original_file.name
        original_file.write(b"This is test file content for encryption!")

    encrypted_path = original_path + '.enc'
    decrypted_path = original_path + '.dec'

    try:
        key_hex = "000102030405060708090a0b0c0d0e0f"
        key_bytes = bytes.fromhex(key_hex)

        original_data = read_file_binary(original_path)

        encrypted_data = ecb_encrypt(key_bytes, original_data)
        write_file_binary(encrypted_path, encrypted_data)

        encrypted_data_read = read_file_binary(encrypted_path)
        decrypted_data = ecb_decrypt(key_bytes, encrypted_data_read)
        write_file_binary(decrypted_path, decrypted_data)

        assert decrypted_data == original_data, "File round-trip failed"

        print(f"  ✓ File encryption/decryption successful")
        print(f"  ✓ Original: {len(original_data)} bytes")
        print(f"  ✓ Encrypted: {len(encrypted_data)} bytes")
        print(f"  ✓ Decrypted: {len(decrypted_data)} bytes")

    finally:
        for path in [original_path, encrypted_path, decrypted_path]:
            if os.path.exists(path):
                os.unlink(path)


def main():
    print("Running CryptoCore tests...\n")

    try:
        test_padding()
        print()
        test_encrypt_decrypt_roundtrip()
        print()
        test_file_operations()
        print("\n All tests passed!")

    except Exception as e:
        print(f"\n Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()