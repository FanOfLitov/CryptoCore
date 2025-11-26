#!/usr/bin/env python3

import os
import sys
import tempfile
import subprocess

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from hash.sha256 import SHA256, sha256_hash, sha256_file
from hash.sha3_256 import SHA3_256, sha3_256_hash, sha3_256_file


def test_sha256_known_answers():
    """Test SHA-256 with known test vectors"""
    print("Testing SHA-256 known answers...")

    # NIST test vectors
    test_vectors = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ]

    for data, expected in test_vectors:
        result = sha256_hash(data.encode('utf-8') if data else b"")
        assert result == expected, f"SHA-256 failed for '{data}': got {result}, expected {expected}"
        print(f"  ✓ '{data[:20]}{'...' if len(data) > 20 else ''}' -> {expected[:16]}...")

    print("  All SHA-256 known answer tests passed!")


def test_sha3_256_known_answers():
    """Test SHA3-256 with known test vectors"""
    print("Testing SHA3-256 known answers...")

    test_vectors = [
        ("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        ("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
    ]

    for data, expected in test_vectors:
        result = sha3_256_hash(data.encode('utf-8') if data else b"")
        assert result == expected, f"SHA3-256 failed for '{data}': got {result}, expected {expected}"
        print(f"  ✓ '{data[:20]}{'...' if len(data) > 20 else ''}' -> {expected[:16]}...")

    print("  All SHA3-256 known answer tests passed!")


def test_avalanche_effect():
    """Test that changing one bit produces completely different hash"""
    print("Testing avalanche effect...")

    original_data = b"Hello, world!"
    modified_data = b"Hello, world?"  # Changed last character

    # Test SHA-256
    hash1 = sha256_hash(original_data)
    hash2 = sha256_hash(modified_data)

    bin1 = bin(int(hash1, 16))[2:].zfill(256)
    bin2 = bin(int(hash2, 16))[2:].zfill(256)

    diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))
    print(f"  SHA-256 bits changed: {diff_count}/256")
    assert 100 < diff_count < 156, f"SHA-256 avalanche effect weak: {diff_count} bits changed"

    # Test SHA3-256
    hash1 = sha3_256_hash(original_data)
    hash2 = sha3_256_hash(modified_data)

    bin1 = bin(int(hash1, 16))[2:].zfill(256)
    bin2 = bin(int(hash2, 16))[2:].zfill(256)

    diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))
    print(f"  SHA3-256 bits changed: {diff_count}/256")
    assert 100 < diff_count < 156, f"SHA3-256 avalanche effect weak: {diff_count} bits changed"

    print("  ✓ Avalanche effect tests passed!")


def test_file_hashing():
    """Test file hashing functionality"""
    print("Testing file hashing...")

    with tempfile.NamedTemporaryFile(delete=False) as f:
        test_file = f.name
        f.write(b"Test file content for hashing")

    try:
        # Test SHA-256 file hashing
        sha256_result = sha256_file(test_file)
        expected_sha256 = sha256_hash(b"Test file content for hashing")
        assert sha256_result == expected_sha256, "SHA-256 file hashing failed"

        # Test SHA3-256 file hashing
        sha3_result = sha3_256_file(test_file)
        expected_sha3 = sha3_256_hash(b"Test file content for hashing")
        assert sha3_result == expected_sha3, "SHA3-256 file hashing failed"

        print("  ✓ File hashing tests passed!")
    finally:
        os.unlink(test_file)


def test_interoperability():
    """Test interoperability with system tools"""
    print("Testing interoperability...")

    with tempfile.NamedTemporaryFile(delete=False) as f:
        test_file = f.name
        f.write(b"Interoperability test data")

    try:
        # Test SHA-256 with sha256sum
        our_hash = sha256_file(test_file)

        # Get system hash (if available)
        try:
            result = subprocess.run(['sha256sum', test_file], capture_output=True, text=True)
            if result.returncode == 0:
                system_hash = result.stdout.split()[0]
                assert our_hash == system_hash, f"SHA-256 interoperability failed: {our_hash} vs {system_hash}"
                print("  ✓ SHA-256 interoperability with sha256sum confirmed")
            else:
                print("  ℹ sha256sum not available, skipping interoperability test")
        except FileNotFoundError:
            print("  ℹ sha256sum not available, skipping interoperability test")

        print("  ✓ Interoperability tests completed")
    finally:
        os.unlink(test_file)


def main():
    """Run all hash tests"""
    print("Running hash function tests...\n")

    try:
        test_sha256_known_answers()
        print()
        test_sha3_256_known_answers()
        print()
        test_avalanche_effect()
        print()
        test_file_hashing()
        print()
        test_interoperability()

        print("\n🎉 All hash tests passed!")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()