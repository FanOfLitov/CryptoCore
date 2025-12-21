#!/usr/bin/env python3

import os
import sys
import tempfile

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from csprng import generate_random_bytes, generate_key


def test_key_uniqueness():
    print("Testing key uniqueness...")

    key_set = set()
    num_keys = 1000

    for i in range(num_keys):
        key = generate_key()
        key_hex = key.hex()

        assert key_hex not in key_set, f"Duplicate key found: {key_hex}"
        key_set.add(key_hex)

        if (i + 1) % 100 == 0:
            print(f"  Generated {i + 1} unique keys...")

    print(f"✓ Successfully generated {len(key_set)} unique keys")


def test_bit_distribution():

    print("Testing bit distribution...")

    total_bits = 0
    total_ones = 0

    random_data = generate_random_bytes(10000)  # 10KB


    for byte in random_data:
        total_bits += 8
        total_ones += bin(byte).count('1')

    ones_ratio = total_ones / total_bits
    print(f"  Total bits: {total_bits}")
    print(f"  Ones: {total_ones} ({ones_ratio:.2%})")

    # Check that ratio is close to 50%
    assert 0.48 <= ones_ratio <= 0.52, f"Bit distribution skewed: {ones_ratio:.2%}"
    print("✓ Bit distribution is within expected range")


def test_nist_preparation():
    print("Generating NIST test data...")

    total_size = 10_000_000  # 10 MB
    output_file = 'nist_test_data.bin'

    with open(output_file, 'wb') as f:
        bytes_written = 0
        chunk_size = 4096

        while bytes_written < total_size:
            remaining = total_size - bytes_written
            current_chunk_size = min(chunk_size, remaining)

            random_chunk = generate_random_bytes(current_chunk_size)
            f.write(random_chunk)
            bytes_written += len(random_chunk)

            if bytes_written % (total_size // 10) == 0:
                progress = (bytes_written / total_size) * 100
                print(f"  Progress: {progress:.0f}%")

    print(f"✓ Generated {bytes_written} bytes for NIST testing in '{output_file}'")


def test_error_handling():
    print("Testing error handling...")

    try:
        generate_random_bytes(0)
        assert False, "Should have raised ValueError for 0 bytes"
    except ValueError:
        print("  ✓ Correctly handled 0 bytes request")

    try:
        generate_random_bytes(-1)
        assert False, "Should have raised ValueError for negative bytes"
    except ValueError:
        print("  ✓ Correctly handled negative bytes request")

    print("✓ All error handling tests passed")


def main():
    """Run all CSPRNG tests"""
    print("Running CSPRNG tests...\n")

    try:
        test_key_uniqueness()
        print()
        test_bit_distribution()
        print()
        test_error_handling()
        print()
        test_nist_preparation()

        print("\nAll CSPRNG tests passed!")
        print("\nNext steps:")
        print("1. Run NIST STS on the generated 'nist_test_data.bin'")
        print("2. Follow NIST STS documentation for statistical testing")

    except Exception as e:
        print(f"\n Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()