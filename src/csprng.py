import os
import sys


def generate_random_bytes(num_bytes):
    """
    Generates cryptographically secure random bytes using os.urandom()

    Args:
        num_bytes: Number of random bytes to generate

    Returns:
        bytes: Cryptographically secure random bytes

    Raises:
        RuntimeError: If random bytes cannot be generated
    """
    if num_bytes <= 0:
        raise ValueError("Number of bytes must be positive")

    try:
        return os.urandom(num_bytes)
    except Exception as e:
        raise RuntimeError(f"Failed to generate random bytes: {e}")


def generate_key():
    """
    Generate a random 16-byte AES-128 key

    Returns:
        bytes: 16-byte key
    """
    return generate_random_bytes(16)


def generate_iv():
    """
    Generate a random 16-byte IV

    Returns:
        bytes: 16-byte IV
    """
    return generate_random_bytes(16)