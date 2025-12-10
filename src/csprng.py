import os

def generate_random_bytes(num_bytes: int) -> bytes:
    """Generate cryptographically secure random bytes.
    Requirements: RNG-1…RNG-6  (Sprint 3)
    """
    if num_bytes <= 0:
        raise ValueError("num_bytes must be positive")

    try:
        return os.urandom(num_bytes)
    except Exception as e:
        raise RuntimeError(f"CSPRNG failure: {e}")


def generate_iv() -> bytes:
    """Generate IV for AES block modes (16 bytes)"""
    return os.urandom(16)

def generate_key() -> bytes:
    """Returns a 16-byte AES-128 key."""
    return os.urandom(16)