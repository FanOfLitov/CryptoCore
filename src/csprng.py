import os

def generate_random_bytes(num_bytes: int) -> bytes:

    if num_bytes <= 0:
        raise ValueError("num_bytes must be positive")

    try:
        return os.urandom(num_bytes)
    except Exception as e:
        raise RuntimeError(f"CSPRNG failure: {e}")


def generate_iv() -> bytes:
    return os.urandom(16)

def generate_key() -> bytes:
    return os.urandom(16)