from Crypto.Cipher import AES
from ..csprng import generate_random_bytes
import struct


def ctr_encrypt(key, plaintext):
    """Encrypt using AES-CTR mode (stream cipher, no padding)"""
    # Generate random nonce using CSPRNG (8 bytes for CTR)
    nonce = generate_random_bytes(8)
    counter = 0

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_blocks = []

    # Process each block
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]

        # Create counter block: nonce + counter
        counter_block = nonce + struct.pack('<Q', counter)  # Little-endian counter

        # Encrypt counter block to generate keystream
        keystream_block = cipher.encrypt(counter_block)

        # XOR keystream with plaintext
        ciphertext_block = bytes(a ^ b for a, b in zip(block, keystream_block))
        ciphertext_blocks.append(ciphertext_block)

        counter += 1

    return nonce + b''.join(ciphertext_blocks)