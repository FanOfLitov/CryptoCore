from Crypto.Cipher import AES
from .ecb import pkcs7_pad, pkcs7_unpad
import os


def cbc_encrypt(key, plaintext):
    """Encrypt using AES-CBC mode"""
    # Generate random IV
    iv = os.urandom(16)

    # Pad the plaintext
    padded_plaintext = pkcs7_pad(plaintext)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_blocks = []
    previous_block = iv

    # Process each block
    for i in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[i:i + 16]

        # XOR with previous ciphertext block (or IV for first block)
        xored_block = bytes(a ^ b for a, b in zip(block, previous_block))

        # Encrypt the XOR result
        encrypted_block = cipher.encrypt(xored_block)
        ciphertext_blocks.append(encrypted_block)
        previous_block = encrypted_block

    # Return IV + ciphertext
    return iv + b''.join(ciphertext_blocks)


def cbc_decrypt(key, ciphertext):
    """Decrypt using AES-CBC mode"""
    # Extract IV from first 16 bytes
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext_blocks = []
    previous_block = iv

    # Process each block
    for i in range(0, len(actual_ciphertext), 16):
        block = actual_ciphertext[i:i + 16]

        # Decrypt the block
        decrypted_block = cipher.decrypt(block)

        # XOR with previous ciphertext block
        plaintext_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
        plaintext_blocks.append(plaintext_block)
        previous_block = block

    # Remove padding and return
    plaintext = b''.join(plaintext_blocks)
    return pkcs7_unpad(plaintext)