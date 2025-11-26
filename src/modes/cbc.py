from Crypto.Cipher import AES
from ..csprng import generate_iv
from .ecb import pkcs7_pad, pkcs7_unpad


def cbc_encrypt(key, plaintext):
    """Encrypt using AES-CBC mode"""
    # Generate random IV using CSPRNG
    iv = generate_iv()

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