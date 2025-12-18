from Crypto.Cipher import AES

from .ecb import pkcs7_pad, pkcs7_unpad
from ..csprng import generate_iv


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

def cbc_decrypt(key, ciphertext):
    """Decrypt AES-CBC"""
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    cipher = AES.new(key, AES.MODE_ECB)

    previous_block = iv
    plaintext_blocks = []

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]

        decrypted_block = cipher.decrypt(block)

        # XOR with previous ciphertext block (or IV)
        plaintext_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))

        plaintext_blocks.append(plaintext_block)
        previous_block = block

    padded = b"".join(plaintext_blocks)
    return pkcs7_unpad(padded)