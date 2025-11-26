from Crypto.Cipher import AES
import os


def ofb_encrypt(key, plaintext):
    """Encrypt using AES-OFB mode (stream cipher, no padding)"""
    # Generate random IV
    iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_blocks = []
    feedback = iv

    # Process each block
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]

        # Encrypt the feedback register to generate keystream
        keystream_block = cipher.encrypt(feedback)

        # XOR keystream with plaintext
        ciphertext_block = bytes(a ^ b for a, b in zip(block, keystream_block))
        ciphertext_blocks.append(ciphertext_block)

        # Update feedback register with keystream (not ciphertext!)
        feedback = keystream_block

    return iv + b''.join(ciphertext_blocks)


def ofb_decrypt(key, ciphertext):
    """Decrypt using AES-OFB mode (same as encryption)"""
    # OFB decryption is identical to encryption
    return ofb_encrypt(key, ciphertext)