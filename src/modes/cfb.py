from Crypto.Cipher import AES
import os


def cfb_encrypt(key, plaintext):
    """Encrypt using AES-CFB mode (stream cipher, no padding)"""
    # Generate random IV
    iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_blocks = []
    feedback = iv

    # Process each block
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]

        # Encrypt the feedback register
        keystream_block = cipher.encrypt(feedback)

        # XOR keystream with plaintext
        ciphertext_block = bytes(a ^ b for a, b in zip(block, keystream_block))
        ciphertext_blocks.append(ciphertext_block)

        # Update feedback register with ciphertext
        feedback = ciphertext_block

    return iv + b''.join(ciphertext_blocks)


def cfb_decrypt(key, ciphertext):
    """Decrypt using AES-CFB mode"""
    # Extract IV from first 16 bytes
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext_blocks = []
    feedback = iv

    # Process each block
    for i in range(0, len(actual_ciphertext), 16):
        block = actual_ciphertext[i:i + 16]

        # Encrypt the feedback register
        keystream_block = cipher.encrypt(feedback)

        # XOR keystream with ciphertext
        plaintext_block = bytes(a ^ b for a, b in zip(block, keystream_block))
        plaintext_blocks.append(plaintext_block)

        # Update feedback register with ciphertext (not plaintext!)
        feedback = block

    return b''.join(plaintext_blocks)