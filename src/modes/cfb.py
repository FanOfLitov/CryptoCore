from Crypto.Cipher import AES
from ..csprng import generate_iv


def cfb_encrypt(key, plaintext):
    """Encrypt using AES-CFB mode (stream cipher, no padding)"""
    # Generate random IV using CSPRNG
    iv = generate_iv()

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
    """Decrypt AES-CFB"""
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    cipher = AES.new(key, AES.MODE_ECB)
    feedback = iv
    plaintext_blocks = []

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]

        keystream_block = cipher.encrypt(feedback)
        plaintext_block = bytes(a ^ b for a, b in zip(block, keystream_block))
        plaintext_blocks.append(plaintext_block)

        feedback = block  # CFB updates feedback with ciphertext

    return b"".join(plaintext_blocks)