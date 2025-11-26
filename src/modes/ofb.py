from Crypto.Cipher import AES
from ..csprng import generate_iv


def ofb_encrypt(key, plaintext):
    """Encrypt using AES-OFB mode (stream cipher, no padding)"""
    # Generate random IV using CSPRNG
    iv = generate_iv()

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