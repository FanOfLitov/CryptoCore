import struct

from Crypto.Cipher import AES

from ..csprng import generate_random_bytes


def ctr_encrypt(key, plaintext):
    nonce = generate_random_bytes(8)
    counter = 0

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_blocks = []


    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]

        counter_block = nonce + struct.pack('<Q', counter)  # Little-endian counter

        keystream_block = cipher.encrypt(counter_block)

        ciphertext_block = bytes(a ^ b for a, b in zip(block, keystream_block))
        ciphertext_blocks.append(ciphertext_block)

        counter += 1

    return nonce + b''.join(ciphertext_blocks)


def ctr_decrypt(key, ciphertext):
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]

    cipher = AES.new(key, AES.MODE_ECB)
    counter = 0
    plaintext_blocks = []

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]

        counter_block = nonce + struct.pack('<Q', counter)
        keystream_block = cipher.encrypt(counter_block)

        plaintext_block = bytes(a ^ b for a, b in zip(block, keystream_block))
        plaintext_blocks.append(plaintext_block)

        counter += 1

    return b"".join(plaintext_blocks)