from Crypto.Cipher import AES

from ..csprng import generate_iv


def ofb_encrypt(key, plaintext):
    iv = generate_iv()

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext_blocks = []
    feedback = iv

    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]

        keystream_block = cipher.encrypt(feedback)


        ciphertext_block = bytes(a ^ b for a, b in zip(block, keystream_block))
        ciphertext_blocks.append(ciphertext_block)


        feedback = keystream_block

    return iv + b''.join(ciphertext_blocks)


def ofb_decrypt(key, ciphertext):

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

        feedback = keystream_block  # OFB updates feedback with keystream

    return b"".join(plaintext_blocks)