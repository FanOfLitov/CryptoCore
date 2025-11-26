from Crypto.Cipher import AES
import struct


def pkcs7_pad(data, block_size=16):
    """
    Apply PKCS#7 padding to data

    Args:
        data: Bytes to pad
        block_size: Block size in bytes (default 16 for AES)

    Returns:
        bytes: Padded data
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data):
    """
    Remove PKCS#7 padding from data

    Args:
        data: Padded bytes

    Returns:
        bytes: Data without padding
    """
    if len(data) == 0:
        return data

    padding_length = data[-1]

    # Validate padding
    if padding_length < 1 or padding_length > len(data):
        raise ValueError("Invalid PKCS#7 padding")

    # Check that all padding bytes are correct
    if not all(byte == padding_length for byte in data[-padding_length:]):
        raise ValueError("Invalid PKCS#7 padding")

    return data[:-padding_length]


def ecb_encrypt(key, plaintext):
    """
    Encrypt data using AES-128 in ECB mode

    Args:
        key: 16-byte encryption key
        plaintext: Data to encrypt

    Returns:
        bytes: Encrypted data
    """
    # Pad the plaintext
    padded_plaintext = pkcs7_pad(plaintext)

    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt each block
    ciphertext = cipher.encrypt(padded_plaintext)

    return ciphertext


def ecb_decrypt(key, ciphertext):
    """
    Decrypt data using AES-128 in ECB mode

    Args:
        key: 16-byte decryption key
        ciphertext: Data to decrypt

    Returns:
        bytes: Decrypted data with padding removed
    """
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove padding
    plaintext = pkcs7_unpad(padded_plaintext)

    return plaintext