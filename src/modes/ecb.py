from Crypto.Cipher import AES
from src.file_io import pkcs7_pad, pkcs7_unpad

class ECBMode:
    def __init__(self, key: bytes):
        self.aes = AES.new(key, AES.MODE_ECB)

    def encrypt(self, data: bytes) -> bytes:
        padded = pkcs7_pad(data)
        out = b''
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            out += self.aes.encrypt(block)
        return out

    def decrypt(self, data: bytes) -> bytes:
        out = b''
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            out += self.aes.decrypt(block)
        return pkcs7_unpad(out)


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    return ECBMode(key).encrypt(plaintext)


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return ECBMode(key).decrypt(ciphertext)