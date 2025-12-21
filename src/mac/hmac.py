from ..hash.sha256 import SHA256

class HMAC:


    BLOCK_SIZE = 64  # bytes for SHA-256

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes")

        self.key = self._process_key(key)

    def _process_key(self, key: bytes) -> bytes:

        if len(key) > self.BLOCK_SIZE:
            sha = SHA256()
            sha.update(key)
            key = sha.digest()

        if len(key) < self.BLOCK_SIZE:
            key = key + b'\x00' * (self.BLOCK_SIZE - len(key))

        return key

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def compute(self, message: bytes) -> bytes:

        ipad = self._xor_bytes(self.key, b'\x36' * self.BLOCK_SIZE)
        opad = self._xor_bytes(self.key, b'\x5c' * self.BLOCK_SIZE)


        inner = SHA256()
        inner.update(ipad)
        inner.update(message)
        inner_digest = inner.digest()


        outer = SHA256()
        outer.update(opad)
        outer.update(inner_digest)

        return outer.digest()

    def hexdigest(self, message: bytes) -> str:
        return self.compute(message).hex()
