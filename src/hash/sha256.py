import binascii
import struct


class SHA256:
    """
    SHA-256 implementation from scratch following NIST FIPS 180-4
    """

    def __init__(self):
        # Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes)
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]

        # Initialize round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        self.message_length = 0
        self.chunk_buffer = bytearray()

    def _rotr(self, n, x):
        """Right rotate n bits of 32-bit word x"""
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def _shr(self, n, x):
        """Right shift n bits of 32-bit word x"""
        return (x >> n) & 0xFFFFFFFF

    def _ch(self, x, y, z):
        """Choice function"""
        return (x & y) ^ (~x & z)

    def _maj(self, x, y, z):
        """Majority function"""
        return (x & y) ^ (x & z) ^ (y & z)

    def _sigma0(self, x):
        """σ0 function"""
        return self._rotr(2, x) ^ self._rotr(13, x) ^ self._rotr(22, x)

    def _sigma1(self, x):
        """σ1 function"""
        return self._rotr(6, x) ^ self._rotr(11, x) ^ self._rotr(25, x)

    def _gamma0(self, x):
        """γ0 function"""
        return self._rotr(7, x) ^ self._rotr(18, x) ^ self._shr(3, x)

    def _gamma1(self, x):
        """γ1 function"""
        return self._rotr(17, x) ^ self._rotr(19, x) ^ self._shr(10, x)

    def padding(self, message_length):
        """
        SHA-256 padding: append bit '1', then '0's, then 64-bit message length
        """
        length = message_length * 8  # Convert to bits

        # Start with padding byte 0x80 (bit '1' followed by seven '0's)
        padding = bytearray([0x80])

        # Calculate number of zeros needed
        zeros_needed = (64 - (message_length + 1 + 8) % 64) % 64
        padding.extend([0x00] * zeros_needed)

        # Append 64-bit big-endian length
        padding.extend(struct.pack('>Q', length))

        return padding

    def process_block(self, block):
        """Process one 512-bit block"""
        if len(block) != 64:
            raise ValueError("Block must be exactly 64 bytes")

        # Convert block to 32-bit words
        w = list(struct.unpack('>16I', block))

        # Extend to 64 words
        for i in range(16, 64):
            s0 = self._gamma0(w[i - 15])
            s1 = self._gamma1(w[i - 2])
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

        # Initialize working variables
        a, b, c, d, e, f, g, h = self.h

        # Main compression loop
        for i in range(64):
            s1 = self._sigma1(e)
            ch = self._ch(e, f, g)
            temp1 = (h + s1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
            s0 = self._sigma0(a)
            maj = self._maj(a, b, c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Update hash values
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def update(self, data):
        """Process input data in chunks"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        self.message_length += len(data)
        self.chunk_buffer.extend(data)

        # Process complete 64-byte blocks
        while len(self.chunk_buffer) >= 64:
            block = bytes(self.chunk_buffer[:64])
            self.process_block(block)
            self.chunk_buffer = self.chunk_buffer[64:]

    def digest(self):
        """Return final hash digest"""
        # Process remaining data with padding
        padding = self.padding(self.message_length)
        self.update(padding)

        # Ensure all data is processed
        if len(self.chunk_buffer) != 0:
            raise ValueError("Buffer should be empty after finalization")

        # Convert hash values to bytes
        digest_bytes = bytearray()
        for h_val in self.h:
            digest_bytes.extend(struct.pack('>I', h_val))

        return bytes(digest_bytes)

    def hexdigest(self):
        """Return final hash as hexadecimal string"""
        return binascii.hexlify(self.digest()).decode('ascii')

    def hash(self, data):
        """Convenience method to hash data in one call"""
        self.update(data)
        return self.hexdigest()


def sha256_hash(data):
    """Convenience function for one-time hashing"""
    sha256 = SHA256()
    return sha256.hash(data)


def sha256_file(filename, chunk_size=4096):
    """Hash a file using SHA-256"""
    sha256 = SHA256()

    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()