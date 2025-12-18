import binascii
import struct


class SHA3_256:
    """
    SHA3-256 implementation from scratch following NIST FIPS 202
    """

    def __init__(self):
        # SHA3-256 parameters
        self.rate = 1088  # bits (136 bytes)
        self.capacity = 512  # bits
        self.output_size = 256  # bits (32 bytes)

        # State: 5x5 matrix of 64-bit lanes (200 bytes total)
        self.state = [[0] * 5 for _ in range(5)]
        self.buffer = bytearray()

    def _rot64(self, x, n):
        """64-bit rotation"""
        return ((x << (64 - n)) | (x >> n)) & ((1 << 64) - 1)

    def _keccak_f(self):
        """Keccak-f[1600] permutation"""
        # Round constants
        RC = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
            0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        ]

        for round in range(24):
            # θ step
            C = [self.state[x][0] ^ self.state[x][1] ^ self.state[x][2] ^
                 self.state[x][3] ^ self.state[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ self._rot64(C[(x + 1) % 5], 1) for x in range(5)]

            for x in range(5):
                for y in range(5):
                    self.state[x][y] ^= D[x]

            # ρ and π steps
            x, y = 1, 0
            current = self.state[x][y]

            for t in range(24):
                x, y = y, (2 * x + 3 * y) % 5
                current, self.state[x][y] = self.state[x][y], self._rot64(current, (t + 1) * (t + 2) // 2 % 64)

            # χ step
            for y in range(5):
                T = [self.state[x][y] for x in range(5)]
                for x in range(5):
                    self.state[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5])

            # ι step
            self.state[0][0] ^= RC[round]

    def _absorb(self):
        """Absorb data into state"""
        block_size = self.rate // 8  # 136 bytes

        for i in range(0, len(self.buffer), block_size):
            block = self.buffer[i:i + block_size]

            # XOR block into state
            for j in range(len(block)):
                x = j % 5
                y = j // 5
                lane = struct.unpack('<Q', block[j:j + 8] + b'\x00' * (8 - len(block[j:j + 8])))[0]
                self.state[x][y] ^= lane

            self._keccak_f()

        self.buffer = bytearray()

    def update(self, data):
        """Process input data"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        self.buffer.extend(data)

        # Absorb full blocks
        block_size = self.rate // 8
        while len(self.buffer) >= block_size:
            self._absorb()

    def digest(self):
        """Return final hash digest"""
        # Padding: append 0x06, then pad with zeros, then set last byte to 0x80
        block_size = self.rate // 8

        # Add padding
        self.buffer.append(0x06)
        while (len(self.buffer) % block_size) != (block_size - 1):
            self.buffer.append(0x00)
        self.buffer.append(0x80)

        # Final absorption
        self._absorb()

        # Squeeze output
        output = bytearray()
        while len(output) < self.output_size // 8:
            for y in range(5):
                for x in range(5):
                    if len(output) >= self.output_size // 8:
                        break
                    output.extend(struct.pack('<Q', self.state[x][y]))
            if len(output) < self.output_size // 8:
                self._keccak_f()

        return bytes(output[:self.output_size // 8])

    def hexdigest(self):
        """Return final hash as hexadecimal string"""
        return binascii.hexlify(self.digest()).decode('ascii')

    def hash(self, data):
        """Convenience method to hash data in one call"""
        self.update(data)
        return self.hexdigest()


def sha3_256_hash(data):
    """Convenience function for one-time hashing"""
    sha3 = SHA3_256()
    return sha3.hash(data)


def sha3_256_file(filename, chunk_size=4096):
    """Hash a file using SHA3-256"""
    sha3 = SHA3_256()

    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha3.update(chunk)

    return sha3.hexdigest()