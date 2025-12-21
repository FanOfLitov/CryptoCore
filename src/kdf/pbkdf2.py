from ..mac.hmac import HMAC
from math import ceil


def pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """
    PBKDF2-HMAC-SHA256 (RFC 8018)
    """
    hlen = 32  # SHA256 output length
    l = ceil(dklen / hlen)

    dk = b""

    for i in range(1, l + 1):
        u = HMAC(password).compute(salt + i.to_bytes(4, 'big'))
        t = u

        for _ in range(iterations - 1):
            u = HMAC(password).compute(u)
            t = bytes(x ^ y for x, y in zip(t, u))

        dk += t

    return dk[:dklen]
