from ..mac.hmac import HMAC
from math import ceil


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * 32
    return HMAC(salt).compute(ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hlen = 32
    n = ceil(length / hlen)

    okm = b""
    t = b""

    for i in range(1, n + 1):
        t = HMAC(prk).compute(t + info + bytes([i]))
        okm += t

    return okm[:length]
