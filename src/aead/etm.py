import secrets
from ..mac.hmac import HMAC

TAG_LEN = 32  # HMAC-SHA256 bytes


def split_master_key(master_key: bytes) -> tuple[bytes, bytes]:
    """
    Milestone 6 temporary key split:
    master_key must be 48 bytes: 16 bytes enc key + 32 bytes mac key
    (In Milestone 7 we replace this with HKDF.)
    """
    if len(master_key) != 48:
        raise ValueError("AEAD master key must be exactly 48 bytes (96 hex chars)")
    return master_key[:16], master_key[16:]


def etm_encrypt(encrypt_func, master_key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt-then-MAC:
      ct = Encrypt(key_enc, plaintext)   (ct already includes IV/nonce prefix if mode uses it)
      tag = HMAC(key_mac, ct)
      out = ct || tag
    """
    key_enc, key_mac = split_master_key(master_key)

    ct = encrypt_func(key_enc, plaintext)
    tag = HMAC(key_mac).compute(ct)

    return ct + tag


def etm_decrypt(decrypt_func, master_key: bytes, data: bytes) -> bytes:
    """
    Verify-then-Decrypt:
      ct = data[:-TAG_LEN]
      tag = data[-TAG_LEN:]
      verify HMAC(key_mac, ct)
      if ok -> Decrypt(key_enc, ct)
    """
    if len(data) < TAG_LEN + 1:
        raise ValueError("Ciphertext too short to contain authentication tag")

    key_enc, key_mac = split_master_key(master_key)

    ct = data[:-TAG_LEN]
    tag = data[-TAG_LEN:]

    expected = HMAC(key_mac).compute(ct)
    if not secrets.compare_digest(tag, expected):
        raise ValueError("Authentication failed (HMAC tag mismatch)")

    return decrypt_func(key_enc, ct)
