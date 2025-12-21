import secrets
from ..mac.hmac import HMAC
from ..kdf.hkdf import hkdf_extract, hkdf_expand

TAG_LEN = 32  # HMAC-SHA256 bytes


def derive_aead_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """
    Milestone 7: derive independent encryption and MAC keys using HKDF.
    key_enc: 16 bytes (AES-128)
    key_mac: 32 bytes (HMAC-SHA256 key)
    """
    prk = hkdf_extract(None, master_key)
    key_material = hkdf_expand(prk, b"aead-etm", 48)
    return key_material[:16], key_material[16:]


def etm_encrypt(encrypt_func, master_key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt-then-MAC:
      ct = encrypt_func(key_enc, plaintext)   (ct already includes IV/nonce if mode uses it)
      tag = HMAC(key_mac, ct)
      out = ct || tag
    """
    key_enc, key_mac = derive_aead_keys(master_key)

    ct = encrypt_func(key_enc, plaintext)
    tag = HMAC(key_mac).compute(ct)

    return ct + tag


def etm_decrypt(decrypt_func, master_key: bytes, data: bytes) -> bytes:
    """
    Verify-then-Decrypt:
      ct = data[:-TAG_LEN]
      tag = data[-TAG_LEN:]
      verify HMAC(key_mac, ct)
      if ok -> decrypt_func(key_enc, ct)
    """
    if len(data) < TAG_LEN + 1:
        raise ValueError("Ciphertext too short to contain authentication tag")

    key_enc, key_mac = derive_aead_keys(master_key)

    ct = data[:-TAG_LEN]
    tag = data[-TAG_LEN:]

    expected = HMAC(key_mac).compute(ct)
    if not secrets.compare_digest(tag, expected):
        raise ValueError("Authentication failed (HMAC tag mismatch)")

    return decrypt_func(key_enc, ct)
