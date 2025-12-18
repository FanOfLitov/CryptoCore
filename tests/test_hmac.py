from .mac.hmac import HMAC

def test_rfc_4231_vectors():
    tests = [
        {
            "key": bytes.fromhex("0b" * 20),
            "msg": b"Hi There",
            "expected": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        },
        {
            "key": b"Jefe",
            "msg": b"what do ya want for nothing?",
            "expected": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        }
    ]

    for t in tests:
        h = HMAC(t["key"])
        assert h.hexdigest(t["msg"]) == t["expected"]
