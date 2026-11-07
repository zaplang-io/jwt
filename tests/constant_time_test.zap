# Walls in the stdlib crypto.constant_time_eq primitive (zaplang-io/zap#729 /
# #757) that now backs HMAC signature comparison (#11 item 8), and confirms HMAC
# verification still accepts a valid token and rejects a same-length tampered
# signature through that comparison path.
import jwt

def main():
    # The primitive: equal content compares equal; a single differing byte at
    # equal length is unequal; a length difference is unequal; str and bytes share
    # the byte-data ABI; two empty inputs are equal.
    assert crypto.constant_time_eq(b"0123456789abcdef", b"0123456789abcdef")
    assert not crypto.constant_time_eq(b"0123456789abcdef", b"0123456789abcdeg")
    assert not crypto.constant_time_eq(b"abc", b"abcd")
    assert not crypto.constant_time_eq(b"abcd", b"abc")
    assert crypto.constant_time_eq(b"", b"")
    assert crypto.constant_time_eq("0123456789abcdef", b"0123456789abcdef")
    # HS256 and HS512 round-trips still authenticate through the comparison.
    auto key = b"0123456789abcdef0123456789abcdef"
    auto t256 = jwt.encode({"exp": JsonValue.Int(200)}, key, "HS256")
    assert len(jwt.verify_signature(t256, key, "HS256").claims) == 1
    auto key64 = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    auto t512 = jwt.encode({"exp": JsonValue.Int(200)}, key64, "HS512")
    assert len(jwt.verify_signature(t512, key64, "HS512").claims) == 1
    # A valid-length but wrong HS256 signature (signed with a different key) is
    # rejected by the comparison itself, not a length or base64 guard.
    auto parts = t256.split(".")
    auto message = parts[0] + "." + parts[1]
    auto wrong = crypto.hmac_sha256_raw(b"different-key-different-key-0123", message)
    auto tampered = message + "." + base64.urlsafe_encode_nopad(wrong)
    auto rejected = False
    try:
        jwt.verify_signature(tampered, key, "HS256")
    except Exception as e:
        rejected = e.startswith("SignatureError:")
    assert rejected
    print("constant-time HMAC comparison: PASS")
