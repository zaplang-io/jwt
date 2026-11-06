# RFC 7515 Appendix A.1 known-answer vector (HS256), an authoritative
# cross-implementation fixture. The token, key and signature are copied verbatim
# from the RFC; this profile must verify the RFC's own JWS and reject any tamper.
import jwt

def main():
    # RFC 7515 A.1: oct key "k" (base64url) and the complete JWS compact form.
    auto k = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    auto key = base64.urlsafe_decode(k)
    auto header = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    auto payload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    auto signature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    auto jws = header + "." + payload + "." + signature
    auto verified = jwt.verify_signature(jws, key, "HS256")
    assert json.dumps(verified.claims["iss"]) == "\"joe\""
    # The RFC header survives verbatim through verification.
    assert json.dumps(verified.header["typ"]) == "\"JWT\""
    match verified.claims["http://example.com/is_root"]:
        case JsonValue.Bool(b):
            assert b
        case _:
            assert False
    # A single flipped signature character must fail authentication.
    auto tampered = header + "." + payload + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl"
    auto caught = False
    try:
        jwt.verify_signature(tampered, key, "HS256")
    except Exception as e:
        caught = e.startswith("SignatureError:")
    assert caught
    # Pinning a different algorithm than the token's header is rejected.
    auto mismatched = False
    try:
        jwt.verify_signature(jws, key, "HS512")
    except Exception as e:
        mismatched = e.startswith("AlgorithmError:")
    assert mismatched
    print("RFC 7515 A.1 known-answer vector: PASS")
