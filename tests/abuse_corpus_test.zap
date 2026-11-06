# Systematic abuse/regression corpus for the compact layer: malformed structure,
# signature reuse, non-object/duplicate/invalid-UTF-8 headers, and the no-Unicode-
# normalization policy guarantee. Complements the per-feature tests as a single
# walled garden against regressions.
import jwt

def reject(str token, bytes key, str algorithm, str prefix):
    auto caught = False
    try:
        jwt.verify_signature(token, key, algorithm)
    except Exception as e:
        caught = e.startswith(prefix)
    assert caught

def header_segment(str json_text) -> str:
    return base64.urlsafe_encode_nopad(bytes(json_text))

def main():
    auto key = b"0123456789abcdef0123456789abcdef"
    auto token = jwt.encode({"sub": JsonValue.Str("alice")}, key, "HS256")
    auto parts = token.split(".")

    # ---- compact structure ----
    reject("", key, "HS256", "TokenError")
    reject("..", key, "HS256", "TokenError")
    reject(parts[0] + "." + parts[1], key, "HS256", "TokenError")
    reject(token + "." + parts[2], key, "HS256", "TokenError")
    reject("." + parts[1] + "." + parts[2], key, "HS256", "TokenError")
    reject(parts[0] + "." + parts[1] + ".", key, "HS256", "TokenError")

    # ---- signature reuse across tokens signed with the same key ----
    auto other = jwt.encode({"sub": JsonValue.Str("mallory")}, key, "HS256")
    auto other_parts = other.split(".")
    auto forged = parts[0] + "." + parts[1] + "." + other_parts[2]
    reject(forged, key, "HS256", "SignatureError")

    # ---- malformed headers (rejected before signature verification) ----
    auto sig = "AAAA"
    reject(
        header_segment("[\"HS256\"]") + "." + parts[1] + "." + sig,
        key,
        "HS256",
        "TokenError",
    )
    reject(
        header_segment("{\"alg\":\"HS256\",\"alg\":\"HS256\"}") + "." + parts[1] + "." + sig,
        key,
        "HS256",
        "TokenError",
    )
    reject(
        header_segment("{\"alg\":123}") + "." + parts[1] + "." + sig,
        key,
        "HS256",
        "AlgorithmError",
    )
    reject(
        header_segment("{\"alg\":\"HS256\",\"crit\":[\"exp\"]}") + "." + parts[1] + "." + sig,
        key,
        "HS256",
        "HeaderError",
    )
    # A header segment whose bytes are not valid UTF-8 is a transport error.
    auto non_utf8 = base64.urlsafe_encode_nopad(b"\xff\xfe\xfd")
    reject(non_utf8 + "." + parts[1] + "." + sig, key, "HS256", "TokenError")

    # ---- claims policy is exact and case-sensitive, with no normalization ----
    auto signed = jwt.encode(
        {
            "iss": JsonValue.Str("issuer"),
            "aud": JsonValue.Str("api"),
            "exp": JsonValue.Int(200),
        },
        key,
        "HS256",
    )
    auto policy = jwt.Policy(expected={"iss": "Issuer"}, audiences=["api"])
    auto case_caught = False
    try:
        jwt.decode_at(signed, key, "HS256", 100.0, policy)
    except Exception as e:
        case_caught = e.startswith("ClaimsError:")
    assert case_caught
    # The exact issuer still authenticates and validates.
    auto ok_policy = jwt.Policy(expected={"iss": "issuer"}, audiences=["api"])
    auto claims = jwt.decode_at(signed, key, "HS256", 100.0, ok_policy)
    assert json.dumps(claims["iss"]) == "\"issuer\""

    print("abuse corpus: PASS")
