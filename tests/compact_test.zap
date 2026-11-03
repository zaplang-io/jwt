import jwt

def signed(str header, str payload, bytes key) -> str:
    auto message = base64.urlsafe_encode_nopad(header) + "." + base64.urlsafe_encode_nopad(payload)
    return message + "." + base64.urlsafe_encode_nopad(crypto.hmac_sha256_raw(key, message))

def bad(str token, bytes key, str category, str algorithm = "HS256"):
    auto caught = False
    auto observed = "accepted"
    try:
        jwt.verify_signature(token, key, algorithm)
    except Exception as e:
        observed = e
        caught = e.startswith(category + ":")
    if not caught:
        raise "Expected " + category + ", observed " + observed + "; input " + token[:160]

def bad_encode(
    dict[str, JsonValue] headers,
    bytes key,
    str category,
    str algorithm = "HS256",
):
    auto caught = False
    auto observed = "accepted"
    try:
        jwt.encode({}, key, algorithm, headers)
    except Exception as e:
        observed = e
        caught = e.startswith(category + ":")
    if not caught:
        raise "Expected encode " + category + ", observed " + observed

def main():
    auto key = b"0123456789abcdef0123456789abcdef"
    auto header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
    auto token = signed(header, "{}", key)
    auto verified = jwt.verify_signature(token, key, "HS256")
    assert len(verified.claims) == 0
    auto parts = token.split(".")
    bad(token, b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "SignatureError")
    bad(token, key, "AlgorithmError", "none")
    bad(token, key, "KeyError", "HS512")
    bad(token, b"weak", "KeyError")
    for value in ["", "a", "a.b", "a.b.c.d", ".e30.AA", "e30.e30."]:
        bad(value, key, "TokenError")
    for value in ["=", "AA=", "A+", "A/", "A A", "AB", "é", "A"]:
        bad(value + "." + parts[1] + "." + parts[2], key, "TokenError")
    bad(parts[0] + ".e30.AA", key, "SignatureError")
    bad(
        parts[0] + ".e30." + base64.urlsafe_encode_nopad(bytes([0, 1, 2])),
        key,
        "SignatureError",
    )
    bad(
        parts[0] + ".e30." + base64.urlsafe_encode_nopad(bytes([0, 1, 2, 3])),
        key,
        "SignatureError",
    )
    bad(signed("{\"alg\":\"HS512\"}", "{}", key), key, "AlgorithmError")
    for value in ["{}", "{\"alg\":false}", "{\"alg\":null}", "{\"alg\":\"none\"}", "{\"alg\":\"RS256\"}"]:
        bad(signed(value, "{}", key), key, "AlgorithmError")
    for field in ["crit", "b64", "jku", "x5u", "jwk", "x5c", "zip"]:
        bad(
            signed("{\"alg\":\"HS256\",\"" + field + "\":null}", "{}", key),
            key,
            "HeaderError",
        )
    for field in ["typ", "cty", "kid"]:
        bad(
            signed("{\"alg\":\"HS256\",\"" + field + "\":7}", "{}", key),
            key,
            "HeaderError",
        )
    for value in ["[]", "null", "true", "1", "\"hello\"", "{", "{}{}", "{\"a\":1,}", "{\"a\":NaN}"]:
        bad(signed(header, value, key), key, "TokenError")
        bad(signed(value, "{}", key), key, "TokenError")
    for value in ["{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}", "{\"x\":{\"a\":1,\"a\":2}}", "{\"x\":[{\"a\":1,\"a\":2}]}"]:
        bad(signed(header, value, key), key, "TokenError")
    bad(
        signed("{\"alg\":\"HS256\",\"\\u0061lg\":\"HS256\"}", "{}", key),
        key,
        "TokenError",
    )
    bad(signed(header, str(b"{\"a\":1}") + "garbage", key), key, "TokenError")
    auto raw_message = parts[0] + "." + base64.urlsafe_encode_nopad(bytes([255, 254]))
    bad(
        raw_message + "." + base64.urlsafe_encode_nopad(crypto.hmac_sha256_raw(key, raw_message)),
        key,
        "TokenError",
    )
    auto nested = "0"
    for i in range(32):
        nested = "[" + nested + "]"
    bad(signed(header, "{\"x\":" + nested + "}", key), key, "TokenError")
    auto huge = "a"
    for i in range(16):
        huge = huge + huge
    huge = huge[:50001]
    bad(huge, key, "TokenError")
    auto huge_payload = "{\"x\":\"" + huge + "\"}"
    bad(signed(header, huge_payload, key), key, "TokenError")
    bad_encode({}, b"", "KeyError")
    bad_encode({}, key, "AlgorithmError", "RS256")
    bad_encode({"alg": JsonValue.Str("none")}, key, "AlgorithmError")
    bad_encode({"jku": JsonValue.Str("https://attacker.invalid")}, key, "HeaderError")
    auto headers = {"kid": JsonValue.Str("key-1")}
    auto claims = {"nested": json.loads("[{\"a\":1},{\"a\":2}]")}
    auto encoded = jwt.encode(claims, key, "HS256", headers)
    assert len(headers) == 1
    assert len(claims) == 1
    assert len(jwt.verify_signature(encoded, key, "HS256").claims) == 1
    # Signature-only verification explicitly does not enforce expiration.
    jwt.verify_signature(
        jwt.encode({"exp": JsonValue.Int(0)}, key, "HS256"),
        key,
        "HS256",
    )
    print("compact and adversarial cases: PASS")
