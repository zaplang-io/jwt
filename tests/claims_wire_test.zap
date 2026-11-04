import jwt

def signed(str header, str payload) -> str:
    auto message = base64.urlsafe_encode_nopad(header) + "." + base64.urlsafe_encode_nopad(payload)
    return message + "." + base64.urlsafe_encode_nopad(crypto.hmac_sha256_raw(b"0123456789abcdef0123456789abcdef", message))

def reject(str encoded, str category):
    auto caught = False
    auto observed = "accepted"
    try:
        jwt.decode_at(encoded, b"0123456789abcdef0123456789abcdef", "HS256", 100.0)
    except Exception as e:
        observed = e
        caught = e.startswith(category + ":")
    if not caught:
        raise "Expected " + category + ", observed " + observed

def main():
    reject(signed("{\"alg\":\"HS256\"}", "{\"exp\":200}"), "ClaimsError")
    reject(
        signed("{\"alg\":\"HS256\",\"typ\":\"jwt\"}", "{\"exp\":200}"),
        "ClaimsError",
    )
    # Invalid transport/JSON remains a TokenError, before application policy.
    reject(
        signed("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"exp\":1e309}"),
        "TokenError",
    )
    reject(
        signed("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"exp\":200,\"exp\":0}"),
        "TokenError",
    )
    reject(
        signed("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"exp\":9223372036854775807}"),
        "ClaimsError",
    )
    reject(
        signed("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"exp\":-9223372036854775808}"),
        "ClaimsError",
    )
    auto message = base64.urlsafe_encode_nopad("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + base64.urlsafe_encode_nopad("{\"exp\":false}")
    auto wrong_key = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    reject(
        message + "." + base64.urlsafe_encode_nopad(crypto.hmac_sha256_raw(wrong_key, message)),
        "SignatureError",
    )
    # All supported algorithms enter the same claims policy path.
    auto key = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    auto encoded = jwt.encode({"exp": JsonValue.Int(200)}, key, "HS512")
    assert len(jwt.decode_at(encoded, key, "HS512", 100.0)) == 1
    print("claims wire and error ordering: PASS")
