import jwt

def rejected(dict[str, JsonValue] claims, bytes key):
    auto caught = False
    try:
        jwt.encode(claims, key, "HS256")
    except Exception as e:
        caught = e.startswith("TokenError:")
    assert caught

def main():
    auto key = b"0123456789abcdef0123456789abcdef"
    auto nested = JsonValue.Int(0)
    for i in range(31):
        nested = JsonValue.Array([nested])
    jwt.encode({"x": nested}, key, "HS256")
    nested = JsonValue.Array([nested])
    rejected({"x": nested}, key)
    rejected({"x": JsonValue.Float(float64("nan"))}, key)
    rejected({"x": JsonValue.Float(float64("inf"))}, key)
    auto text = "a"
    for i in range(16):
        text = text + text
    rejected({"x": JsonValue.Str(text)}, key)
    # Payload alone fits 32768 bytes; the next byte exceeds the public limit.
    auto at_limit = {"x": JsonValue.Str(text[:32760])}
    auto token = jwt.encode(at_limit, key, "HS256")
    jwt.verify_signature(token, key, "HS256")
    rejected({"x": JsonValue.Str(text[:32761])}, key)
    print("encoding resource boundaries: PASS")
