import jwt

def document(str kid, bytes material) -> str:
    return json.dumps(
        JsonValue.Object(
            {
                "kty": JsonValue.Str("oct"),
                "alg": JsonValue.Str("HS256"),
                "kid": JsonValue.Str(kid),
                "k": JsonValue.Str(base64.urlsafe_encode_nopad(material)),
            },
        ),
    )

def bad(str source, bool is_set = False):
    auto caught = False
    try:
        if is_set:
            jwt.load_jwks(source)
        else:
            jwt.load_jwk(source)
    except Exception as e:
        caught = e.startswith("JWKError:")
    assert caught

def main():
    auto kid = "é"
    for i in range(6):
        kid = kid + kid
    auto material = b"0123456789abcdef0123456789abcdef"
    assert len(jwt.load_jwk(document(kid, material)).material) == 32
    bad(document(kid + "é", material))
    auto long_key = b"x"
    for i in range(13):
        long_key = long_key + long_key
    assert len(jwt.load_jwk(document("max", long_key)).material) == 8192
    bad(document("large", long_key + b"x"))
    list[JsonValue] entries = []
    for i in range(64):
        entries.append(json.loads(document(str(i), material)))
    auto text = json.dumps(JsonValue.Object({"keys": JsonValue.Array(entries)}))
    auto loaded_set = jwt.load_jwks(text)
    assert len(loaded_set.keys) == 64
    auto token = jwt.encode_key({"exp": JsonValue.Int(200)}, loaded_set.keys[63])
    assert len(jwt.decode_keyset_at(token, loaded_set, ["HS256"], 100.0)) == 1
    entries.append(json.loads(document("65", material)))
    bad(json.dumps(JsonValue.Object({"keys": JsonValue.Array(entries)})), True)
    loaded_set.keys.append(jwt.Key("65", "HS256", material))
    auto rejected = False
    try:
        jwt.decode_keyset_at(token, loaded_set, ["HS256"], 100.0)
    except Exception as e:
        rejected = e.startswith("JWKError:")
    assert rejected
    auto huge = "x"
    for i in range(20):
        huge = huge + huge
    bad(huge + "x")
    bad(huge + "x", True)
    print("offline JWK resource limits: PASS")
