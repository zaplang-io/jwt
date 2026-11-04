import jwt

def record(
    str kid = "old",
    str algorithm = "HS256",
    bytes material = b"0123456789abcdef0123456789abcdef",
) -> dict[str, JsonValue]:
    return {
        "kid": JsonValue.Str(kid),
        "alg": JsonValue.Str(algorithm),
        "kty": JsonValue.Str("oct"),
        "k": JsonValue.Str(base64.urlsafe_encode_nopad(material)),
    }

def load(dict[str, JsonValue] fields) -> jwt.Key:
    return jwt.load_jwk(json.dumps(JsonValue.Object(fields)))

def bad_record(dict[str, JsonValue] fields):
    auto caught = False
    try:
        load(fields)
    except Exception as e:
        caught = e.startswith("JWKError:")
    assert caught

def bad_document(str source, bool is_set = False):
    auto caught = False
    try:
        if is_set:
            jwt.load_jwks(source)
        else:
            jwt.load_jwk(source)
    except Exception as e:
        caught = e.startswith("JWKError:")
    assert caught

def bad_token(
    str token,
    jwt.KeySet keys,
    str category,
    list[str] algorithms = ["HS256"],
):
    auto caught = False
    auto observed = "accepted"
    try:
        jwt.decode_keyset_at(token, keys, algorithms, 100.0)
    except Exception as e:
        observed = e
        caught = e.startswith(category + ":")
    if not caught:
        raise "Expected " + category + ", observed " + observed

def bad_sign(jwt.Key key, dict[str, JsonValue] headers = {}):
    auto caught = False
    try:
        jwt.encode_key({}, key, headers)
    except Exception as e:
        caught = e.startswith("JWKError:") or e.startswith("AlgorithmError:")
    assert caught

def raw(dict[str, JsonValue] header, bytes key) -> str:
    auto message = base64.urlsafe_encode_nopad(json.dumps(JsonValue.Object(header))) + "." + base64.urlsafe_encode_nopad("{\"exp\":200}")
    return message + "." + base64.urlsafe_encode_nopad(crypto.hmac_sha256_raw(key, message))

def main():
    auto old = load(record())
    auto newer = load(record("new", "HS256", b"fedcba9876543210fedcba9876543210"))
    auto key512 = load(
        record(
            "wide",
            "HS512",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
    )
    assert old.kid == "old"
    assert old.algorithm == "HS256"
    assert old.material == b"0123456789abcdef0123456789abcdef"
    assert old.can_sign and old.can_verify
    auto overlapping = jwt.KeySet([old, newer, key512])
    auto before = jwt.KeySet([old])
    auto after = jwt.KeySet([newer])
    auto claims = {"exp": JsonValue.Int(200)}
    auto old_token = jwt.encode_key(claims, old)
    auto new_token = jwt.encode_key(claims, newer)
    auto wide_token = jwt.encode_key(claims, key512)
    assert len(jwt.decode_keyset_at(old_token, before, ["HS256"], 100.0)) == 1
    assert len(jwt.decode_keyset_at(old_token, overlapping, ["HS256"], 100.0)) == 1
    assert len(jwt.decode_keyset_at(new_token, overlapping, ["HS256"], 100.0)) == 1
    assert len(jwt.decode_keyset_at(new_token, after, ["HS256"], 100.0)) == 1
    assert len(jwt.decode_keyset_at(wide_token, overlapping, ["HS256", "HS512"], 100.0)) == 1
    bad_token(old_token, after, "KeySelectionError")
    bad_token(new_token, before, "KeySelectionError")
    bad_token(wide_token, overlapping, "AlgorithmError")
    bad_token(old_token, overlapping, "AlgorithmError", [])
    bad_token(old_token, overlapping, "AlgorithmError", ["HS256", "HS256"])
    bad_token(old_token, overlapping, "AlgorithmError", ["RS256"])
    auto fields = record()
    fields["use"] = JsonValue.Str("sig")
    fields["key_ops"] = JsonValue.Array([JsonValue.Str("verify")])
    auto verify_only = load(fields)
    bad_sign(verify_only)
    assert len(jwt.decode_keyset_at(old_token, jwt.KeySet([verify_only]), ["HS256"], 100.0)) == 1
    fields["key_ops"] = JsonValue.Array([JsonValue.Str("sign")])
    auto sign_only = load(fields)
    jwt.encode_key(claims, sign_only)
    bad_token(old_token, jwt.KeySet([sign_only]), "KeySelectionError")
    fields["key_ops"] = JsonValue.Array(
        [JsonValue.Str("sign"), JsonValue.Str("verify")],
    )
    auto both = load(fields)
    assert both.can_sign and both.can_verify
    for name in ["kty", "kid", "alg", "k"]:
        for value in [JsonValue.Null, JsonValue.Bool(True), JsonValue.Int(1), JsonValue.Array([]), JsonValue.Object({}), JsonValue.Str("")]:
            auto invalid = record()
            invalid[name] = value
            bad_record(invalid)
    for missing_name in ["kty", "kid", "alg", "k"]:
        dict[str, JsonValue] missing = {}
        auto original = record()
        for name in original:
            if name != missing_name:
                missing[name] = original[name]
        bad_record(missing)
    bad_record({})
    for algorithm in ["none", "RS256", "ES256", "HS384", "hs256"]:
        bad_record(record("bad", algorithm))
    auto unsupported = record()
    unsupported["kty"] = JsonValue.Str("RSA")
    bad_record(unsupported)
    bad_record(record("short", "HS256", b"short"))
    bad_record(record("short512", "HS512", old.material))
    for value in [JsonValue.Str("enc"), JsonValue.Null, JsonValue.Bool(True), JsonValue.Int(1)]:
        auto invalid = record()
        invalid["use"] = value
        bad_record(invalid)
    for value in [JsonValue.Null, JsonValue.Str("verify"), JsonValue.Array([]), JsonValue.Array([JsonValue.Int(1)]), JsonValue.Array([JsonValue.Str("encrypt")]), JsonValue.Array([JsonValue.Str("verify"), JsonValue.Str("verify")]), JsonValue.Array([JsonValue.Str("verify"), JsonValue.Str("decrypt")])]:
        auto invalid = record()
        invalid["key_ops"] = value
        bad_record(invalid)
    for name in ["x5u", "x5c", "x5t", "x5t#S256", "jku", "jwk", "crit", "b64"]:
        auto invalid = record()
        invalid[name] = JsonValue.Str("https://attacker.invalid/key")
        bad_record(invalid)
    for encoded in ["", "AA=", "AA+", "AA/", "AA A", "AB", "A", "é"]:
        auto invalid = record()
        invalid["k"] = JsonValue.Str(encoded)
        bad_record(invalid)
    for encoded in [base64.urlsafe_encode_nopad(old.material) + "=", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"]:
        auto invalid = record()
        invalid["k"] = JsonValue.Str(encoded)
        bad_record(invalid)
    for text in ["", "{", "[]", "null", "{}{}", "{\"kty\":\"oct\",\"kty\":\"oct\"}", "{\"kty\":\"oct\",\"\\u006bty\":\"oct\"}"]:
        bad_document(text)
        bad_document(text, True)
    for text in ["{}", "{\"keys\":null}", "{\"keys\":{}}", "{\"keys\":[]}", "{\"keys\":[1]}"]:
        bad_document(text, True)
    auto document = "{\"keys\":[" + json.dumps(JsonValue.Object(record())) + "," + json.dumps(JsonValue.Object(record("new", "HS256", newer.material))) + "]}"
    auto loaded = jwt.load_jwks(document)
    assert len(loaded.keys) == 2
    jwt.decode_keyset_at(new_token, loaded, ["HS256"], 100.0)
    bad_document(
        "{\"keys\":[" + json.dumps(JsonValue.Object(record())) + "," + json.dumps(JsonValue.Object(record())) + "]}",
        True,
    )
    bad_token(old_token, jwt.KeySet([old, old]), "JWKError")
    bad_token(old_token, jwt.KeySet(), "JWKError")
    bad_token(
        old_token,
        jwt.KeySet([jwt.Key("alias", "HS256", key512.material), key512]),
        "JWKError",
        ["HS256", "HS512"],
    )
    loaded.keys.append(old)
    bad_token(old_token, loaded, "JWKError")
    bad_sign(old, {"kid": JsonValue.Str("different")})
    bad_sign(old, {"kid": JsonValue.Int(1)})
    bad_sign(old, {"alg": JsonValue.Str("HS512")})
    auto headers = {"typ": JsonValue.Str("JWT")}
    jwt.encode_key(claims, old, headers)
    assert len(headers) == 1
    assert len(claims) == 1
    auto header = {"alg": JsonValue.Str("HS256"), "typ": JsonValue.Str("JWT")}
    bad_token(raw(header, old.material), before, "KeySelectionError")
    header["kid"] = JsonValue.Str("")
    bad_token(raw(header, old.material), before, "KeySelectionError")
    header["kid"] = JsonValue.Int(1)
    bad_token(raw(header, old.material), before, "HeaderError")
    for kid in ["unknown", "../../secrets", "https://attacker.invalid/key"]:
        header["kid"] = JsonValue.Str(kid)
        bad_token(raw(header, old.material), before, "KeySelectionError")
    header["kid"] = JsonValue.Str("old")
    # The other configured key would verify; never fall back after kid selection.
    bad_token(raw(header, newer.material), overlapping, "SignatureError")
    header["kid"] = JsonValue.Str("wide")
    bad_token(
        raw(header, key512.material),
        overlapping,
        "AlgorithmError",
        ["HS256", "HS512"],
    )
    for name in ["jku", "x5u", "jwk", "x5c", "crit", "b64", "zip"]:
        auto hostile = {
            "alg": JsonValue.Str("HS256"),
            "typ": JsonValue.Str("JWT"),
            "kid": JsonValue.Str("old"),
            name: JsonValue.Str("https://attacker.invalid/key"),
        }
        bad_token(raw(hostile, old.material), before, "HeaderError")
    auto expired = jwt.encode_key({"exp": JsonValue.Int(0)}, old)
    bad_token(expired, before, "ClaimsError")
    assert len(jwt.verify_keyset_signature(expired, before, ["HS256"]).claims) == 1
    auto profiled = jwt.encode_key(
        {
            "exp": JsonValue.Int(200),
            "iss": JsonValue.Str("issuer"),
            "aud": JsonValue.Str("api"),
        },
        old,
        {"typ": JsonValue.Str("access+jwt")},
    )
    auto policy = jwt.Policy(
        expected={"iss": "issuer"},
        audiences=["api"],
        token_type="access+jwt",
    )
    auto single = jwt.decode_at(profiled, old.material, "HS256", 100.0, policy)
    auto multiple = jwt.decode_keyset_at(profiled, before, ["HS256"], 100.0, policy)
    assert len(single) == len(multiple)
    for name in single:
        assert json.dumps(single[name]) == json.dumps(multiple[name])
    bad_token(profiled, before, "ClaimsError")
    auto future = jwt.encode_key({"exp": JsonValue.Int(9007199254740991)}, old)
    assert len(jwt.decode_keyset(future, before, ["HS256"])) == 1
    print("offline JWK metadata, selection and rotation: PASS")
