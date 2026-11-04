import jwt

def reject(
    dict[str, JsonValue] claims,
    jwt.Policy policy,
    str category = "ClaimsError",
):
    auto key = b"0123456789abcdef0123456789abcdef"
    auto caught = False
    auto observed = "accepted"
    try:
        jwt.decode_at(jwt.encode(claims, key, "HS256"), key, "HS256", 100.0, policy)
    except Exception as e:
        observed = e
        caught = e.startswith(category + ":")
    if not caught:
        raise "Expected " + category + ", observed " + observed

def accept(dict[str, JsonValue] claims, jwt.Policy policy):
    auto key = b"0123456789abcdef0123456789abcdef"
    auto token = jwt.encode(claims, key, "HS256")
    auto out = jwt.decode_at(token, key, "HS256", 100.0, policy)
    assert len(out) == len(claims)
    for name in claims:
        assert json.dumps(out[name]) == json.dumps(claims[name])

def main():
    for name in ["iss", "sub", "jti"]:
        for bad in [JsonValue.Null, JsonValue.Bool(False), JsonValue.Int(7), JsonValue.Array([]), JsonValue.Object({})]:
            reject({"exp": JsonValue.Int(200), name: bad}, jwt.Policy())
        auto expected = {name: "chosen"}
        auto policy = jwt.Policy(expected=expected)
        accept({"exp": JsonValue.Int(200), name: JsonValue.Str("chosen")}, policy)
        reject({"exp": JsonValue.Int(200), name: JsonValue.Str("Chosen")}, policy)
        reject({"exp": JsonValue.Int(200)}, policy)
        # Empty expected strings are explicit values, not a disable sentinel.
        accept(
            {"exp": JsonValue.Int(200), name: JsonValue.Str("")},
            jwt.Policy(expected={name: ""}),
        )
        assert len(expected) == 1
    auto policy = jwt.Policy(
        expected={"iss": "issuer", "sub": "alice", "jti": "id-1"},
        audiences=["api"],
        required=["exp", "custom"],
    )
    auto claims = {
        "exp": JsonValue.Int(200),
        "iss": JsonValue.Str("issuer"),
        "sub": JsonValue.Str("alice"),
        "jti": JsonValue.Str("id-1"),
        "aud": JsonValue.Str("api"),
        "custom": json.loads("{\"roles\":[\"reader\"]}"),
    }
    accept(claims, policy)
    accept(claims, policy)
    assert len(policy.expected) == 3
    assert len(policy.required) == 2
    assert len(policy.audiences) == 1
    assert len(claims) == 6
    reject({"exp": JsonValue.Int(200)}, jwt.Policy(required=["exp", "custom"]))
    reject(
        {"exp": JsonValue.Int(200), "custom": JsonValue.Null},
        jwt.Policy(required=["custom"]),
    )
    accept(
        {"exp": JsonValue.Int(200), "custom": JsonValue.Bool(False)},
        jwt.Policy(required=["custom"]),
    )
    reject(
        {"exp": JsonValue.Int(200)},
        jwt.Policy(expected={"other": "x"}),
        "PolicyError",
    )
    reject({"exp": JsonValue.Int(200)}, jwt.Policy(required=[""]), "PolicyError")
    reject({"exp": JsonValue.Int(200)}, jwt.Policy(token_type=""), "PolicyError")
    reject({"exp": JsonValue.Int(200)}, jwt.Policy(audiences=[""]), "PolicyError")
    auto audience_policy = jwt.Policy(audiences=["api", "backup"])
    accept({"exp": JsonValue.Int(200), "aud": JsonValue.Str("api")}, audience_policy)
    accept(
        {
            "exp": JsonValue.Int(200),
            "aud": JsonValue.Array([JsonValue.Str("other"), JsonValue.Str("backup")]),
        },
        audience_policy,
    )
    reject({"exp": JsonValue.Int(200)}, audience_policy)
    reject({"exp": JsonValue.Int(200), "aud": JsonValue.Str("API")}, audience_policy)
    reject({"exp": JsonValue.Int(200), "aud": JsonValue.Str("api")}, jwt.Policy())
    for bad in [JsonValue.Null, JsonValue.Bool(True), JsonValue.Int(1), JsonValue.Str(""), JsonValue.Array([]), JsonValue.Array([JsonValue.Str("api"), JsonValue.Int(1)]), JsonValue.Array([JsonValue.Str("")])]:
        reject({"exp": JsonValue.Int(200), "aud": bad}, audience_policy)
    auto key = b"0123456789abcdef0123456789abcdef"
    auto typed = jwt.encode(
        {"exp": JsonValue.Int(200)},
        key,
        "HS256",
        {"typ": JsonValue.Str("access+jwt")},
    )
    auto out = jwt.decode_at(
        typed,
        key,
        "HS256",
        100.0,
        jwt.Policy(token_type="access+jwt"),
    )
    assert len(out) == 1
    auto wrong_type = False
    try:
        jwt.decode_at(typed, key, "HS256", 100.0)
    except Exception as e:
        wrong_type = e.startswith("ClaimsError:")
    assert wrong_type
    # Signature errors take precedence over absent claims and invalid policies.
    auto bad_signature = False
    try:
        jwt.decode_at(
            jwt.encode({}, key, "HS256"),
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "HS256",
            100.0,
            jwt.Policy(leeway=-1.0),
        )
    except Exception as e:
        bad_signature = e.startswith("SignatureError:")
    assert bad_signature
    # Separate default policies have fresh mutable fields.
    auto first = jwt.Policy()
    auto second = jwt.Policy()
    first.required.append("custom")
    assert len(second.required) == 1
    print("claims application policy: PASS")
