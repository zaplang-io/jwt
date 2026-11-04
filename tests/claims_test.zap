import jwt
import math

def token(dict[str, JsonValue] claims) -> str:
    return jwt.encode(claims, b"0123456789abcdef0123456789abcdef", "HS256")

def accept(dict[str, JsonValue] claims, float64 now, jwt.Policy policy = jwt.Policy()):
    auto encoded = token(claims)
    auto out = jwt.decode_at(
        encoded,
        b"0123456789abcdef0123456789abcdef",
        "HS256",
        now,
        policy,
    )
    assert len(out) == len(claims)
    for name in claims:
        assert json.dumps(out[name]) == json.dumps(claims[name])

def reject(
    dict[str, JsonValue] claims,
    float64 now,
    jwt.Policy policy = jwt.Policy(),
    str category = "ClaimsError",
):
    auto caught = False
    auto observed = "accepted"
    try:
        jwt.decode_at(
            token(claims),
            b"0123456789abcdef0123456789abcdef",
            "HS256",
            now,
            policy,
        )
    except Exception as e:
        observed = e
        caught = e.startswith(category + ":")
    if not caught:
        raise "Expected " + category + ", observed " + observed

def main():
    accept({"exp": JsonValue.Int(101)}, 100.0)
    reject({"exp": JsonValue.Int(100)}, 100.0)
    reject({"exp": JsonValue.Int(99)}, 100.0)
    reject({}, 100.0)
    accept({}, 100.0, jwt.Policy(required=[]))
    # Explicitly allowing absence never disables validation of present dates.
    reject({"exp": JsonValue.Int(0)}, 100.0, jwt.Policy(required=[]))
    for name in ["exp", "nbf", "iat"]:
        for bad in [JsonValue.Null, JsonValue.Bool(True), JsonValue.Str("100"), JsonValue.Array([]), JsonValue.Object({})]:
            auto claims = {"exp": JsonValue.Int(200)}
            claims[name] = bad
            reject(claims, 100.0)
        auto claims = {"exp": JsonValue.Int(200)}
        claims[name] = JsonValue.Int(9007199254740992)
        reject(claims, 100.0)
        claims[name] = JsonValue.Int(-9007199254740992)
        reject(claims, 100.0)
    accept({"exp": JsonValue.Float(100.25)}, 100.0)
    reject({"exp": JsonValue.Float(100.25)}, 100.25)
    accept({"exp": JsonValue.Float(100.25)}, 100.5, jwt.Policy(leeway=0.5))
    reject({"exp": JsonValue.Float(100.25)}, 100.75, jwt.Policy(leeway=0.5))
    for name in ["nbf", "iat"]:
        auto claims = {"exp": JsonValue.Int(200)}
        claims[name] = JsonValue.Int(100)
        accept(claims, 100.0)
        claims[name] = JsonValue.Float(100.25)
        reject(claims, 100.0)
        accept(claims, 100.0, jwt.Policy(leeway=0.25))
        reject(claims, 99.75, jwt.Policy(leeway=0.25))
        claims[name] = JsonValue.Int(99)
        accept(claims, 100.0)
    accept({"exp": JsonValue.Int(0)}, -0.25)
    reject({"exp": JsonValue.Int(0)}, 0.0)
    accept({"exp": JsonValue.Int(9007199254740991)}, 9007199254740990.0)
    reject({"exp": JsonValue.Int(9007199254740991)}, 9007199254740991.0)
    accept(
        {"exp": JsonValue.Int(9007199254740991)},
        9007199254740991.0,
        jwt.Policy(leeway=0.25),
    )
    reject({"exp": JsonValue.Int(-9007199254740991)}, 9007199254740991.0)
    reject(
        {
            "exp": JsonValue.Int(9007199254740991),
            "nbf": JsonValue.Int(9007199254740991),
        },
        -9007199254740991.0,
    )
    for leeway in [-0.25, 86400.25, math.sqrt(-1.0), math.exp(1000.0)]:
        reject(
            {"exp": JsonValue.Int(200)},
            100.0,
            jwt.Policy(leeway=leeway),
            "PolicyError",
        )
    for now in [math.sqrt(-1.0), math.exp(1000.0), 9007199254740992.0]:
        reject({"exp": JsonValue.Int(200)}, now, jwt.Policy(), "PolicyError")
    accept({"exp": JsonValue.Int(0)}, 86399.0, jwt.Policy(leeway=86400.0))
    reject({"exp": JsonValue.Int(0)}, 86400.0, jwt.Policy(leeway=86400.0))
    # Real-clock entry point: far-future expiration and a definitely expired token.
    jwt.decode(
        token({"exp": JsonValue.Int(9007199254740991)}),
        b"0123456789abcdef0123456789abcdef",
        "HS256",
    )
    auto expired = False
    try:
        jwt.decode(
            token({"exp": JsonValue.Int(0)}),
            b"0123456789abcdef0123456789abcdef",
            "HS256",
        )
    except Exception as e:
        expired = e.startswith("ClaimsError:")
    assert expired
    print("claims time boundaries: PASS")
