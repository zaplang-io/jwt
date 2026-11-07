# Pins the exact error ordering of the JWK metadata parsers so the unified
# `_jwk_meta_from` tail (issue #11 item 4) can never silently reorder checks.
# The oct path reads its secret (`k`) before the shared extension/use/key_ops
# tail; the asymmetric paths read their components after it. Both orderings are
# asserted here by exact error message, not merely the `JWKError:` prefix.
import jwt

def oct_base() -> dict[str, JsonValue]:
    auto secret = b"0123456789abcdef0123456789abcdef"
    return {
        "kty": JsonValue.Str("oct"),
        "kid": JsonValue.Str("k1"),
        "alg": JsonValue.Str("HS256"),
        "k": JsonValue.Str(base64.urlsafe_encode_nopad(secret)),
    }

def rsa_base() -> dict[str, JsonValue]:
    return {
        "kty": JsonValue.Str("RSA"),
        "kid": JsonValue.Str("k1"),
        "alg": JsonValue.Str("RS256"),
    }

def ec_base() -> dict[str, JsonValue]:
    return {
        "kty": JsonValue.Str("EC"),
        "kid": JsonValue.Str("k1"),
        "alg": JsonValue.Str("ES256"),
    }

def okp_base() -> dict[str, JsonValue]:
    return {
        "kty": JsonValue.Str("OKP"),
        "kid": JsonValue.Str("k1"),
        "alg": JsonValue.Str("EdDSA"),
    }

# Copy every member except one, mirroring a JWK that simply omits that field.
def without(dict[str, JsonValue] fields, str drop) -> dict[str, JsonValue]:
    dict[str, JsonValue] out = {}
    for name in fields:
        if name != drop:
            out[name] = fields[name]
    return out

def expect(dict[str, JsonValue] fields, str message):
    auto observed = "accepted"
    try:
        jwt.load_jwk(json.dumps(JsonValue.Object(fields)))
    except Exception as e:
        observed = e
    if observed != message:
        raise "want [" + message + "] got [" + observed + "]"

def expect_keyset(str token, jwt.KeySet keys, list[str] algorithms, str message):
    auto observed = "accepted"
    try:
        jwt.decode_keyset_at(token, keys, algorithms, 100.0)
    except Exception as e:
        observed = e
    if observed != message:
        raise "want [" + message + "] got [" + observed + "]"

def main():
    # Valid oct keys still load through the refactored path.
    auto good = jwt.load_jwk(json.dumps(JsonValue.Object(oct_base())))
    assert good.kid == "k1" and good.algorithm == "HS256"
    assert good.can_sign and good.can_verify
    # key_ops narrows capability through the shared metadata tail.
    auto narrowed_fields = oct_base()
    narrowed_fields["key_ops"] = JsonValue.Array([JsonValue.Str("verify")])
    auto narrowed = jwt.load_jwk(json.dumps(JsonValue.Object(narrowed_fields)))
    assert not narrowed.can_sign and narrowed.can_verify
    # oct ordering: kty, kid, alg, k presence, k size, then the shared tail.
    auto unknown_kty = oct_base()
    unknown_kty["kty"] = JsonValue.Str("DES")
    expect(unknown_kty, "JWKError: only oct keys are supported")
    expect(without(oct_base(), "kid"), "JWKError: missing required key member kid")
    expect(without(oct_base(), "alg"), "JWKError: missing required key member alg")
    # k presence beats the extension rejection.
    auto no_k = without(oct_base(), "k")
    no_k["x5c"] = JsonValue.Str("x")
    expect(no_k, "JWKError: missing required key member k")
    # k size beats the extension rejection.
    auto big = "A"
    for i in range(14):
        big = big + big
    auto huge_k = oct_base()
    huge_k["k"] = JsonValue.Str(big)
    huge_k["x5c"] = JsonValue.Str("x")
    expect(huge_k, "JWKError: encoded key material exceeds its limit")
    # The shared tail: extension beats use, use beats key_ops.
    auto ext = oct_base()
    ext["x5c"] = JsonValue.Str("x")
    ext["use"] = JsonValue.Str("enc")
    expect(ext, "JWKError: unsupported key reference or extension")
    auto use_first = oct_base()
    use_first["use"] = JsonValue.Str("enc")
    use_first["key_ops"] = JsonValue.Int(1)
    expect(use_first, "JWKError: key use must be sig")
    auto bad_ops = oct_base()
    bad_ops["key_ops"] = JsonValue.Int(1)
    expect(bad_ops, "JWKError: key_ops must be an array")
    # RSA ordering: _jwk_meta (kid, alg, shared tail) runs before the algorithm
    # value check, which runs before private-member rejection and component reads.
    expect(without(rsa_base(), "kid"), "JWKError: missing required key member kid")
    expect(without(rsa_base(), "alg"), "JWKError: missing required key member alg")
    # The same shared tail used by oct fires on the asymmetric path too.
    auto rsa_ext = rsa_base()
    rsa_ext["x5c"] = JsonValue.Str("x")
    expect(rsa_ext, "JWKError: unsupported key reference or extension")
    # Wrong algorithm is caught before the private-member sweep.
    auto rsa_wrong_alg = rsa_base()
    rsa_wrong_alg["alg"] = JsonValue.Str("HS256")
    rsa_wrong_alg["d"] = JsonValue.Str("AA")
    expect(rsa_wrong_alg, "JWKError: RSA keys require the RS256 algorithm")
    # Private members are rejected before any component is read.
    auto rsa_private = rsa_base()
    rsa_private["d"] = JsonValue.Str("AA")
    expect(rsa_private, "JWKError: only public keys are supported")
    expect(rsa_base(), "JWKError: missing required key member n")
    # EC ordering: algorithm value, then curve, then private members.
    auto ec_wrong_alg = ec_base()
    ec_wrong_alg["alg"] = JsonValue.Str("RS256")
    expect(ec_wrong_alg, "JWKError: EC keys require the ES256 algorithm")
    expect(ec_base(), "JWKError: missing required key member crv")
    auto ec_private = ec_base()
    ec_private["crv"] = JsonValue.Str("P-256")
    ec_private["d"] = JsonValue.Str("AA")
    expect(ec_private, "JWKError: only public keys are supported")
    # OKP ordering: curve, then private members.
    expect(okp_base(), "JWKError: missing required key member crv")
    auto okp_private = okp_base()
    okp_private["crv"] = JsonValue.Str("Ed25519")
    okp_private["d"] = JsonValue.Str("AA")
    expect(okp_private, "JWKError: only public keys are supported")
    # Dead-code removal regression (#11 item 5): `_require_algorithm` still
    # rejects an unsupported algorithm on the key-set allowlist path, even though
    # its unreachable `if len(family) == 0` guard is gone.
    auto token = jwt.encode_key({"exp": JsonValue.Int(200)}, good)
    auto keyset = jwt.KeySet([good])
    auto bad_alg = "AlgorithmError: supported algorithms are HS256, HS512, RS256, ES256 and EdDSA"
    expect_keyset(token, keyset, ["BOGUS"], bad_alg)
    print("JWK parser error ordering: PASS")
