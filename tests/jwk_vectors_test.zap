# Generated independently with Python stdlib by tools/generate-jwk-vectors.py.
import jwt

def main():
    auto loaded32 = jwt.load_jwk(
        "{\"kty\":\"oct\",\"alg\":\"HS256\",\"kid\":\"external-32\",\"k\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY\",\"use\":\"sig\",\"key_ops\":[\"verify\"]}",
    )
    assert loaded32.material == bytes("0123456789abcdef0123456789abcdef")
    assert not loaded32.can_sign and loaded32.can_verify
    auto keys32 = jwt.load_jwks(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"HS256\",\"kid\":\"external-32\",\"k\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY\",\"use\":\"sig\",\"key_ops\":[\"verify\"]}]}",
    )
    auto out32 = jwt.decode_keyset_at(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4dGVybmFsLTMyIn0.eyAic3ViIjogImFsaWNlIiwgImV4cCI6IDIwMCwgInJvbGVzIjogWyJyZWFkZXIiXSB9.QdomAdxAH5435TI544owkYw9ipf6xOrfy4ZaKlgFo8c",
        keys32,
        ["HS256"],
        100.0,
    )
    assert json.dumps(out32["sub"]) == "\"alice\""
    assert json.dumps(out32["roles"]) == "[\"reader\"]"
    auto loaded64 = jwt.load_jwk(
        "{\"kty\":\"oct\",\"alg\":\"HS512\",\"kid\":\"external-64\",\"k\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZg\",\"use\":\"sig\",\"key_ops\":[\"verify\"]}",
    )
    assert loaded64.material == bytes("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    assert not loaded64.can_sign and loaded64.can_verify
    auto keys64 = jwt.load_jwks(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"HS512\",\"kid\":\"external-64\",\"k\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZg\",\"use\":\"sig\",\"key_ops\":[\"verify\"]}]}",
    )
    auto out64 = jwt.decode_keyset_at(
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6ImV4dGVybmFsLTY0In0.eyAic3ViIjogImFsaWNlIiwgImV4cCI6IDIwMCwgInJvbGVzIjogWyJyZWFkZXIiXSB9.GvyISp2e6Ezx_97GlQ0bGOWExi9QNpyWovz02a3Wwp6F5a5vqE38M4cKkI5K4Qvc2aawLsMaVjCYj30UO8L0Xw",
        keys64,
        ["HS512"],
        100.0,
    )
    assert json.dumps(out64["sub"]) == "\"alice\""
    assert json.dumps(out64["roles"]) == "[\"reader\"]"
    print("independent oct JWK vectors: PASS")
