#!/bin/sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
zap=${ZAP:-zap}
case "$zap" in
    /*) ;;
    */*) zap=$(cd "$(dirname "$zap")" && pwd)/$(basename "$zap") ;;
esac
build=$(mktemp -d "${TMPDIR:-/tmp}/jwt-package.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM
(cd "$root" && "$zap" publish --dry-run)
mkdir -p "$build/src"
cat > "$build/zap.toml" <<MANIFEST
[package]
name = "jwt_consumer"
version = "0.1.0"
[dependencies]
jwt = { path = "$root" }
MANIFEST
cat > "$build/src/main.zap" <<'ZAP'
import jwt

def main():
    auto key = b"0123456789abcdef0123456789abcdef"
    auto token = jwt.encode({"sub": JsonValue.Str("consumer")}, key, "HS256")
    auto verified = jwt.verify_signature(token, key, "HS256")
    assert json.dumps(verified.claims["sub"]) == "\"consumer\""
    auto policy = jwt.Policy(expected={"iss": "issuer"}, audiences=["api"], required=["exp", "sub"])
    auto signed = jwt.encode({"iss": JsonValue.Str("issuer"), "sub": JsonValue.Str("consumer"), "aud": JsonValue.Str("api"), "exp": JsonValue.Int(200)}, key, "HS256")
    auto claims = jwt.decode_at(signed, key, "HS256", 100.0, policy)
    assert json.dumps(claims["sub"]) == "\"consumer\""
    auto key_json = json.dumps(JsonValue.Object({"kty": JsonValue.Str("oct"), "alg": JsonValue.Str("HS256"), "kid": JsonValue.Str("consumer-1"), "k": JsonValue.Str(base64.urlsafe_encode_nopad(key))}))
    auto loaded = jwt.load_jwk(key_json)
    auto trusted = jwt.load_jwks("{\"keys\":[" + key_json + "]}")
    auto rotated = jwt.encode_key({"iss": JsonValue.Str("issuer"), "sub": JsonValue.Str("consumer"), "aud": JsonValue.Str("api"), "exp": JsonValue.Int(200)}, loaded)
    auto selected = jwt.decode_keyset_at(rotated, trusted, ["HS256"], 100.0, policy)
    assert json.dumps(selected["sub"]) == "\"consumer\""
    print("isolated package consumer: PASS")
ZAP
(cd "$build" && "$zap" zenv create --no-venv && ZAP_ZENV="$build/zenv" "$zap" run src/main.zap)
