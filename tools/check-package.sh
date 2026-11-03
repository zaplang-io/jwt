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
    print("isolated package consumer: PASS")
ZAP
(cd "$build" && "$zap" zenv create --no-venv && ZAP_ZENV="$build/zenv" "$zap" run src/main.zap)
