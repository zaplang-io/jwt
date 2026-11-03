#!/bin/sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/jwt-tests.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM
cp "$root/src/jwt.zap" "$build/jwt.zap"
for source in "$root"/tests/*_test.zap; do
    cp "$source" "$build/main.zap"
    if [ "${1:-}" = --check ]; then
        "${ZAP:-zap}" ir "$build/main.zap" > /dev/null
    else
        "${ZAP:-zap}" run "$build/main.zap"
    fi
done
