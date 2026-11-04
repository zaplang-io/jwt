#!/usr/bin/env python3
"""Reproduce offline oct JWK fixtures with Python stdlib, independently of Zap."""
import base64
import hashlib
import hmac
import json
from pathlib import Path


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def compact(value):
    return json.dumps(value, separators=(',', ':'))


out = ['# Generated independently with Python stdlib by tools/generate-jwk-vectors.py.',
       'import jwt', '', 'def main():']
for alg, size, digest in [('HS256', 32, hashlib.sha256), ('HS512', 64, hashlib.sha512)]:
    key = b'0123456789abcdef' * (size // 16)
    kid = f'external-{size}'
    record = {'kty': 'oct', 'alg': alg, 'kid': kid, 'k': b64(key), 'use': 'sig', 'key_ops': ['verify']}
    header = compact({'alg': alg, 'typ': 'JWT', 'kid': kid})
    payload = '{ "sub": "alice", "exp": 200, "roles": ["reader"] }'
    message = b64(header.encode()) + '.' + b64(payload.encode())
    token = message + '.' + b64(hmac.new(key, message.encode(), digest).digest())
    q = json.dumps
    out += [f'    auto loaded{size} = jwt.load_jwk({q(compact(record))})',
            f'    assert loaded{size}.material == bytes({q(key.decode())})',
            f'    assert not loaded{size}.can_sign and loaded{size}.can_verify',
            f'    auto keys{size} = jwt.load_jwks({q(compact({"keys": [record]}))})',
            f'    auto out{size} = jwt.decode_keyset_at({q(token)}, keys{size}, ["{alg}"], 100.0)',
            f'    assert json.dumps(out{size}["sub"]) == "\\\"alice\\\""',
            f'    assert json.dumps(out{size}["roles"]) == "[\\\"reader\\\"]"']
out += ['    print("independent oct JWK vectors: PASS")', '']
Path(__file__).resolve().parents[1].joinpath('tests/jwk_vectors_test.zap').write_text('\n'.join(out))
