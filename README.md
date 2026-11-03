# jwt

Pure-Zap JWT creation and verification over stdlib crypto.
Implements [zaplang-io/zap#318](https://github.com/zaplang-io/zap/issues/318).
Development status: compact HMAC foundation; **claims validation is not implemented yet**.

```zap
import jwt

def main():
    auto key = crypto.random_bytes(32)  # Store securely; reuse the trusted key for verification.
    auto token = jwt.encode({"sub": JsonValue.Str("alice")}, key, "HS256")
    auto verified = jwt.verify_signature(token, key, "HS256")
    print(json.dumps(JsonValue.Object(verified.claims)))
```

`encode(claims, key, algorithm, headers={}) -> str` signs a JSON object using
HS256 or HS512. Keys are raw `bytes`, with a minimum length of 32 or 64 bytes
respectively. Generate random keys; a long password does not guarantee entropy.
Optional headers are copied, and cannot override the selected algorithm.
`typ` defaults to `JWT`; `kid`, `typ`, and `cty` must be strings when present.

`verify_signature(token, key, algorithm) -> VerifiedToken` returns `header` and
`claims` maps after signature authentication. The caller must explicitly select
the algorithm from trusted configuration. Verification uses the original encoded
header and payload, including their whitespace and member order.

**This low-level function does not validate expiration, not-before, issuer,
audience, subject, or token type. It is not a complete authentication check.**
The high-level policy API is tracked in [#2](https://github.com/zaplang-io/jwt/issues/2).
Never authorize a request from these claims without applying application policy.
There is no public unverified-claims decode helper.

Parsing rejects padding, non-URL-safe alphabets, noncanonical trailing bits,
invalid UTF-8/JSON, non-object headers/payloads, and duplicate JSON members at any
depth (including escaped equivalent names). Header extensions `crit`, `b64`,
`zip`, `jku`, `x5u`, `jwk`, and `x5c` are rejected. Token content cannot load keys,
read files or cause network requests. Unknown noncritical header fields are
preserved but carry no trust or policy meaning.

Limits: 50,000 compact token bytes; 4,096 decoded header bytes; 32,768 decoded
payload bytes; 32 JSON container levels; 86 encoded signature characters. Signing
uses the same JSON limits. Short/wrong signatures fail authentication. Signature
comparison accumulates XOR differences over the entire fixed-length digest with
no data-dependent early return in Zap source. The current compiler/stdlib does
**not** provide a documented constant-time comparison guarantee; this package
does not claim one. Generated-code auditing/core primitive work is tracked in
[#5](https://github.com/zaplang-io/jwt/issues/5).

Failures raise catchable messages prefixed with `TokenError:`, `AlgorithmError:`,
`HeaderError:`, `KeyError:`, or `SignatureError:`. Treat every failure as rejection;
do not depend on full message text. Signature authentication precedes payload JSON
parsing. Invalid input may fail at the first applicable check.

Supported now: compact JWS with HS256 and HS512. Unsupported: HS384, asymmetric
algorithms, `none`, JWE, detached/unencoded payloads, network JWKS and automatic
key discovery. Asymmetric algorithms require core crypto support and remain
tracked explicitly; HMAC support does not imply RSA/EC/Ed25519 support.

Build sequence (each is an agent-sized M issue including tests and docs):

1. [Compact signing/verification foundation](https://github.com/zaplang-io/jwt/issues/1).
2. [Verified claims and application policy](https://github.com/zaplang-io/jwt/issues/2).
3. [Offline JWK sets and rotation](https://github.com/zaplang-io/jwt/issues/3).
4. [Asymmetric algorithms and public keys](https://github.com/zaplang-io/jwt/issues/4).
5. [Conformance and release readiness](https://github.com/zaplang-io/jwt/issues/5).

Run `sh tools/run-tests.sh` with a codegen-enabled `zap` on PATH (or set `ZAP`).
`--check` checks the frontend only. `sh tools/check-package.sh` checks packaging
and runs an isolated consumer. CI pins the published Zap compiler image. Test
vectors are independently generated with Python stdlib HMAC/SHA-2; reproduce with
`python3 tools/generate-vectors.py` followed by `zap fmt tests`. Python is only a
fixture authoring tool, not a runtime dependency.

References: [JWS](https://www.rfc-editor.org/rfc/rfc7515),
[JWA](https://www.rfc-editor.org/rfc/rfc7518),
[JWT](https://www.rfc-editor.org/rfc/rfc7519),
[JWT security practices](https://www.rfc-editor.org/rfc/rfc8725).
