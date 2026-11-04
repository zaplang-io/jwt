# jwt

Pure-Zap JWT creation and verification over stdlib crypto.
Implements [zaplang-io/zap#318](https://github.com/zaplang-io/zap/issues/318).
Development status: compact HMAC signing, authenticated claims, and offline JWK rotation.

```zap
import jwt

def main():
    auto key = crypto.random_bytes(32)  # Store securely and reuse the trusted key.
    auto expires = int64(time.time()) + 300
    auto token = jwt.encode({"iss": JsonValue.Str("https://issuer.example"), "sub": JsonValue.Str("alice"), "aud": JsonValue.Str("api"), "exp": JsonValue.Int(expires)}, key, "HS256", {"typ": JsonValue.Str("access+jwt")})
    auto policy = jwt.Policy(expected={"iss": "https://issuer.example"}, audiences=["api"], required=["exp", "sub"], token_type="access+jwt")
    auto claims = jwt.decode(token, key, "HS256", policy)
    print(json.dumps(claims["sub"]))
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

**The low-level `verify_signature` function does not validate expiration,
not-before, issuer, audience, subject, or token type.** Use `decode` with an
application policy for authentication. There is no public unverified-claims
decode helper.

`decode(token, key, algorithm, policy=Policy()) -> dict[str, JsonValue]` first
authenticates the signature, then validates registered claims and application
policy before returning claims. `decode_at(token, key, algorithm, now,
policy=Policy())` accepts trusted Unix seconds for a deterministic/injected
clock. `decode` samples the wall clock once after signature verification.
A bad signature takes precedence over claim, clock, and policy errors.

`Policy` fields:

- `required=["exp"]`: claim names that must be present and non-null. Set `[]`
  explicitly to allow absent expiration. Present `exp`, `nbf`, and `iat` are
  always validated, even when absent from this list. Other custom required values
  may be false, zero, or empty containers; only missing/null fails presence.
- `expected={}`: exact string values for `iss`, `sub`, and/or `jti`. Configured
  claims become required. Unknown configuration keys raise `PolicyError`.
  Empty expected strings are explicit values, not disable sentinels.
- `audiences=[]`: acceptable recipient identifiers. A present `aud` requires a
  configured expected audience; a configured audience requires `aud`. A nonempty
  string or nonempty string array is accepted if any recipient matches any
  expected audience. Empty strings, mixed arrays, and coercion are rejected.
- `token_type="JWT"`: required exact `typ` header. Use distinct types such as
  `access+jwt` for application profiles. Missing/mismatched types are rejected;
  an empty configured type is invalid.
- `leeway=0.0`: finite tolerance from 0 through 86,400 seconds, inclusive.

All matches are case-sensitive, with no URI normalization or coercion. Present
`iss`, `sub`, and `jti` must be strings even without expected values. The decoder
preserves unknown application claims and never mutates caller policy/maps.
String identity and audience validation do not establish application permissions;
apply those rules to the returned claims. `jti` matching does not maintain a
replay cache.

NumericDate accepts JSON integers and finite binary64 fractions in the range
`[-9007199254740991, 9007199254740991]` seconds. Integers outside that range are
rejected before float conversion. Fractions retain binary64 precision, with no
integer truncation or rounding tolerance. `exp` rejects at the exact expiration
boundary; `nbf` and this profile's future-`iat` check permit equality. With leeway,
expiration rejects when `now >= exp` and `now - exp >= leeway`; future dates
reject when `date > now` and `date - now > leeway`. This avoids adding leeway to
large dates or overflowing integer arithmetic. Unsupported clock values and
invalid leeway raise `PolicyError`; invalid registered claims raise `ClaimsError`.
Malformed/nonfinite JSON remains a `TokenError` at the transport layer.

The defaults require expiration and a `JWT` type. Issuer, subject and recipient
expectations are application-specific; configure them as in the example. No
policy option disables signature verification.
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
`HeaderError:`, `KeyError:`, `SignatureError:`, `ClaimsError:`, `PolicyError:`,
`JWKError:`, or `KeySelectionError:`. Treat every failure as rejection;
do not depend on full message text. Signature authentication precedes payload JSON
parsing. Invalid input may fail at the first applicable check.

Supported now: compact JWS with HS256 and HS512. Unsupported: HS384, asymmetric
algorithms, `none`, JWE, detached/unencoded payloads, network JWKS and automatic
key discovery. Trusted offline oct JWK/JWKS is supported below. Asymmetric algorithms require core crypto support and remain
tracked explicitly; HMAC support does not imply RSA/EC/Ed25519 support.

For trusted offline key configuration, `load_jwk(json_text) -> Key` and
`load_jwks(json_text) -> KeySet` validate oct JWKs. An oct JWK contains the shared
secret: keep these documents private, rather than publishing them as a public
JWKS endpoint. Load explicitly trusted configuration; token headers never supply
key documents or locations.

This profile requires nonempty `kid`, explicit `alg` (`HS256` or `HS512`),
`kty="oct"`, and canonical unpadded base64url `k`. HMAC minimum key sizes remain
32/64 bytes. Optional `use` must be `sig`; optional `key_ops` must be a nonempty
array of unique `sign` and/or `verify` values. Absent `key_ops` permits both;
present operations are enforced by the key-based APIs. Unsupported key types,
algorithms, certificate/reference fields and critical extensions are rejected.
Unknown other metadata is ignored. Duplicate JSON members at any depth fail.

`Key` exposes `kid`, `algorithm`, `material` (raw bytes), `can_sign`, and
`can_verify`; `KeySet` holds `keys`. These are trusted, mutable configuration
objects, not opaque secret vaults. Key-set operations revalidate configuration
on each use, including directly constructed or mutated sets. IDs must be unique,
and identical material cannot be bound to different algorithms within one set.
Limits are 64 keys, 128 UTF-8 bytes per ID, 8,192 raw bytes per key, and 1 MiB per
loaded JSON document; the existing 32-level JSON nesting limit also applies.
An empty set is invalid. Replacing a whole loaded set makes rotation explicit.

`encode_key(claims, key, headers={})` checks signing permission, supplies `kid`
and the bound algorithm, and rejects conflicting supplied headers.
`verify_keyset_signature(token, keys, algorithms)` selects one key and returns
`VerifiedToken` after signature authentication, without claims validation.
`decode_keyset(token, keys, algorithms, policy=Policy())` and
`decode_keyset_at(token, keys, algorithms, now, policy=Policy())` apply the same
claims policy as their single-key counterparts. The caller must supply a
nonempty unique allowlist of supported algorithms; a token cannot widen it.

Selection requires exactly one configured `kid`, the key's bound algorithm must
match both the token and the caller's allowlist, and the key must permit verify.
Missing/empty/unknown IDs or verification-disallowed keys raise
`KeySelectionError`. Malformed key documents/configurations raise `JWKError`;
algorithm policy violations raise `AlgorithmError`. A malformed header retains
its existing error category. Failure never falls back to another key, fetches a
URL, reads a path from `kid`, or updates a hidden cache. All selected signatures
and claims still pass through the existing verification functions.

A rotation overlap can accept the old and new keys while the issuer signs with
the new key. Remove the old key after the intended overlap window:

```zap
import jwt

def jwk_json(str kid, bytes material) -> str:
    return json.dumps(JsonValue.Object({"kty": JsonValue.Str("oct"), "alg": JsonValue.Str("HS256"), "kid": JsonValue.Str(kid), "k": JsonValue.Str(base64.urlsafe_encode_nopad(material))}))

def main():
    auto old_json = jwk_json("old", crypto.random_bytes(32))
    auto new_json = jwk_json("new", crypto.random_bytes(32))
    auto old_key = jwt.load_jwk(old_json)
    auto new_key = jwt.load_jwk(new_json)
    auto claims = {"exp": JsonValue.Int(200), "iss": JsonValue.Str("issuer"), "aud": JsonValue.Str("api")}
    auto old_token = jwt.encode_key(claims, old_key)
    auto new_token = jwt.encode_key(claims, new_key)
    auto overlap = jwt.load_jwks("{\"keys\":[" + old_json + "," + new_json + "]}")
    auto policy = jwt.Policy(expected={"iss": "issuer"}, audiences=["api"])
    jwt.decode_keyset_at(old_token, overlap, ["HS256"], 100.0, policy)
    jwt.decode_keyset_at(new_token, overlap, ["HS256"], 100.0, policy)
    auto retired = jwt.load_jwks("{\"keys\":[" + new_json + "]}")
    jwt.decode_keyset_at(new_token, retired, ["HS256"], 100.0, policy)
    # old_token now fails KeySelectionError with the retired set.
```

The fixed time/expiration in this rotation example is for deterministic checking;
use real expiration and `decode_keyset` in an application. Independent oct JWK
fixtures are reproduced with `python3 tools/generate-jwk-vectors.py`, followed by
`zap fmt tests`. Their HMAC signatures and base64url key values are generated
with Python stdlib, not the Zap implementation. See [JWK](https://www.rfc-editor.org/rfc/rfc7517)
and [symmetric key parameters](https://www.rfc-editor.org/rfc/rfc7518#section-6.4).

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
