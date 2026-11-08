# jwt

Pure-Zap JWT creation and verification over stdlib crypto.
Implements [zaplang-io/zap#318](https://github.com/zaplang-io/zap/issues/318).
Development status: compact HMAC and asymmetric (RS256/ES256/EdDSA) signing,
authenticated claims, and offline symmetric and public-key JWK rotation.

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

`encode(claims, key, algorithm, headers={}) -> str` signs a JSON object. For
HS256/HS512 the `key` is the raw secret `bytes`, with a minimum length of 32 or
64 bytes respectively; generate random keys, since a long password does not
guarantee entropy. For RS256/ES256/EdDSA the `key` is the **private** key as
PEM or DER `bytes` (see the asymmetric section below).
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

## Asymmetric algorithms

The same `encode`, `verify_signature`, `decode`, and key-set functions accept the
asymmetric algorithms. Signing with `encode`/`encode_key` always requires the
**private** key; verification with `verify_signature`/`decode`/`decode_keyset`
always requires the **public** key. Passing a public key to sign, or a private
key to verify, raises `KeyError` — the roles never silently cross.

| `alg` | JOSE scheme | Key family | Signature encoding |
| --- | --- | --- | --- |
| `HS256` | HMAC-SHA-256 | shared `oct` secret (≥ 32 bytes) | 32-byte MAC |
| `HS512` | HMAC-SHA-512 | shared `oct` secret (≥ 64 bytes) | 64-byte MAC |
| `RS256` | RSASSA-PKCS1-v1_5 + SHA-256 | RSA, 2048–8192-bit modulus | modulus-width signature |
| `ES256` | ECDSA P-256 + SHA-256 | EC, curve `P-256` | fixed 64-byte JOSE `r‖s` |
| `EdDSA` | Ed25519 (RFC 8037) | OKP, curve `Ed25519` | 64-byte signature |

Asymmetric keys are supplied as PEM (`BEGIN PUBLIC KEY`/`BEGIN PRIVATE KEY`,
and PKCS#1 `BEGIN RSA PRIVATE KEY`) or DER `bytes`. Every key is inspected before
use: the family must match the algorithm, an `ES256` key must be on `P-256`, and
an `RS256` modulus must be 2048–8192 bits. `ES256` only ever accepts and emits the
fixed-width 64-byte JOSE `r‖s` form — ASN.1/DER ECDSA signatures are rejected.
Unparseable, encrypted, or unsupported keys raise `KeyError`.

`ES256` is non-deterministic (random ECDSA nonce), so an identical payload yields
a different signature each time; it is still verifiable by any conformant party.
`RS256` and `EdDSA` are deterministic.

```zap
import jwt

def main(bytes private_pem, bytes public_pem):
    # Key bytes come from trusted configuration, never from the token.
    auto token = jwt.encode({"sub": JsonValue.Str("alice"), "exp": JsonValue.Int(int64(time.time()) + 300)}, private_pem, "RS256")
    auto verified = jwt.verify_signature(token, public_pem, "RS256")
    print(json.dumps(verified.claims["sub"]))
```

The classic "algorithm confusion" attack is prevented because the verifier always
pins the algorithm from trusted configuration: a token's `alg` header can never
select HMAC verification against an RSA/EC public key, nor widen a key set's
allowlist.

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
payload bytes; 32 JSON container levels; 1,366 encoded signature characters (an
8192-bit RSA signature; HMAC/ES256/EdDSA signatures are 86). Signing
uses the same JSON limits. Short/wrong signatures fail authentication. HMAC
signature comparison uses the stdlib `crypto.constant_time_eq` primitive (OpenSSL
`CRYPTO_memcmp`,
[zaplang-io/zap#729](https://github.com/zaplang-io/zap/issues/729) /
[#757](https://github.com/zaplang-io/zap/pull/757)): equal-length digests are
compared with no data-dependent branch, so verification time cannot reveal how
many leading bytes matched. The digest length is a public constant, so the only
observable timing signal (a length mismatch) leaks nothing secret. Asymmetric
verification compares inside OpenSSL and has the same property.

Failures raise catchable messages prefixed with `TokenError:`, `AlgorithmError:`,
`HeaderError:`, `KeyError:`, `SignatureError:`, `ClaimsError:`, `PolicyError:`,
`JWKError:`, or `KeySelectionError:`. Treat every failure as rejection;
do not depend on full message text. Signature authentication precedes payload JSON
parsing. Invalid input may fail at the first applicable check.

Supported now: compact JWS with HS256, HS512, RS256, ES256, and EdDSA.
Unsupported: HS384, RS384/RS512, ES384/ES512, PS256/PS384/PS512, `none`, JWE,
detached/unencoded payloads, network JWKS and automatic key discovery. Trusted
offline `oct`, `RSA`, `EC`, and `OKP` JWK/JWKS is supported below.

For trusted offline key configuration, `load_jwk(json_text) -> Key` and
`load_jwks(json_text) -> KeySet` validate `oct`, `RSA`, `EC`, and `OKP` JWKs.
An `oct` JWK contains the shared secret, and a single `RSA`/`EC`/`OKP` JWK may
carry the private components too: keep those documents private, rather than
publishing them as a JWKS endpoint. A `load_jwks` key set is always **public**
verification keys and may be published — a private member in a key set is
rejected, so a private key can never hide in a JWKS. Load explicitly trusted
configuration; token headers never supply key documents or locations.

Every JWK requires a nonempty `kid` and explicit `alg`. By key type:

- `oct` (`alg` `HS256`/`HS512`): canonical unpadded base64url `k`; HMAC minimum
  key sizes remain 32/64 bytes. Permits sign and verify.
- `RSA` (`alg` `RS256`): public components `n` and `e`; the modulus must be
  2048–8192 bits. A full private key (`d` plus the CRT members `p`, `q`, `dp`,
  `dq`, `qi`) loads via `load_jwk` as a sign-only key; stray private members
  without `d`, or `oth`, are rejected.
- `EC` (`alg` `ES256`): `crv="P-256"` and public coordinates `x`, `y`, validated
  to lie on the curve. A private `d` member makes it a sign-only key via
  `load_jwk`.
- `OKP` (`alg` `EdDSA`): `crv="Ed25519"` and public key `x`. A private `d` member
  makes it a sign-only key via `load_jwk`.

A JWK with private components loads (via `load_jwk` only) as a **sign-only** key:
it signs with `encode_key` but cannot verify, so `key_ops` may not request
`verify`; a purely public `RSA`/`EC`/`OKP` JWK is verification-only and `key_ops`
may not request `sign`. Optional `use` must be `sig`; optional `key_ops` must be a
nonempty array of unique `sign` and/or `verify` values. Unsupported key types,
algorithms, curves, certificate/reference fields and critical extensions are
rejected. Unknown other metadata is ignored. Duplicate JSON members at any depth
fail. `encode_key` signs with an `oct` key or a private `RSA`/`EC`/`OKP` JWK;
public keys cannot sign.

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
and runs an isolated consumer. CI pins the published Zap compiler image by digest.
HMAC test vectors are independently generated with Python stdlib HMAC/SHA-2;
reproduce with `python3 tools/generate-vectors.py` followed by `zap fmt tests`.
Asymmetric interop and binding vectors are generated from fixed test keys in
`tools/asym-fixtures/` using the OpenSSL CLI as the independent signer; reproduce
with `python3 tools/generate-asym-vectors.py` followed by `zap fmt tests` (RS256
and EdDSA reproduce byte-for-byte; ES256 uses a random nonce). Python and OpenSSL
are only fixture-authoring tools, not runtime dependencies.

## Replay protection

Replay protection is **opt-in** and caller-managed. `decode`/`verify_signature`
are deliberately stateless; to reject a token whose `jti` has already been
presented, build a `ReplayCache` and call `replay_admit` (or `replay_admit_at`
with an explicit clock) **after** the token's claims have validated:

```zap
auto cache = jwt.new_replay_cache()        # optional: new_replay_cache(capacity)

auto claims = jwt.decode(token, key, "HS256", policy)
jwt.replay_admit(cache, claims)            # raises ClaimsError on a replay
```

A `ReplayCache` is a bounded, mutex-guarded set of seen `jti` values and is safe
to share across coroutines. Each entry is remembered only until the token's `exp`
(so the memory is bounded by the number of live tokens, and a `jti` may be reused
once its earlier token has expired); `replay_admit` therefore requires both a
string `jti` (≤ 256 bytes) and an `exp`, and raises `ClaimsError` on a live
replay or when a full cache cannot admit a new identifier. The cache lives for as
long as the caller keeps it — scope one per trust domain and discard it to forget
all history.

## Conformance and release readiness

Correctness is established against independent implementations, never by
self-round-trip alone. The fixture corpus and its provenance:

- **RFC known-answer vector** — `tests/rfc_vectors_test.zap` verifies the RFC 7515
  Appendix A.1 HS256 JWS verbatim from the specification.
- **Independent HMAC vectors** — `tests/vectors_test.zap`, `tests/jwk_vectors_test.zap`
  from Python stdlib HMAC/SHA-2.
- **Independent asymmetric vectors** — `tests/asym_vectors_test.zap` from the
  OpenSSL CLI: external-sign→verify for every algorithm, plus deterministic
  Zap-sign→external known-answer tokens for RS256 and EdDSA.
- **Abuse/regression corpus** — `tests/compact_test.zap`, `tests/encoding_test.zap`,
  `tests/claims_test.zap`, `tests/claims_wire_test.zap`, `tests/policy_test.zap`,
  `tests/jwks_test.zap`, `tests/jwk_limits_test.zap`, `tests/asym_binding_test.zap`
  and `tests/abuse_corpus_test.zap` cover malformed/tampered compact, JSON,
  Unicode, header, claims and JWK inputs, algorithm confusion, and key binding.
- **Durability** — `tests/stress_test.zap` repeats sign/verify across symmetric
  and asymmetric algorithms under allocation pressure to exercise the GC.

Packaging is validated by `sh tools/check-package.sh` (an isolated consumer plus
`zap publish --dry-run`). CI runs every test in the pinned, published Zap compiler
image (`.github/workflows/test.yml`); the digest is bumped deliberately and must
carry every stdlib primitive this library uses. Signature comparison timing is
documented above (constant-time via the stdlib `crypto.constant_time_eq`).

Release checklist:

1. `sh tools/run-tests.sh` and `sh tools/check-package.sh` green in CI on the
   pinned image.
2. Supported algorithms and key formats match the tables above; unsupported
   inputs are rejected with tests.
3. `README.md` documents the API, errors, limits, support matrix and the
   unsupported set (HS384/RS384/…, `none`, JWE, detached/unencoded JWS, network
   JWKS and automatic key discovery).
4. `CHANGELOG.md` updated; `version` in `zap.toml` bumped.
5. Publish only with the maintainer's explicit authorization.

References: [JWS](https://www.rfc-editor.org/rfc/rfc7515),
[JWA](https://www.rfc-editor.org/rfc/rfc7518),
[JWT](https://www.rfc-editor.org/rfc/rfc7519),
[JWT security practices](https://www.rfc-editor.org/rfc/rfc8725).
