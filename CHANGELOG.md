# Changelog

All notable changes to this package are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Private-JWK signing ([#11](https://github.com/zaplang-io/jwt/issues/11) item 9):
  `load_jwk` now accepts a private `RSA` (full CRT), `EC`, or `OKP` JWK and returns
  a sign-only `Key` usable with `encode_key`, built through the stdlib
  `crypto.*_private_key_pem` primitives ([zaplang-io/zap#778](https://github.com/zaplang-io/zap/issues/778)).
  Key sets stay public-only: a private member in a JWKS is rejected.
- Opt-in replay protection ([#11](https://github.com/zaplang-io/jwt/issues/11) item 10):
  a `ReplayCache` type with `new_replay_cache(capacity)` and
  `replay_admit`/`replay_admit_at`. The cache is a bounded, mutex-guarded set of
  seen `jti` values (each kept only until its token's `exp`) and is checked by the
  caller after claims validation; `decode`/`verify_signature` stay stateless.
- Conformance and release-readiness suite ([#5](https://github.com/zaplang-io/jwt/issues/5)):
  - RFC 7515 Appendix A.1 (HS256) known-answer vector (`tests/rfc_vectors_test.zap`).
  - Consolidated abuse/regression corpus for malformed structure, signature
    reuse, non-object/duplicate/invalid-UTF-8 headers, and the no-normalization
    policy guarantee (`tests/abuse_corpus_test.zap`).
  - Repeated sign/verify under GC pressure across algorithms (`tests/stress_test.zap`).
  - "Conformance and release readiness" documentation, fixture provenance, and a
    release checklist in `README.md`.
- Asymmetric algorithms and public-key JWK interoperability
  ([#4](https://github.com/zaplang-io/jwt/issues/4)):
  - `RS256` (RSA PKCS#1 v1.5, 2048–8192-bit), `ES256` (ECDSA P-256, fixed 64-byte
    JOSE `r‖s`), and `EdDSA` (Ed25519) signing and verification.
  - PEM/DER private keys for signing and public keys for verification, with strict
    family/curve/size binding and private/public role separation.
  - Public-key JWK loading for `RSA`, `EC`, and `OKP` keys and key sets.
  - Independent interop vectors (OpenSSL) and an exhaustive binding/abuse corpus.

### Changed

- Post-review cleanups from [#11](https://github.com/zaplang-io/jwt/issues/11):
  - HMAC signature comparison now uses the stdlib `crypto.constant_time_eq`
    primitive (OpenSSL `CRYPTO_memcmp`,
    [zaplang-io/zap#757](https://github.com/zaplang-io/zap/pull/757) closing
    [#729](https://github.com/zaplang-io/zap/issues/729)), replacing a hand-rolled
    XOR compare whose constant-time property the compiler did not guarantee.
  - JWK document load errors now report the specific cause (duplicate member,
    non-object, invalid UTF-8, nesting overflow) while keeping the `JWKError:`
    prefix, instead of collapsing to one opaque message.

### Notes

- The committed asymmetric test keys under `tools/asym-fixtures/` (and the key
  material embedded in the asymmetric test vectors) are intentionally test-only,
  a reviewed decision for a public repository ([#11](https://github.com/zaplang-io/jwt/issues/11) item 11); they match the convention of PyJWT and `cryptography`.
- Signature comparison is constant-time via the stdlib `crypto.constant_time_eq`
  primitive; asymmetric verification compares inside OpenSSL.
- CI pins the published Zap compiler image by digest; it carries the stdlib
  asymmetric crypto primitives, `crypto.constant_time_eq`, and the
  `zaplang-io/zap#727`/`#728` codegen fix.

## [0.1.0] — earlier

- Compact HS256/HS512 signing and verification
  ([#1](https://github.com/zaplang-io/jwt/issues/1)).
- Authenticated claims and application policy
  ([#2](https://github.com/zaplang-io/jwt/issues/2)).
- Offline `oct` JWK sets and deterministic key rotation
  ([#3](https://github.com/zaplang-io/jwt/issues/3)).
