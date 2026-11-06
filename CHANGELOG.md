# Changelog

All notable changes to this package are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Notes

- Signature comparison is not documented as constant-time; a core
  `crypto.constant_time_eq` primitive is requested in
  [zaplang-io/zap#729](https://github.com/zaplang-io/zap/issues/729).
- CI pins the published Zap compiler image by digest; it carries the stdlib
  asymmetric crypto primitives and the `zaplang-io/zap#727`/`#728` codegen fix.

## [0.1.0] — earlier

- Compact HS256/HS512 signing and verification
  ([#1](https://github.com/zaplang-io/jwt/issues/1)).
- Authenticated claims and application policy
  ([#2](https://github.com/zaplang-io/jwt/issues/2)).
- Offline `oct` JWK sets and deterministic key rotation
  ([#3](https://github.com/zaplang-io/jwt/issues/3)).
