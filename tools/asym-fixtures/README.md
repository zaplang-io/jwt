# Asymmetric test key fixtures

Fixed **test-only** key pairs used by `tools/generate-asym-vectors.py` to author
the committed interop, binding, and private-JWK vectors. They are not secrets and
must never be used in production.

Committing these test-only private keys to a public repository is an intentional,
reviewed decision (issue #11 item 11): the key material exists solely to make the
test vectors reproducible and self-contained, it protects nothing, and the
private-JWK signing tests embed the same material because the language has no
runtime keypair generation. This mirrors the convention of PyJWT and the Python
`cryptography` project, whose test suites likewise commit fixed test keys.

| File | Purpose |
| --- | --- |
| `rsa.pem` / `rsa.pub.pem` | RSA 2048-bit key pair (RS256). |
| `ec.pem` / `ec.pub.pem` | EC P-256 key pair (ES256). |
| `ed.pem` / `ed.pub.pem` | Ed25519 key pair (EdDSA). |
| `ec384.pub.pem` | P-384 public key — wrong-curve rejection fixture. |
| `rsa1024.pub.pem` | RSA 1024-bit public key — undersized-key rejection fixture. |

Regenerate the vectors with the OpenSSL CLI (an independent, non-runtime signer):

```sh
python3 tools/generate-asym-vectors.py
zap fmt tests
```

RS256 and EdDSA are deterministic, so their known-answer vectors reproduce
byte-for-byte. ES256 (ECDSA) uses a random nonce, so re-running changes only the
ES256 external-signature vectors; they remain valid signatures the library must
still verify.
