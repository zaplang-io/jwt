#!/usr/bin/env python3
"""Reproduce committed asymmetric fixtures with the OpenSSL CLI, not Zap.

The private/public keys in tools/asym-fixtures/ are fixed test keys; OpenSSL is
the independent signer/verifier. RS256 (RSA PKCS#1 v1.5) and EdDSA (Ed25519) are
deterministic, so their known-answer vectors reproduce byte-for-byte. ES256
(ECDSA) uses a random nonce, so a re-run changes only the ES256 external-vector
signature; it is still a valid signature that Zap must verify. OpenSSL is a
fixture-authoring tool, never a runtime dependency of the library.
"""
import base64
import hashlib
import hmac
import json
import subprocess
import tempfile
from pathlib import Path

FIX = Path(__file__).resolve().parent / "asym-fixtures"
TESTS = Path(__file__).resolve().parents[1] / "tests"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def read(name: str) -> str:
    return (FIX / name).read_text()


def openssl(args, stdin: bytes = b"") -> bytes:
    return subprocess.run(
        ["openssl", *args], input=stdin, stdout=subprocess.PIPE, check=True
    ).stdout


def sign_rsa(priv: str, message: bytes) -> bytes:
    # Raw RSA-SHA256 PKCS#1 v1.5 signature (no DER wrapper), 256 bytes for 2048.
    return openssl(["dgst", "-sha256", "-sign", str(FIX / priv)], message)


def sign_ed25519(priv: str, message: bytes) -> bytes:
    # Ed25519 is a one-shot raw signature; OpenSSL needs a sized -in file, not stdin.
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(message)
        tmp.flush()
        return openssl(
            ["pkeyutl", "-sign", "-inkey", str(FIX / priv), "-rawin", "-in", tmp.name]
        )


def _der_to_jose_p256(der: bytes) -> bytes:
    # ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }; all lengths < 128.
    assert der[0] == 0x30
    idx = 2
    assert der[idx] == 0x02
    rlen = der[idx + 1]
    r = der[idx + 2 : idx + 2 + rlen]
    idx = idx + 2 + rlen
    assert der[idx] == 0x02
    slen = der[idx + 1]
    s = der[idx + 2 : idx + 2 + slen]
    r = r.lstrip(b"\x00").rjust(32, b"\x00")
    s = s.lstrip(b"\x00").rjust(32, b"\x00")
    return r + s


def sign_es256_der(priv: str, message: bytes) -> bytes:
    return openssl(["dgst", "-sha256", "-sign", str(FIX / priv)], message)


def sign_es256_jose(priv: str, message: bytes) -> bytes:
    return _der_to_jose_p256(sign_es256_der(priv, message))


def rsa_components(pub: str):
    modulus = (
        openssl(["rsa", "-pubin", "-in", str(FIX / pub), "-noout", "-modulus"])
        .decode()
        .strip()
    )
    assert modulus.startswith("Modulus=")
    n = bytes.fromhex(modulus[len("Modulus=") :])
    n = n.lstrip(b"\x00")  # JWK integers use the minimal unsigned octet string.
    e = (65537).to_bytes(3, "big")
    return n, e


def _pub_hex_block(pub: str) -> bytes:
    text = openssl(
        ["pkey", "-pubin", "-in", str(FIX / pub), "-text_pub", "-noout"]
    ).decode()
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "pub:")
    out = []
    for ln in lines[start + 1 :]:
        stripped = ln.strip()
        if not stripped or ":" not in stripped or stripped.endswith(":") is False and all(
            c in "0123456789abcdef:" for c in stripped
        ) is False:
            break
        if not all(c in "0123456789abcdef:" for c in stripped.rstrip(":")):
            break
        out.extend(b for b in stripped.split(":") if b)
    return bytes(int(b, 16) for b in out)


def ec_components(pub: str):
    point = _pub_hex_block(pub)
    assert point[0] == 0x04 and len(point) == 65  # uncompressed P-256 point
    return point[1:33], point[33:65]


def okp_component(pub: str) -> bytes:
    x = _pub_hex_block(pub)
    assert len(x) == 32
    return x


def q(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def message(header_json: str, payload_json: str) -> str:
    return b64u(header_json.encode()) + "." + b64u(payload_json.encode())


def token(message_str: str, signature: bytes) -> str:
    return message_str + "." + b64u(signature)


# ---- key material -----------------------------------------------------------
RSA_PRIV, RSA_PUB = read("rsa.pem"), read("rsa.pub.pem")
EC_PRIV, EC_PUB = read("ec.pem"), read("ec.pub.pem")
ED_PRIV, ED_PUB = read("ed.pem"), read("ed.pub.pem")
EC384_PUB = read("ec384.pub.pem")
RSA1024_PUB = read("rsa1024.pub.pem")

RSA_N, RSA_E = rsa_components("rsa.pub.pem")
EC_X, EC_Y = ec_components("ec.pub.pem")
ED_X = okp_component("ed.pub.pem")
EC384_X, EC384_Y = (b"", b"")  # unused; P-384 is rejected before component read

ALGS = {
    # alg: (family, priv_file, priv_pem, pub_pem, signer(priv_file, msg)->sig)
    "RS256": ("RSA", "rsa.pem", RSA_PRIV, RSA_PUB, sign_rsa),
    "ES256": ("EC", "ec.pem", EC_PRIV, EC_PUB, sign_es256_jose),
    "EdDSA": ("Ed25519", "ed.pem", ED_PRIV, ED_PUB, sign_ed25519),
}

PAYLOAD = '{"sub":"alice","iss":"issuer"}'
SIMPLE = '{"sub":"alice"}'


def public_jwk(alg: str, kid: str) -> str:
    if alg == "RS256":
        fields = {"kty": "RSA", "alg": "RS256", "kid": kid,
                  "n": b64u(RSA_N), "e": b64u(RSA_E), "use": "sig"}
    elif alg == "ES256":
        fields = {"kty": "EC", "alg": "ES256", "kid": kid, "crv": "P-256",
                  "x": b64u(EC_X), "y": b64u(EC_Y), "use": "sig"}
    else:
        fields = {"kty": "OKP", "alg": "EdDSA", "kid": kid, "crv": "Ed25519",
                  "x": b64u(ED_X), "use": "sig"}
    return json.dumps(fields, separators=(",", ":"))


# =============================================================================
# tests/asym_vectors_test.zap  — interop vectors (external<->Zap).
# =============================================================================
def emit_vectors():
    out = [
        "# Generated by tools/generate-asym-vectors.py (OpenSSL is the independent signer).",
        "# RS256/EdDSA are deterministic known-answer tests; ES256 uses a random nonce",
        "# so only external-sign->Zap-verify and the self round-trip are asserted.",
        "import jwt",
        "",
        "def main():",
    ]
    for alg, (_fam, priv_file, _priv, pub, signer) in ALGS.items():
        tag = alg.lower()
        hdr = '{"alg":"' + alg + '","typ":"JWT"}'
        msg = message(hdr, PAYLOAD)
        tok = token(msg, signer(priv_file, msg.encode()))
        out += [
            f"    # ---- {alg}: external sign -> Zap verify (direct PEM public key) ----",
            f"    auto {tag}_pub = bytes({q(pub)})",
            f"    auto {tag}_token = {q(tok)}",
            f"    auto {tag}_v = jwt.verify_signature({tag}_token, {tag}_pub, {q(alg)})",
            f'    assert json.dumps({tag}_v.claims["sub"]) == "\\"alice\\""',
            f'    assert json.dumps({tag}_v.claims["iss"]) == "\\"issuer\\""',
        ]
        # External sign -> Zap verify via a public JWK key set (kid selection).
        kid = f"{tag}-1"
        hdr_kid = '{"alg":"' + alg + '","typ":"JWT","kid":"' + kid + '"}'
        msg_kid = message(hdr_kid, PAYLOAD)
        tok_kid = token(msg_kid, signer(priv_file, msg_kid.encode()))
        out += [
            f"    # ---- {alg}: external sign -> Zap verify via public JWK ----",
            f"    auto {tag}_jwk = {q(public_jwk(alg, kid))}",
            f"    auto {tag}_key = jwt.load_jwk({tag}_jwk)",
            f"    assert {tag}_key.can_verify and not {tag}_key.can_sign",
            f"    auto {tag}_set = jwt.KeySet([{tag}_key])",
            f"    auto {tag}_kv = jwt.verify_keyset_signature({q(tok_kid)}, {tag}_set, [{q(alg)}])",
            f'    assert json.dumps({tag}_kv.claims["sub"]) == "\\"alice\\""',
        ]
    # Deterministic Zap-sign -> external known-answer tests (RS256, EdDSA).
    for alg in ("RS256", "EdDSA"):
        _fam, priv_file, priv, pub, signer = ALGS[alg]
        tag = alg.lower()
        primary = token(message('{"alg":"' + alg + '","typ":"JWT"}', SIMPLE),
                        signer(priv_file, message('{"alg":"' + alg + '","typ":"JWT"}', SIMPLE).encode()))
        alt = token(message('{"typ":"JWT","alg":"' + alg + '"}', SIMPLE),
                    signer(priv_file, message('{"typ":"JWT","alg":"' + alg + '"}', SIMPLE).encode()))
        out += [
            f"    # ---- {alg}: Zap sign -> external known-answer (deterministic) ----",
            f"    auto {tag}_priv = bytes({q(priv)})",
            f'    auto {tag}_enc = jwt.encode({{"sub": JsonValue.Str("alice")}}, {tag}_priv, {q(alg)})',
            f"    assert {tag}_enc == {q(primary)} or {tag}_enc == {q(alt)}",
            f"    jwt.verify_signature({tag}_enc, {tag}_pub, {q(alg)})",
        ]
    # ES256 round-trip (randomized signature; byte KAT is impossible).
    out += [
        "    # ---- ES256: Zap sign -> Zap verify round-trip; canonical 64-byte JOSE ----",
        f"    auto es_priv = bytes({q(EC_PRIV)})",
        '    auto es_rt = jwt.encode({"sub": JsonValue.Str("alice")}, es_priv, "ES256")',
        '    auto es_rtv = jwt.verify_signature(es_rt, es256_pub, "ES256")',
        '    assert json.dumps(es_rtv.claims["sub"]) == "\\"alice\\""',
        '    assert len(es_rt.split(".")[2]) == 86',
        '    print("asymmetric interop vectors: PASS")',
        "",
    ]
    (TESTS / "asym_vectors_test.zap").write_text("\n".join(out))


# =============================================================================
# tests/asym_binding_test.zap  — exhaustive binding / abuse rejections.
# =============================================================================
def emit_binding():
    # Valid externally-signed tokens to tamper with / mis-key.
    def tok_for(alg):
        _fam, priv_file, _priv, pub, signer = ALGS[alg]
        hdr = '{"alg":"' + alg + '","typ":"JWT"}'
        msg = message(hdr, PAYLOAD)
        return token(msg, signer(priv_file, msg.encode())), msg

    rs_token, rs_msg = tok_for("RS256")
    es_token, es_msg = tok_for("ES256")
    ed_token, _ = tok_for("EdDSA")

    # Classic confusion: HMAC token whose secret is the RSA public key PEM.
    hs_hdr = '{"alg":"HS256","typ":"JWT"}'
    hs_msg = message(hs_hdr, PAYLOAD)
    hs_sig = hmac.new(RSA_PUB.encode(), hs_msg.encode(), hashlib.sha256).digest()
    hs_token = token(hs_msg, hs_sig)

    # Tampered ES256: a different payload under the original signature.
    es_tampered = ".".join([es_msg.split(".")[0],
                            b64u('{"sub":"mallory","iss":"issuer"}'.encode()),
                            es_token.split(".")[2]])

    es_der = sign_es256_der("ec.pem", es_msg.encode())  # DER (not JOSE) ES256 sig
    es_der_token = token(es_msg, es_der)
    es_short_token = es_msg + "." + b64u(b"\x01" * 63)
    rs_short_token = rs_msg + "." + b64u(b"\x02" * 10)
    oversized_token = rs_msg + "." + ("A" * 1400)

    kid = "rsa-1"
    rs_kid_hdr = '{"alg":"RS256","typ":"JWT","kid":"' + kid + '"}'
    rs_kid_msg = message(rs_kid_hdr, PAYLOAD)
    rs_kid_token = token(rs_kid_msg, sign_rsa("rsa.pem", rs_kid_msg.encode()))

    # JWK mutations.
    rsa_ok = json.loads(public_jwk("RS256", kid))
    ec_ok = json.loads(public_jwk("ES256", "ec-1"))
    okp_ok = json.loads(public_jwk("EdDSA", "ed-1"))

    def mut(base, **changes):
        d = dict(base)
        for k, v in changes.items():
            if v is None:
                d.pop(k, None)
            else:
                d[k] = v
        return json.dumps(d, separators=(",", ":"))

    rsa_wrong_alg = mut(rsa_ok, alg="HS256")
    rsa_private = mut(rsa_ok, d="AQAB")
    rsa_sign_op = mut(rsa_ok, key_ops=["sign"])
    rsa_bad_n = mut(rsa_ok, n="AAAA")
    ec_wrong_crv = mut(ec_ok, crv="P-384")
    ec_private = mut(ec_ok, d="AQAB")
    # Off-curve: flip the last byte of y.
    bad_y = bytearray(EC_Y)
    bad_y[-1] ^= 0x01
    ec_offcurve = mut(ec_ok, y=b64u(bytes(bad_y)))
    okp_wrong_crv = mut(okp_ok, crv="Ed448")
    okp_private = mut(okp_ok, d="AQAB")
    unknown_kty = mut(rsa_ok, kty="XYZ")

    key32 = "0123456789abcdef0123456789abcdef"

    lines = [
        "# Generated by tools/generate-asym-vectors.py (abuse / binding corpus).",
        "import jwt",
        "",
        "def verify_rejected(str token, bytes key, str algorithm, str prefix):",
        "    auto caught = False",
        "    try:",
        "        jwt.verify_signature(token, key, algorithm)",
        "    except Exception as e:",
        "        caught = e.startswith(prefix)",
        "    assert caught",
        "",
        "def encode_rejected(bytes key, str algorithm, str prefix):",
        "    auto caught = False",
        "    try:",
        '        jwt.encode({"sub": JsonValue.Str("x")}, key, algorithm)',
        "    except Exception as e:",
        "        caught = e.startswith(prefix)",
        "    assert caught",
        "",
        "def jwk_rejected(str source, str prefix):",
        "    auto caught = False",
        "    try:",
        "        jwt.load_jwk(source)",
        "    except Exception as e:",
        "        caught = e.startswith(prefix)",
        "    assert caught",
        "",
        "def main():",
        f"    auto rsa_pub = bytes({q(RSA_PUB)})",
        f"    auto ec_pub = bytes({q(EC_PUB)})",
        f"    auto ed_pub = bytes({q(ED_PUB)})",
        f"    auto ec_priv = bytes({q(EC_PRIV)})",
        f"    auto rsa_priv = bytes({q(RSA_PRIV)})",
        f"    auto ed_priv = bytes({q(ED_PRIV)})",
        f"    auto ec384_pub = bytes({q(EC384_PUB)})",
        f"    auto rsa1024_pub = bytes({q(RSA1024_PUB)})",
        f"    auto rs_token = {q(rs_token)}",
        f"    auto es_token = {q(es_token)}",
        f"    auto ed_token = {q(ed_token)}",
        f"    auto hs_token = {q(hs_token)}",
        "",
        "    # ---- private/public role separation ----",
        '    encode_rejected(rsa_pub, "RS256", "KeyError")',
        '    encode_rejected(ec_pub, "ES256", "KeyError")',
        '    encode_rejected(ed_pub, "EdDSA", "KeyError")',
        '    verify_rejected(es_token, ec_priv, "ES256", "KeyError")',
        '    verify_rejected(rs_token, rsa_priv, "RS256", "KeyError")',
        '    verify_rejected(ed_token, ed_priv, "EdDSA", "KeyError")',
        "",
        "    # ---- wrong family / curve / size ----",
        '    verify_rejected(rs_token, ec_pub, "RS256", "KeyError")',
        '    verify_rejected(es_token, rsa_pub, "ES256", "KeyError")',
        '    verify_rejected(ed_token, rsa_pub, "EdDSA", "KeyError")',
        '    verify_rejected(es_token, ec384_pub, "ES256", "KeyError")',
        '    verify_rejected(rs_token, rsa1024_pub, "RS256", "KeyError")',
        '    verify_rejected(rs_token, bytes("not a pem"), "RS256", "KeyError")',
        "",
        "    # ---- RSA/HMAC confusion: pinned algorithm wins ----",
        '    verify_rejected(rs_token, rsa_pub, "HS256", "AlgorithmError")',
        '    verify_rejected(hs_token, rsa_pub, "RS256", "AlgorithmError")',
        "",
        "    # ---- rejected / unsupported algorithm identifiers ----",
        '    encode_rejected(ec_priv, "none", "AlgorithmError")',
        '    verify_rejected(es_token, ec_pub, "none", "AlgorithmError")',
        f'    encode_rejected(bytes({q(key32)}), "HS384", "AlgorithmError")',
        "",
        "    # ---- signature encoding / length abuse ----",
        f'    verify_rejected({q(es_tampered)}, ec_pub, "ES256", "SignatureError")',
        f'    verify_rejected({q(es_der_token)}, ec_pub, "ES256", "SignatureError")',
        f'    verify_rejected({q(es_short_token)}, ec_pub, "ES256", "SignatureError")',
        f'    verify_rejected({q(rs_short_token)}, rsa_pub, "RS256", "SignatureError")',
        f'    verify_rejected({q(oversized_token)}, rsa_pub, "RS256", "TokenError")',
        "",
        "    # ---- valid public JWKs load as verify-only ----",
        f"    auto rsa_key = jwt.load_jwk({q(json.dumps(rsa_ok, separators=(',', ':')))})",
        "    assert rsa_key.can_verify and not rsa_key.can_sign",
        f"    auto ec_key = jwt.load_jwk({q(json.dumps(ec_ok, separators=(',', ':')))})",
        "    assert ec_key.can_verify and not ec_key.can_sign",
        f"    auto okp_key = jwt.load_jwk({q(json.dumps(okp_ok, separators=(',', ':')))})",
        "    assert okp_key.can_verify and not okp_key.can_sign",
        "",
        "    # ---- public JWK cannot sign via the key API ----",
        "    auto blocked = False",
        "    try:",
        '        jwt.encode_key({"sub": JsonValue.Str("x")}, rsa_key)',
        "    except Exception as e:",
        '        blocked = e.startswith("JWKError:")',
        "    assert blocked",
        "",
        "    # ---- malformed / mis-bound JWKs ----",
        f'    jwk_rejected({q(rsa_wrong_alg)}, "JWKError")',
        f'    jwk_rejected({q(rsa_private)}, "JWKError")',
        f'    jwk_rejected({q(rsa_sign_op)}, "JWKError")',
        f'    jwk_rejected({q(rsa_bad_n)}, "JWKError")',
        f'    jwk_rejected({q(ec_wrong_crv)}, "JWKError")',
        f'    jwk_rejected({q(ec_private)}, "JWKError")',
        f'    jwk_rejected({q(ec_offcurve)}, "JWKError")',
        f'    jwk_rejected({q(okp_wrong_crv)}, "JWKError")',
        f'    jwk_rejected({q(okp_private)}, "JWKError")',
        f'    jwk_rejected({q(unknown_kty)}, "JWKError")',
        "",
        "    # ---- key-set algorithm restriction: a token cannot widen the allowlist ----",
        f"    auto rsa_set = jwt.KeySet([jwt.load_jwk({q(public_jwk('RS256', kid))})])",
        "    auto restricted = False",
        "    try:",
        f'        jwt.verify_keyset_signature({q(rs_kid_token)}, rsa_set, ["ES256"])',
        "    except Exception as e:",
        '        restricted = e.startswith("AlgorithmError:")',
        "    assert restricted",
        f'    auto selected = jwt.verify_keyset_signature({q(rs_kid_token)}, rsa_set, ["RS256"])',
        '    assert json.dumps(selected.claims["sub"]) == "\\"alice\\""',
        "",
        '    print("asymmetric binding corpus: PASS")',
        "",
    ]
    (TESTS / "asym_binding_test.zap").write_text("\n".join(lines))


def _openssl_text_blocks(text: str) -> dict:
    # Parse `openssl rsa/ec -text` output: a label line, then indented `xx:xx:`
    # hex continuation lines, into {label: bytes}.
    blocks = {}
    label = None
    acc = []
    for ln in text.splitlines():
        if ln and not ln[0].isspace() and ln.rstrip().endswith(":"):
            if label is not None:
                blocks[label] = bytes(int(b, 16) for b in acc if b)
            label = ln.strip().rstrip(":")
            acc = []
        elif label is not None and ln.strip() and all(
            c in "0123456789abcdef:" for c in ln.strip()
        ):
            acc.extend(ln.strip().split(":"))
        elif label is not None:
            blocks[label] = bytes(int(b, 16) for b in acc if b)
            label = None
            acc = []
    if label is not None:
        blocks[label] = bytes(int(b, 16) for b in acc if b)
    return blocks


def _minimal(n: bytes) -> bytes:
    return n.lstrip(b"\x00") or b"\x00"


def rsa_private_components(priv: str) -> dict:
    text = openssl(["rsa", "-in", str(FIX / priv), "-text", "-noout"]).decode()
    b = _openssl_text_blocks(text)
    return {
        "n": b64u(_minimal(b["modulus"])),
        "e": b64u((65537).to_bytes(3, "big")),
        "d": b64u(_minimal(b["privateExponent"])),
        "p": b64u(_minimal(b["prime1"])),
        "q": b64u(_minimal(b["prime2"])),
        "dp": b64u(_minimal(b["exponent1"])),
        "dq": b64u(_minimal(b["exponent2"])),
        "qi": b64u(_minimal(b["coefficient"])),
    }


def ec_private_scalar(priv: str) -> bytes:
    text = openssl(["ec", "-in", str(FIX / priv), "-text", "-noout"]).decode()
    scalar = _openssl_text_blocks(text)["priv"]
    return scalar.rjust(32, b"\x00")[-32:]


def okp_private_seed(priv: str) -> bytes:
    # Ed25519 PKCS#8 v1 DER is a fixed prefix followed by the 32-byte seed.
    der = openssl(["pkey", "-in", str(FIX / priv), "-outform", "DER"])
    return der[-32:]


def private_jwk(alg: str, kid: str) -> str:
    if alg == "RS256":
        c = rsa_private_components("rsa.pem")
        fields = {"kty": "RSA", "alg": "RS256", "kid": kid,
                  "n": c["n"], "e": c["e"], "d": c["d"], "p": c["p"],
                  "q": c["q"], "dp": c["dp"], "dq": c["dq"], "qi": c["qi"],
                  "key_ops": ["sign"]}
    elif alg == "ES256":
        fields = {"kty": "EC", "alg": "ES256", "kid": kid, "crv": "P-256",
                  "x": b64u(EC_X), "y": b64u(EC_Y),
                  "d": b64u(ec_private_scalar("ec.pem")), "key_ops": ["sign"]}
    else:
        fields = {"kty": "OKP", "alg": "EdDSA", "kid": kid, "crv": "Ed25519",
                  "x": b64u(ED_X), "d": b64u(okp_private_seed("ed.pem")),
                  "key_ops": ["sign"]}
    return json.dumps(fields, separators=(",", ":"))


# =============================================================================
# tests/asym_private_jwk_test.zap — private-JWK signing (#11 item 9).
# =============================================================================
def emit_private_jwk():
    lines = [
        "# Generated by tools/generate-asym-vectors.py — private-JWK signing (#11 item 9).",
        "# Each private JWK loads as a sign-only key; the library signs with it and",
        "# verifies the result with the matching public key (full round-trip).",
        "import jwt",
        "",
        "def main():",
    ]
    for alg, (_fam, _pf, _priv, pub, _signer) in ALGS.items():
        tag = alg.lower()
        lines += [
            f"    auto {tag}_priv_jwk = {q(private_jwk(alg, tag + '-priv'))}",
            f"    auto {tag}_signer = jwt.load_jwk({tag}_priv_jwk)",
            f"    assert {tag}_signer.can_sign and not {tag}_signer.can_verify",
            f'    auto {tag}_tok = jwt.encode_key({{"sub": JsonValue.Str("alice")}}, {tag}_signer)',
            f"    auto {tag}_pub = bytes({q(pub)})",
            f"    auto {tag}_v = jwt.verify_signature({tag}_tok, {tag}_pub, {q(alg)})",
            f'    assert json.dumps({tag}_v.claims["sub"]) == "\\"alice\\""',
        ]
    # Negatives: private JWK rejected in a key set; verify op on a private key;
    # an RSA private JWK missing a CRT parameter.
    rsa_priv = json.loads(private_jwk("RS256", "rsa-neg"))
    no_qi = {k: v for k, v in rsa_priv.items() if k != "qi"}
    verify_op = dict(rsa_priv)
    verify_op["key_ops"] = ["verify"]
    jwks = json.dumps({"keys": [rsa_priv]}, separators=(",", ":"))
    lines += [
        "    auto in_set = False",
        f"    try:",
        f"        jwt.load_jwks({q(jwks)})",
        "    except Exception as e:",
        '        in_set = e.startswith("JWKError:")',
        "    assert in_set",
        "    auto verify_op = False",
        f"    try:",
        f"        jwt.load_jwk({q(json.dumps(verify_op, separators=(',', ':')))})",
        "    except Exception as e:",
        '        verify_op = e.startswith("JWKError:")',
        "    assert verify_op",
        "    auto no_crt = False",
        f"    try:",
        f"        jwt.load_jwk({q(json.dumps(no_qi, separators=(',', ':')))})",
        "    except Exception as e:",
        '        no_crt = e.startswith("JWKError:")',
        "    assert no_crt",
        '    print("private-JWK signing: PASS")',
        "",
    ]
    (TESTS / "asym_private_jwk_test.zap").write_text("\n".join(lines))


if __name__ == "__main__":
    emit_vectors()
    emit_binding()
    emit_private_jwk()
    print("wrote asym vectors, binding, and private-JWK tests")
