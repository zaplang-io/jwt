# Compact signed JWTs with authenticated claim validation and explicit policy.
import math
struct VerifiedToken:
    dict[str, JsonValue] header
    dict[str, JsonValue] claims

def _signature_size(str algorithm) -> int64:
    if algorithm == "HS256":
        return 32
    if algorithm == "HS512":
        return 64
    raise "AlgorithmError: supported algorithms are HS256 and HS512"

def _key(bytes key, str algorithm):
    if len(key) < _signature_size(algorithm):
        raise "KeyError: HMAC key is shorter than the digest size"

# Map a JOSE algorithm identifier to its key family. The asymmetric families use
# the same spelling as crypto.key_info().kind so binding is a direct comparison.
def _algorithm_family(str algorithm) -> str:
    if algorithm == "HS256" or algorithm == "HS512":
        return "HMAC"
    if algorithm == "RS256":
        return "RSA"
    if algorithm == "ES256":
        return "EC"
    if algorithm == "EdDSA":
        return "Ed25519"
    raise "AlgorithmError: supported algorithms are HS256, HS512, RS256, ES256 and EdDSA"

def _is_hmac(str algorithm) -> bool:
    return algorithm == "HS256" or algorithm == "HS512"

def _require_algorithm(str algorithm):
    # Reject any unsupported identifier before it reaches a signing primitive.
    # `_algorithm_family` raises for anything outside the supported set, so the
    # call's side effect is the whole check; its return value is unused here.
    _algorithm_family(algorithm)

def _key_info_or_raise(bytes key) -> KeyInfo:
    # A single, uniform rejection for unparseable/unsupported/encrypted keys so
    # callers never branch on the stdlib's lower-level ValueError text.
    try:
        return crypto.key_info(key)
    except Exception:
        raise "KeyError: unsupported or malformed asymmetric key"

# Enforce key family, size, curve, and the private/public role an operation
# needs. Signing requires a private key; verification requires a public key.
def _check_asym_key(bytes key, str algorithm, bool want_private):
    auto family = _algorithm_family(algorithm)
    if family == "HMAC":
        raise "AlgorithmError: HMAC keys are not asymmetric"
    auto info = _key_info_or_raise(key)
    if info.kind != family:
        raise "KeyError: " + algorithm + " requires a " + family + " key"
    if family == "RSA":
        if info.bits < 2048:
            raise "KeyError: RS256 requires an RSA key of at least 2048 bits"
        if info.bits > 8192:
            raise "KeyError: RS256 rejects RSA keys larger than 8192 bits"
    if family == "EC":
        if info.curve != "P-256":
            raise "KeyError: ES256 requires the P-256 curve"
    if want_private and not info.is_private:
        raise "KeyError: signing requires a private key"
    if not want_private and info.is_private:
        raise "KeyError: verification requires a public key, not a private key"

def _decode_segment(str segment) -> bytes:
    if len(segment) == 0 or len(segment) % 4 == 1:
        raise "TokenError: invalid base64url length"
    for c in segment:
        if "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".find(str(c)) < 0:
            raise "TokenError: expected unpadded base64url"
    auto raw = base64.urlsafe_decode(segment)
    if base64.urlsafe_encode_nopad(raw) != segment:
        raise "TokenError: noncanonical base64url"
    return raw

def _object(str text) -> dict[str, JsonValue]:
    # Inspect tokens before DOM construction so duplicate names cannot disappear.
    # A per-container key set also rejects duplicates in nested objects.
    list[bool] objects = []
    list[bool] want_key = []
    list[dict[str, bool]] names = []
    for i in range(32):
        objects.append(False)
        want_key.append(False)
        names.append({})
    auto depth = 0
    for token in json.scan(text):
        match token:
            case JsonToken.BeginObject:
                if depth == 32:
                    raise "TokenError: JSON nesting exceeds 32"
                objects[depth] = True
                want_key[depth] = True
                names[depth] = {}
                depth = depth + 1
            case JsonToken.BeginArray:
                if depth == 32:
                    raise "TokenError: JSON nesting exceeds 32"
                objects[depth] = False
                want_key[depth] = False
                names[depth] = {}
                depth = depth + 1
            case JsonToken.EndObject:
                if depth > 0:
                    depth = depth - 1
            case JsonToken.EndArray:
                if depth > 0:
                    depth = depth - 1
            case JsonToken.Comma:
                if depth > 0:
                    want_key[depth - 1] = objects[depth - 1]
            case JsonToken.Str(s):
                if depth > 0:
                    auto i = depth - 1
                    if objects[i] and want_key[i]:
                        # `names[i]` is the same dict object stored in the list,
                        # not a copy: Zap dicts are references, so `seen[s] = True`
                        # below mutates the stored per-container key set in place.
                        # This aliasing is load-bearing — the duplicate-member
                        # rejection depends on those writes persisting in names[i].
                        dict[str, bool] seen = names[i]
                        if s in seen:
                            raise "TokenError: duplicate JSON member"
                        seen[s] = True
                        want_key[i] = False
            case _:
                auto ignored = 0
    match json.loads(text):
        case JsonValue.Object(fields):
            return fields
        case _:
            raise "TokenError: JWT header and payload must be JSON objects"

def _json_object(bytes raw) -> dict[str, JsonValue]:
    try:
        return _object(str(raw))
    except Exception as e:
        if e.startswith("TokenError:"):
            raise e
        raise "TokenError: invalid UTF-8 JSON object"

def _header(dict[str, JsonValue] header, str algorithm):
    if not "alg" in header:
        raise "AlgorithmError: missing alg header"
    auto actual = ""
    match header["alg"]:
        case JsonValue.Str(s):
            actual = s
        case _:
            raise "AlgorithmError: alg must be a string"
    if actual != algorithm:
        raise "AlgorithmError: alg does not match caller-selected algorithm"
    for name in ["crit", "b64", "jku", "x5u", "jwk", "x5c", "zip"]:
        if name in header:
            raise "HeaderError: unsupported header " + name
    for name in ["typ", "cty", "kid"]:
        if name in header:
            match header[name]:
                case JsonValue.Str(s):
                    auto ignored = 0
                case _:
                    raise "HeaderError: " + name + " must be a string"

def _sign(bytes key, str message, str algorithm) -> bytes:
    if algorithm == "HS256":
        return crypto.hmac_sha256_raw(key, message)
    if algorithm == "HS512":
        # Stdlib HS512 currently returns hex; decode once to the raw JWS signature.
        return hex.decode(crypto.hmac_sha512(key, message))
    if algorithm == "RS256":
        return crypto.rsa_sha256_sign(key, message)
    if algorithm == "ES256":
        # Fixed-width 64-byte JOSE r||s; the stdlib never exposes DER.
        return crypto.p256_sha256_sign(key, message)
    if algorithm == "EdDSA":
        return crypto.ed25519_sign(key, message)
    raise "AlgorithmError: supported algorithms are HS256, HS512, RS256, ES256 and EdDSA"

def _verify_sig(bytes key, str message, bytes signature, str algorithm) -> bool:
    if algorithm == "HS256" or algorithm == "HS512":
        return _same_signature(_sign(key, message, algorithm), signature)
    if algorithm == "RS256":
        return crypto.rsa_sha256_verify(key, message, signature)
    if algorithm == "ES256":
        # Rejects any signature that is not canonical 64-byte JOSE r||s.
        return crypto.p256_sha256_verify(key, message, signature)
    if algorithm == "EdDSA":
        return crypto.ed25519_verify(key, message, signature)
    # Unreachable: every caller first passes `algorithm` through `_is_hmac` or
    # `_check_asym_key`, both of which reject any identifier outside the five
    # branches above. A terminal `raise` (mirroring `_sign`) states that as a
    # programming error, rather than silently reporting an invalid signature.
    raise "AlgorithmError: supported algorithms are HS256, HS512, RS256, ES256 and EdDSA"

def _same_signature(bytes expected, bytes actual) -> bool:
    if len(expected) != len(actual):
        return False
    auto difference = 0
    for i in range(len(expected)):
        difference = difference | expected[i] ^ actual[i]
    return difference == 0

def _check_value(JsonValue value, int64 depth = 0):
    match value:
        case JsonValue.Object(fields):
            if depth >= 32:
                raise "TokenError: JSON nesting exceeds 32"
            for name in fields:
                _check_value(fields[name], depth + 1)
        case JsonValue.Array(items):
            if depth >= 32:
                raise "TokenError: JSON nesting exceeds 32"
            for item in items:
                _check_value(item, depth + 1)
        case JsonValue.Float(f):
            if math.isnan(f) or math.isinf(f):
                raise "TokenError: nonfinite JSON number"
        case _:
            auto ignored = 0

def encode(
    dict[str, JsonValue] claims,
    bytes key,
    str algorithm,
    dict[str, JsonValue] headers = {},
) -> str:
    if _is_hmac(algorithm):
        _key(key, algorithm)
    else:
        # Asymmetric signing requires the matching private key of the right family.
        _check_asym_key(key, algorithm, True)
    # Copy supplied headers rather than modifying a caller's reusable map.
    dict[str, JsonValue] header = {
        "alg": JsonValue.Str(algorithm),
        "typ": JsonValue.Str("JWT"),
    }
    for name in headers:
        header[name] = headers[name]
    _header(header, algorithm)
    _check_value(JsonValue.Object(header))
    _check_value(JsonValue.Object(claims))
    auto header_text = json.dumps(JsonValue.Object(header))
    auto payload_text = json.dumps(JsonValue.Object(claims))
    if len(bytes(header_text)) > 4096 or len(bytes(payload_text)) > 32768:
        raise "TokenError: JSON size limit exceeded"
    # Apply identical nesting/JSON checks on both creation and verification.
    _json_object(bytes(header_text))
    _json_object(bytes(payload_text))
    auto message = base64.urlsafe_encode_nopad(header_text) + "." + base64.urlsafe_encode_nopad(payload_text)
    return message + "." + base64.urlsafe_encode_nopad(_sign(key, message, algorithm))

def _compact_parts(str token) -> list[str]:
    if len(bytes(token)) > 50000:
        raise "TokenError: compact token exceeds 50000 bytes"
    auto parts = token.split(".")
    if len(parts) != 3:
        raise "TokenError: expected three compact segments"
    if len(parts[0]) > 5462 or len(parts[1]) > 43691:
        raise "TokenError: encoded JSON size limit exceeded"
    # 86 base64url chars hold a 64-byte HMAC/ES256/EdDSA signature; RSA signatures
    # scale with the modulus, so cap at an 8192-bit RSA signature (1366 chars).
    if len(parts[2]) > 1366:
        raise "TokenError: signature size limit exceeded"
    return parts

def verify_signature(str token, bytes key, str algorithm) -> VerifiedToken:
    # Only authenticates the signature. It does not validate exp/iss/aud/etc.
    if _is_hmac(algorithm):
        _key(key, algorithm)
    else:
        # Verification uses the public key only; a private key is rejected.
        _check_asym_key(key, algorithm, False)
    auto parts = _compact_parts(token)
    auto header_raw = _decode_segment(parts[0])
    auto signature = _decode_segment(parts[2])
    auto header = _json_object(header_raw)
    _header(header, algorithm)
    auto message = parts[0] + "." + parts[1]
    if not _verify_sig(key, message, signature, algorithm):
        raise "SignatureError: invalid signature"
    auto payload_raw = _decode_segment(parts[1])
    auto claims = _json_object(payload_raw)
    _check_value(JsonValue.Object(claims))
    return VerifiedToken(header, claims)

# Trusted application configuration. Registered claims are always checked when
# present; `required` controls which claims must also be present and non-null.
struct Policy:
    dict[str, str] expected = {}
    list[str] audiences = []
    list[str] required = ["exp"]
    str token_type = "JWT"
    float64 leeway = 0.0

def _policy(Policy policy):
    if math.isnan(policy.leeway) or math.isinf(policy.leeway):
        raise "PolicyError: leeway must be finite"
    if policy.leeway < 0.0 or policy.leeway > 86400.0:
        raise "PolicyError: leeway must be between 0 and 86400 seconds"
    if len(policy.token_type) == 0:
        raise "PolicyError: an expected token type is required"
    for name in policy.required:
        if len(name) == 0:
            raise "PolicyError: required claim names must be nonempty"
    for audience in policy.audiences:
        if len(audience) == 0:
            raise "PolicyError: expected audiences must be nonempty"
    for name in policy.expected:
        if name != "iss" and name != "sub" and name != "jti":
            raise "PolicyError: expected only accepts iss, sub and jti"

def _finite_date(float64 value) -> bool:
    # Every supported integer date is exactly representable as binary64. Compare
    # dates before subtracting them, rather than adding leeway to large dates.
    return not math.isnan(value) and not math.isinf(value) and value >= -9007199254740991.0 and value <= 9007199254740991.0

def _date(JsonValue value, str name) -> float64:
    match value:
        case JsonValue.Int(i):
            if i < -9007199254740991 or i > 9007199254740991:
                raise "ClaimsError: " + name + " exceeds the supported NumericDate range"
            return float64(i)
        case JsonValue.Float(f):
            if not _finite_date(f):
                raise "ClaimsError: " + name + " must be a finite supported NumericDate"
            return f
        case _:
            raise "ClaimsError: " + name + " must be a numeric date"

def _claim_string(JsonValue value, str name) -> str:
    match value:
        case JsonValue.Str(s):
            return s
        case _:
            raise "ClaimsError: " + name + " must be a string"

def _audiences(JsonValue value) -> list[str]:
    list[str] out = []
    match value:
        case JsonValue.Str(s):
            if len(s) == 0:
                raise "ClaimsError: aud must not be empty"
            out.append(s)
        case JsonValue.Array(items):
            if len(items) == 0:
                raise "ClaimsError: aud must not be empty"
            for item in items:
                auto s = _claim_string(item, "aud entry")
                if len(s) == 0:
                    raise "ClaimsError: aud entries must not be empty"
                out.append(s)
        case _:
            raise "ClaimsError: aud must be a string or string array"
    return out

def _verified_claims(
    VerifiedToken token,
    Policy policy,
    float64 now,
) -> dict[str, JsonValue]:
    _policy(policy)
    if not _finite_date(now):
        raise "PolicyError: clock must return a finite supported NumericDate"
    if not "typ" in token.header:
        raise "ClaimsError: missing token type"
    if _claim_string(token.header["typ"], "typ") != policy.token_type:
        raise "ClaimsError: token type mismatch"
    auto claims = token.claims
    for name in policy.required:
        if not name in claims:
            raise "ClaimsError: missing required claim " + name
        match claims[name]:
            case JsonValue.Null:
                raise "ClaimsError: required claim is null: " + name
            case _:
                auto ignored = 0
    for name in ["iss", "sub", "jti"]:
        if name in claims:
            _claim_string(claims[name], name)
    for name in policy.expected:
        if not name in claims:
            raise "ClaimsError: missing expected claim " + name
        if _claim_string(claims[name], name) != policy.expected[name]:
            raise "ClaimsError: " + name + " mismatch"
    if "aud" in claims:
        auto actual = _audiences(claims["aud"])
        if len(policy.audiences) == 0:
            raise "ClaimsError: aud requires an expected audience"
        auto matched = False
        for candidate in actual:
            for expected in policy.audiences:
                if candidate == expected:
                    matched = True
        if not matched:
            raise "ClaimsError: audience mismatch"
    else:
        if len(policy.audiences) > 0:
            raise "ClaimsError: missing audience"
    if "exp" in claims:
        auto expires = _date(claims["exp"], "exp")
        if now >= expires:
            if now - expires >= policy.leeway:
                raise "ClaimsError: token expired"
    for name in ["nbf", "iat"]:
        if name in claims:
            auto date = _date(claims[name], name)
            if date > now:
                if date - now > policy.leeway:
                    raise "ClaimsError: " + name + " is in the future"
    return claims

def decode_at(
    str token,
    bytes key,
    str algorithm,
    float64 now,
    Policy policy = Policy(),
) -> dict[str, JsonValue]:
    auto verified = verify_signature(token, key, algorithm)
    return _verified_claims(verified, policy, now)

def decode(
    str token,
    bytes key,
    str algorithm,
    Policy policy = Policy(),
) -> dict[str, JsonValue]:
    auto verified = verify_signature(token, key, algorithm)
    return _verified_claims(verified, policy, time.time())

# Loaded only from explicitly trusted, offline configuration.
struct Key:
    str kid
    str algorithm
    bytes material
    bool can_sign = True
    bool can_verify = True

struct KeySet:
    list[Key] keys = []

def _jwk_string(dict[str, JsonValue] fields, str name) -> str:
    if not name in fields:
        raise "JWKError: missing required key member " + name
    match fields[name]:
        case JsonValue.Str(s):
            return s
        case _:
            raise "JWKError: key member must be a string: " + name

def _key_record(Key key):
    if len(bytes(key.kid)) == 0 or len(bytes(key.kid)) > 128:
        raise "JWKError: kid must contain 1 through 128 UTF-8 bytes"
    if len(key.material) > 8192:
        raise "JWKError: key material exceeds 8192 bytes"
    try:
        if _is_hmac(key.algorithm):
            _key(key.material, key.algorithm)
        else:
            # Key-set entries are public verification keys; reject private keys.
            _check_asym_key(key.material, key.algorithm, False)
    except Exception:
        raise "JWKError: unsupported algorithm or insufficient key material"
    if not key.can_sign and not key.can_verify:
        raise "JWKError: key must permit sign or verify"

# Shared non-secret JWK metadata: identifier, bound algorithm and operations.
struct _JwkMeta:
    str kid
    str algorithm
    bool can_sign
    bool can_verify

# Reject the certificate, reference and critical-extension fields this
# trusted-offline profile omits, honour an optional "use":"sig", and resolve
# "key_ops" into (can_sign, can_verify). `kid` and `algorithm` are already read
# by the caller; every key type shares this tail so the rules live in one place.
# Callers invoke this at the exact point their own check order requires, so the
# oct and asym paths keep their existing, slightly different orderings.
def _jwk_meta_from(str kid, str algorithm, dict[str, JsonValue] fields) -> _JwkMeta:
    for name in ["x5u", "x5c", "x5t", "x5t#S256", "jku", "jwk", "crit", "b64"]:
        if name in fields:
            raise "JWKError: unsupported key reference or extension"
    if "use" in fields:
        if _jwk_string(fields, "use") != "sig":
            raise "JWKError: key use must be sig"
    auto can_sign = True
    auto can_verify = True
    if "key_ops" in fields:
        can_sign = False
        can_verify = False
        dict[str, bool] seen = {}
        match fields["key_ops"]:
            case JsonValue.Array(operations):
                if len(operations) == 0:
                    raise "JWKError: key_ops must not be empty"
                for operation in operations:
                    auto name = ""
                    match operation:
                        case JsonValue.Str(s):
                            name = s
                        case _:
                            raise "JWKError: key_ops entries must be strings"
                    if name in seen:
                        raise "JWKError: duplicate key operation"
                    seen[name] = True
                    if name == "sign":
                        can_sign = True
                    elif name == "verify":
                        can_verify = True
                    else:
                        raise "JWKError: key_ops only supports sign and verify"
            case _:
                raise "JWKError: key_ops must be an array"
    return _JwkMeta(kid, algorithm, can_sign, can_verify)

# Parse the members common to every asymmetric key type: identifier and bound
# algorithm first, then the shared extension/use/key_ops tail.
def _jwk_meta(dict[str, JsonValue] fields) -> _JwkMeta:
    auto kid = _jwk_string(fields, "kid")
    auto algorithm = _jwk_string(fields, "alg")
    return _jwk_meta_from(kid, algorithm, fields)

# Decode a required fixed base64url integer/octet component (RSA n/e, EC x/y,
# OKP x). The canonical unpadded base64url rule matches the compact profile.
def _jwk_component(dict[str, JsonValue] fields, str name) -> bytes:
    auto encoded = _jwk_string(fields, name)
    if len(encoded) == 0:
        raise "JWKError: key component must not be empty: " + name
    if len(encoded) > 10923:
        raise "JWKError: key component exceeds its limit: " + name
    try:
        return _decode_segment(encoded)
    except Exception:
        raise "JWKError: key component must be canonical unpadded base64url: " + name

def _parse_jwk(dict[str, JsonValue] fields) -> Key:
    auto kty = _jwk_string(fields, "kty")
    if kty == "RSA":
        return _parse_rsa_jwk(fields)
    if kty == "EC":
        return _parse_ec_jwk(fields)
    if kty == "OKP":
        return _parse_okp_jwk(fields)
    return _parse_oct_jwk(fields)

def _parse_oct_jwk(dict[str, JsonValue] fields) -> Key:
    if _jwk_string(fields, "kty") != "oct":
        raise "JWKError: only oct keys are supported"
    auto kid = _jwk_string(fields, "kid")
    auto algorithm = _jwk_string(fields, "alg")
    # Unlike the asymmetric keys (whose component is read after the shared
    # metadata tail), the oct secret is present-and-sized before that tail so the
    # error order is preserved exactly: kty, kid, alg, k presence, k size, then
    # the extension/use/key_ops checks that `_jwk_meta_from` performs.
    auto encoded = _jwk_string(fields, "k")
    if len(encoded) > 10923:
        raise "JWKError: encoded key material exceeds its limit"
    auto meta = _jwk_meta_from(kid, algorithm, fields)
    auto material = b""
    try:
        material = _decode_segment(encoded)
    except Exception:
        raise "JWKError: k must be canonical unpadded base64url"
    auto key = Key(kid, algorithm, material, meta.can_sign, meta.can_verify)
    _key_record(key)
    return key

# Reject the private-key members so a key set can only ever hold public keys.
def _reject_private_members(dict[str, JsonValue] fields, list[str] members):
    for name in members:
        if name in fields:
            raise "JWKError: only public keys are supported"

def _public_jwk_key(_JwkMeta meta, dict[str, JsonValue] fields, bytes material) -> Key:
    # Public keys can only verify; an explicit sign operation is contradictory.
    if "key_ops" in fields and meta.can_sign:
        raise "JWKError: public keys cannot sign"
    auto key = Key(meta.kid, meta.algorithm, material, False, meta.can_verify)
    _key_record(key)
    return key

def _parse_rsa_jwk(dict[str, JsonValue] fields) -> Key:
    auto meta = _jwk_meta(fields)
    if meta.algorithm != "RS256":
        raise "JWKError: RSA keys require the RS256 algorithm"
    _reject_private_members(fields, ["d", "p", "q", "dp", "dq", "qi", "oth"])
    auto n_bytes = _jwk_component(fields, "n")
    auto e_bytes = _jwk_component(fields, "e")
    auto material = b""
    try:
        material = crypto.rsa_public_key_pem(n_bytes, e_bytes)
    except Exception:
        raise "JWKError: invalid RSA public key parameters"
    return _public_jwk_key(meta, fields, material)

def _parse_ec_jwk(dict[str, JsonValue] fields) -> Key:
    auto meta = _jwk_meta(fields)
    if meta.algorithm != "ES256":
        raise "JWKError: EC keys require the ES256 algorithm"
    if _jwk_string(fields, "crv") != "P-256":
        raise "JWKError: ES256 requires the P-256 curve"
    _reject_private_members(fields, ["d"])
    auto x_bytes = _jwk_component(fields, "x")
    auto y_bytes = _jwk_component(fields, "y")
    auto material = b""
    try:
        material = crypto.p256_public_key_pem(x_bytes, y_bytes)
    except Exception:
        raise "JWKError: invalid EC public key parameters"
    return _public_jwk_key(meta, fields, material)

def _parse_okp_jwk(dict[str, JsonValue] fields) -> Key:
    auto meta = _jwk_meta(fields)
    if meta.algorithm != "EdDSA":
        raise "JWKError: OKP keys require the EdDSA algorithm"
    if _jwk_string(fields, "crv") != "Ed25519":
        raise "JWKError: EdDSA requires the Ed25519 curve"
    _reject_private_members(fields, ["d"])
    auto x_bytes = _jwk_component(fields, "x")
    auto material = b""
    try:
        material = crypto.ed25519_public_key_pem(x_bytes)
    except Exception:
        raise "JWKError: invalid OKP public key parameters"
    return _public_jwk_key(meta, fields, material)

def _jwk_document(str source) -> dict[str, JsonValue]:
    if len(bytes(source)) > 1048576:
        raise "JWKError: key document exceeds 1048576 bytes"
    try:
        auto fields = _json_object(bytes(source))
        _check_value(JsonValue.Object(fields))
        return fields
    except Exception:
        raise "JWKError: invalid or duplicate-member JSON key document"

def load_jwk(str source) -> Key:
    return _parse_jwk(_jwk_document(source))

def _key_set(KeySet keys):
    if len(keys.keys) == 0 or len(keys.keys) > 64:
        raise "JWKError: a key set must contain 1 through 64 keys"
    dict[str, bool] seen = {}
    for key in keys.keys:
        _key_record(key)
        if key.kid in seen:
            raise "JWKError: duplicate kid in key set"
        seen[key.kid] = True
        for other in keys.keys:
            if key.algorithm != other.algorithm and key.material == other.material:
                raise "JWKError: the same key material cannot bind different algorithms"

def load_jwks(str source) -> KeySet:
    auto fields = _jwk_document(source)
    if not "keys" in fields:
        raise "JWKError: missing keys array"
    list[Key] keys = []
    match fields["keys"]:
        case JsonValue.Array(items):
            if len(items) == 0 or len(items) > 64:
                raise "JWKError: a key set must contain 1 through 64 keys"
            for item in items:
                match item:
                    case JsonValue.Object(record):
                        keys.append(_parse_jwk(record))
                    case _:
                        raise "JWKError: key set entries must be objects"
        case _:
            raise "JWKError: keys must be an array"
    auto result = KeySet(keys)
    _key_set(result)
    return result

def encode_key(
    dict[str, JsonValue] claims,
    Key key,
    dict[str, JsonValue] headers = {},
) -> str:
    _key_record(key)
    if not key.can_sign:
        raise "JWKError: key does not permit signing"
    dict[str, JsonValue] copied = {}
    for name in headers:
        copied[name] = headers[name]
    if "kid" in copied:
        match copied["kid"]:
            case JsonValue.Str(s):
                if s != key.kid:
                    raise "JWKError: signing header kid conflicts with key"
            case _:
                raise "JWKError: signing header kid must be a string"
    copied["kid"] = JsonValue.Str(key.kid)
    return encode(claims, key.material, key.algorithm, copied)

def _allowed_algorithms(list[str] algorithms):
    if len(algorithms) == 0 or len(algorithms) > 5:
        raise "AlgorithmError: supply 1 through 5 supported algorithms"
    dict[str, bool] seen = {}
    for algorithm in algorithms:
        _require_algorithm(algorithm)
        if algorithm in seen:
            raise "AlgorithmError: allowed algorithms must be unique"
        seen[algorithm] = True

def _select_key(str token, KeySet keys, list[str] algorithms) -> Key:
    _allowed_algorithms(algorithms)
    # Validate even directly constructed or subsequently mutated configurations.
    # Duplicate IDs are never resolved by order or by trying arbitrary keys.
    _key_set(keys)
    auto parts = _compact_parts(token)
    auto header = _json_object(_decode_segment(parts[0]))
    if not "alg" in header:
        raise "AlgorithmError: missing alg header"
    auto algorithm = ""
    match header["alg"]:
        case JsonValue.Str(s):
            algorithm = s
        case _:
            raise "AlgorithmError: alg must be a string"
    auto allowed = False
    for candidate in algorithms:
        if candidate == algorithm:
            allowed = True
    if not allowed:
        raise "AlgorithmError: token algorithm is not allowed"
    _header(header, algorithm)
    if not "kid" in header:
        raise "KeySelectionError: missing kid"
    auto kid = ""
    match header["kid"]:
        case JsonValue.Str(s):
            kid = s
        case _:
            raise "KeySelectionError: kid must be a string"
    if len(bytes(kid)) == 0 or len(bytes(kid)) > 128:
        raise "KeySelectionError: kid is empty or too long"
    for key in keys.keys:
        if key.kid == kid:
            if key.algorithm != algorithm:
                raise "AlgorithmError: selected key algorithm does not match token"
            if not key.can_verify:
                raise "KeySelectionError: selected key does not permit verification"
            return key
    raise "KeySelectionError: unknown kid"

def verify_keyset_signature(
    str token,
    KeySet keys,
    list[str] algorithms,
) -> VerifiedToken:
    auto key = _select_key(token, keys, algorithms)
    return verify_signature(token, key.material, key.algorithm)

def decode_keyset_at(
    str token,
    KeySet keys,
    list[str] algorithms,
    float64 now,
    Policy policy = Policy(),
) -> dict[str, JsonValue]:
    auto verified = verify_keyset_signature(token, keys, algorithms)
    return _verified_claims(verified, policy, now)

def decode_keyset(
    str token,
    KeySet keys,
    list[str] algorithms,
    Policy policy = Policy(),
) -> dict[str, JsonValue]:
    auto verified = verify_keyset_signature(token, keys, algorithms)
    return _verified_claims(verified, policy, time.time())
