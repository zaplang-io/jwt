# Compact signed JWTs. Claim validation is deliberately a separate API/slice.
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

def _mac(bytes key, str message, str algorithm) -> bytes:
    if algorithm == "HS256":
        return crypto.hmac_sha256_raw(key, message)
    # Stdlib HS512 currently returns hex; decode once to the raw JWS signature.
    return hex.decode(crypto.hmac_sha512(key, message))

def _same_signature(bytes expected, bytes actual) -> bool:
    if len(expected) != len(actual):
        return False
    auto difference = 0
    for i in range(len(expected)):
        difference = difference | expected[i] ^ actual[i]
    return difference == 0

def encode(
    dict[str, JsonValue] claims,
    bytes key,
    str algorithm,
    dict[str, JsonValue] headers = {},
) -> str:
    _key(key, algorithm)
    # Copy supplied headers rather than modifying a caller's reusable map.
    dict[str, JsonValue] header = {
        "alg": JsonValue.Str(algorithm),
        "typ": JsonValue.Str("JWT"),
    }
    for name in headers:
        header[name] = headers[name]
    _header(header, algorithm)
    auto header_text = json.dumps(JsonValue.Object(header))
    auto payload_text = json.dumps(JsonValue.Object(claims))
    if len(bytes(header_text)) > 4096 or len(bytes(payload_text)) > 32768:
        raise "TokenError: JSON size limit exceeded"
    # Apply identical nesting/JSON checks on both creation and verification.
    _json_object(bytes(header_text))
    _json_object(bytes(payload_text))
    auto message = base64.urlsafe_encode_nopad(header_text) + "." + base64.urlsafe_encode_nopad(payload_text)
    return message + "." + base64.urlsafe_encode_nopad(_mac(key, message, algorithm))

def verify_signature(str token, bytes key, str algorithm) -> VerifiedToken:
    # Only authenticates the signature. It does not validate exp/iss/aud/etc.
    _key(key, algorithm)
    if len(bytes(token)) > 50000:
        raise "TokenError: compact token exceeds 50000 bytes"
    auto parts = token.split(".")
    if len(parts) != 3:
        raise "TokenError: expected three compact segments"
    if len(parts[0]) > 5462 or len(parts[1]) > 43691:
        raise "TokenError: encoded JSON size limit exceeded"
    if len(parts[2]) > 86:
        raise "TokenError: signature size limit exceeded"
    auto header_raw = _decode_segment(parts[0])
    auto signature = _decode_segment(parts[2])
    auto header = _json_object(header_raw)
    _header(header, algorithm)
    auto message = parts[0] + "." + parts[1]
    if not _same_signature(_mac(key, message, algorithm), signature):
        raise "SignatureError: invalid signature"
    auto payload_raw = _decode_segment(parts[1])
    auto claims = _json_object(payload_raw)
    return VerifiedToken(header, claims)
