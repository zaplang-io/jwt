# Repeated sign/verify under allocation pressure to exercise the GC and confirm
# the encode/verify paths stay correct across many iterations for symmetric and
# asymmetric algorithms. Each iteration allocates fresh maps, strings and bytes.
import jwt

def main():
    auto rounds = 300

    # HS256 with a freshly generated secret.
    auto hkey = crypto.random_bytes(32)
    for i in range(rounds):
        auto token = jwt.encode(
            {"sub": JsonValue.Str("alice"), "n": JsonValue.Int(i)},
            hkey,
            "HS256",
        )
        auto v = jwt.verify_signature(token, hkey, "HS256")
        match v.claims["n"]:
            case JsonValue.Int(got):
                assert got == i
            case _:
                assert False

    # ES256 (randomized signature each round) round-trips with the public key.
    auto ec_priv = bytes(
        "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOdnFeCJxVc6WZ+Yh\nFqkLg2bhJ9Bo3wYHbK8PoHPF2vChRANCAARu7N0xFIR5O4GtdDJUcrnFYNLOVrVh\n5CV5xjQGH2up/GY7WpQ4WBli/ArjIt+CeoQFtMzM9KaIFogB2ZGpOzKG\n-----END PRIVATE KEY-----\n",
    )
    auto ec_pub = bytes(
        "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbuzdMRSEeTuBrXQyVHK5xWDSzla1\nYeQlecY0Bh9rqfxmO1qUOFgZYvwK4yLfgnqEBbTMzPSmiBaIAdmRqTsyhg==\n-----END PUBLIC KEY-----\n",
    )
    for i in range(rounds):
        auto token = jwt.encode(
            {"sub": JsonValue.Str("alice"), "n": JsonValue.Int(i)},
            ec_priv,
            "ES256",
        )
        auto v = jwt.verify_signature(token, ec_pub, "ES256")
        assert json.dumps(v.claims["sub"]) == "\"alice\""

    # EdDSA (deterministic) round-trips with the public key.
    auto ed_priv = bytes(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIPir7sSo5wp44H0Bp9w9l2n6j4JYKmBuOe1RbMdaXd2D\n-----END PRIVATE KEY-----\n",
    )
    auto ed_pub = bytes(
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAo8QjCOnUT+j/qtpX++u3z1Ejbf2UnNq9D41qXPEgcQs=\n-----END PUBLIC KEY-----\n",
    )
    for i in range(rounds):
        auto token = jwt.encode(
            {"sub": JsonValue.Str("alice"), "n": JsonValue.Int(i)},
            ed_priv,
            "EdDSA",
        )
        auto v = jwt.verify_signature(token, ed_pub, "EdDSA")
        assert json.dumps(v.claims["sub"]) == "\"alice\""

    print("repeated verification under GC: PASS")
