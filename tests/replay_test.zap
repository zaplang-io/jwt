# Exhaustive coverage of the opt-in replay cache (#11 item 10): admission,
# replay rejection, required jti/exp, jti hygiene, expiry-based forgetting, and
# bounded-capacity eviction. Treated as intent documentation for the walled
# garden around replay protection.
import jwt

def claims(str jti = "a", int64 exp = 200) -> dict[str, JsonValue]:
    return {"jti": JsonValue.Str(jti), "exp": JsonValue.Int(exp)}

def expect_ok(jwt.ReplayCache cache, dict[str, JsonValue] c, float64 now):
    jwt.replay_admit_at(cache, c, now)

def expect_err(jwt.ReplayCache cache, dict[str, JsonValue] c, float64 now, str msg):
    auto observed = "accepted"
    try:
        jwt.replay_admit_at(cache, c, now)
    except Exception as e:
        observed = e
    if observed != msg:
        raise "want [" + msg + "] got [" + observed + "]"

def main():
    auto m_replay = "ClaimsError: token replay detected"
    auto m_jti_req = "ClaimsError: jti is required for replay protection"
    auto m_exp_req = "ClaimsError: exp is required for replay protection"
    auto m_jti_str = "ClaimsError: jti must be a string"
    auto m_jti_empty = "ClaimsError: jti must not be empty"
    auto m_jti_long = "ClaimsError: jti exceeds 256 bytes"
    auto m_exp_num = "ClaimsError: exp must be a numeric date"
    auto m_full = "ClaimsError: replay cache capacity exceeded"
    auto cache = jwt.new_replay_cache()
    # First sighting admits; a second sighting of the same live jti is a replay.
    expect_ok(cache, claims("a", 200), 100.0)
    expect_err(cache, claims("a", 200), 100.0, m_replay)
    # A different jti is independent.
    expect_ok(cache, claims("b", 200), 100.0)
    # jti and exp are both mandatory for replay protection.
    auto no_jti = {"exp": JsonValue.Int(200)}
    auto no_exp = {"jti": JsonValue.Str("c")}
    expect_err(cache, no_jti, 100.0, m_jti_req)
    expect_err(cache, no_exp, 100.0, m_exp_req)
    # jti hygiene: non-string, empty, and over-long are rejected.
    auto int_jti = {"jti": JsonValue.Int(1), "exp": JsonValue.Int(200)}
    expect_err(cache, int_jti, 100.0, m_jti_str)
    expect_err(cache, claims("", 200), 100.0, m_jti_empty)
    auto longjti = "a"
    for i in range(9):
        longjti = longjti + longjti
    expect_err(cache, claims(longjti, 200), 100.0, m_jti_long)
    # exp must be a numeric date.
    auto str_exp = {"jti": JsonValue.Str("d"), "exp": JsonValue.Str("x")}
    expect_err(cache, str_exp, 100.0, m_exp_num)
    # An expired entry is forgotten: the same jti may be admitted again once its
    # prior token's exp has passed, and then replaying the new one is rejected.
    expect_ok(cache, claims("e", 200), 100.0)
    expect_ok(cache, claims("e", 400), 300.0)
    expect_err(cache, claims("e", 400), 350.0, m_replay)
    # Bounded capacity: a full cache with no expired entries rejects new jtis,
    # then admits once expiry frees room.
    auto small = jwt.new_replay_cache(2)
    expect_ok(small, claims("x1", 1000), 100.0)
    expect_ok(small, claims("x2", 1000), 100.0)
    expect_err(small, claims("x3", 1000), 100.0, m_full)
    expect_ok(small, claims("x3", 5000), 2000.0)
    expect_err(small, claims("x3", 5000), 3000.0, m_replay)
    # Capacity bounds are validated at construction.
    auto rejected = False
    try:
        jwt.new_replay_cache(0)
    except Exception as e:
        rejected = e.startswith("PolicyError:")
    assert rejected
    # The now-less convenience uses the system clock; a far-future exp stays live.
    auto live = jwt.new_replay_cache()
    jwt.replay_admit(live, claims("f", 9007199254740991))
    auto replayed = False
    try:
        jwt.replay_admit(live, claims("f", 9007199254740991))
    except Exception as e:
        replayed = e.startswith("ClaimsError:")
    assert replayed
    print("replay cache: PASS")
