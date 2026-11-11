"""TC-Sec-04 / TC-Sec-01 / TC-Sec-05: roles, pairing, login, lockout, tokens, privileges."""

import json
import threading

import pytest

from pps import auth
from pps.auth import (
    CLIENT_TOKEN_TTL_S,
    AuthenticationError,
    AuthorizationError,
    AuthService,
    LastAdminError,
    LockedOutError,
    Principal,
    Role,
    UserNotFoundError,
    UserValidationError,
    hash_password,
    require_role,
    verify_password,
)
from pps.settings import Settings
from pps.storage import Storage

PIN = "424242"
TTL = 60
LOCKOUT_S = 100
ATTEMPTS = 3


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    """Cheap scrypt cost so the suite stays fast; verify() reads cost from each stored hash."""
    monkeypatch.setattr(auth, "_N", 2**4)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(tmp_path):
    s = Storage(tmp_path / "t.db", tmp_path / "caps")
    yield s
    s.close()


@pytest.fixture
def svc(store, clock):
    cfg = Settings(
        token_ttl_s=TTL, pairing_lockout_attempts=ATTEMPTS, pairing_lockout_s=LOCKOUT_S
    )
    return AuthService(store, cfg, pin=PIN, clock=clock)


@pytest.fixture
def admin_pw(svc):
    return svc.bootstrap_admin()


def login(svc, username, password, client=None):
    client = client or svc.pair(PIN, "pytest")
    return svc.login(username, password, client)


def principal(svc, username, password):
    return svc.authenticate_token(login(svc, username, password).access_token)


@pytest.fixture
def admin(svc, admin_pw):
    return principal(svc, "admin", admin_pw)


@pytest.fixture
def users(svc, admin):
    """An analyst and a trainee, each with a known password and an authenticated Principal."""
    for name, role in (("analyst1", "analyst"), ("trainee1", "trainee")):
        svc.create_user(admin, name, "secret-pw", role)
    return {
        "admin": admin,
        "analyst": principal(svc, "analyst1", "secret-pw"),
        "trainee": principal(svc, "trainee1", "secret-pw"),
    }


def actions(store):
    return [r["action"] for r in store.list_audit()]


# ------------------------------------------------------------------ password hashing
def test_hash_is_salted_and_verifies():
    a, b = hash_password("correct horse"), hash_password("correct horse")
    assert a != b
    assert verify_password("correct horse", a) and verify_password("correct horse", b)
    assert not verify_password("correct horsf", a)
    assert "correct horse" not in a


def test_hash_uses_real_scrypt_cost_by_default(monkeypatch):
    monkeypatch.setattr(auth, "_N", 2**14)
    assert hash_password("correct horse").startswith("scrypt$16384$8$1$")


@pytest.mark.parametrize(
    "stored",
    [
        "",
        None,
        "plaintext",
        "scrypt$x",
        "md5$16$8$1$AAAA$AAAA",
        f"scrypt${2**30}$8$1$AAAA$AAAA",  # would demand ~hundreds of GiB: must be refused
        "scrypt$16$8$1$!!notbase64!!$AAAA",
        "scrypt$16$8$1$AAAA$AAAA$extra",
    ],
)
def test_verify_rejects_malformed_or_hostile_hashes(stored):
    assert verify_password("whatever1", stored) is False


def test_verify_rejects_oversized_password_without_hashing():
    stored = hash_password("correct horse")
    assert verify_password("x" * (auth.MAX_PASSWORD_LEN + 1), stored) is False


@pytest.mark.parametrize("bad", ["short", "x" * 129, "", None, 12345678])
def test_password_policy(bad):
    with pytest.raises(UserValidationError):
        hash_password(bad)


# ------------------------------------------------------------------ roles
def test_role_ordering_and_parsing():
    assert Role.TRAINEE.rank < Role.ANALYST.rank < Role.ADMIN.rank
    assert Role.parse("ADMIN") is Role.ADMIN
    for bad in ("root", "", None, 3, ["admin"]):
        with pytest.raises(UserValidationError, match="role must be one of"):
            Role.parse(bad)


@pytest.mark.parametrize(
    ("actual", "minimum", "allowed"),
    [
        (Role.ADMIN, Role.ADMIN, True),
        (Role.ADMIN, Role.ANALYST, True),
        (Role.ADMIN, Role.TRAINEE, True),
        (Role.ANALYST, Role.ADMIN, False),
        (Role.ANALYST, Role.ANALYST, True),
        (Role.ANALYST, Role.TRAINEE, True),
        (Role.TRAINEE, Role.ADMIN, False),
        (Role.TRAINEE, Role.ANALYST, False),
        (Role.TRAINEE, Role.TRAINEE, True),
    ],
)
def test_require_role_matrix(actual, minimum, allowed):
    p = Principal("u", actual)
    if allowed:
        require_role(p, minimum)
    else:
        with pytest.raises(AuthorizationError, match=minimum.value):
            require_role(p, minimum)


# ------------------------------------------------------------------ bootstrap
def test_bootstrap_creates_admin_once(svc, store):
    pw = svc.bootstrap_admin()
    assert pw and len(pw) >= auth.MIN_PASSWORD_LEN
    user = store.get_user("admin")
    assert (user["role"], user["active"]) == ("admin", 1)
    assert pw not in user["pw_hash"]
    assert svc.bootstrap_admin() is None  # never resets an existing install
    assert verify_password(pw, store.get_user("admin")["pw_hash"])
    assert "USER_CREATED" in actions(store)


# ------------------------------------------------------------------ pairing (PPS-SR-001)
def test_pairing_with_correct_pin(svc, store):
    token = svc.pair(PIN, "  Nia's phone ")
    assert svc.validate_client(token) == "Nia's phone"
    assert "PAIRING_OK" in actions(store)


@pytest.mark.parametrize("wrong", ["000000", "", "424242 ", None, 424242])
def test_pairing_rejects_wrong_pin(svc, wrong):
    with pytest.raises(AuthenticationError, match="Invalid PIN"):
        svc.pair(wrong, "phone")


def test_pairing_lockout_and_recovery(svc, clock, store):
    for _ in range(ATTEMPTS):
        with pytest.raises(AuthenticationError):
            svc.pair("111111", "attacker")
    with pytest.raises(LockedOutError) as exc:  # even the right PIN is refused while locked
        svc.pair(PIN, "attacker")
    assert 0 < exc.value.retry_after_s <= LOCKOUT_S
    assert "PAIRING_LOCKOUT" in actions(store)

    clock.advance(LOCKOUT_S + 1)
    assert svc.validate_client(svc.pair(PIN, "owner")) == "owner"


def test_successful_pairing_resets_the_failure_count(svc):
    for _ in range(ATTEMPTS - 1):
        with pytest.raises(AuthenticationError):
            svc.pair("111111", "x")
    svc.pair(PIN, "x")
    for _ in range(ATTEMPTS - 1):  # would lock if the earlier failures still counted
        with pytest.raises(AuthenticationError):
            svc.pair("111111", "x")


def test_failures_outside_the_window_are_forgotten(svc, clock):
    for _ in range(ATTEMPTS - 1):
        with pytest.raises(AuthenticationError):
            svc.pair("111111", "x")
    clock.advance(LOCKOUT_S + 1)
    with pytest.raises(AuthenticationError):  # a fresh window, not a lockout
        svc.pair("111111", "x")


@pytest.mark.parametrize("name", ["", "   ", "x" * 65, "bad\x00name", "new\nline", None])
def test_invalid_client_names_are_rejected_without_using_an_attempt(svc, name):
    with pytest.raises(UserValidationError):
        svc.pair(PIN, name)
    for _ in range(ATTEMPTS - 1):
        with pytest.raises(AuthenticationError):
            svc.pair("111111", "x")


def test_pin_format_is_validated(store):
    for bad in ("12345", "1234567890123", "abcdef", ""):
        with pytest.raises(UserValidationError):
            AuthService(store, pin=bad)
    assert len(AuthService(store).pin) == 6  # generated PINs are 6 digits


def test_client_token_expires(svc, clock):
    token = svc.pair(PIN, "phone")
    clock.advance(CLIENT_TOKEN_TTL_S - 1)
    svc.validate_client(token)
    clock.advance(2)
    with pytest.raises(AuthenticationError, match="not paired"):
        svc.validate_client(token)


def test_pin_rotation_is_admin_only_and_invalidates_the_old_pin(svc, users, store, monkeypatch):
    for role in ("analyst", "trainee"):
        with pytest.raises(AuthorizationError):
            svc.rotate_pin(users[role])
    assert svc.pin == PIN
    monkeypatch.setattr(auth, "generate_pin", lambda: "135790")
    assert svc.rotate_pin(users["admin"]) == "135790"
    with pytest.raises(AuthenticationError):
        svc.pair(PIN, "late")
    svc.pair("135790", "ok")
    assert "PAIRING_PIN_ROTATED" in actions(store)


# ------------------------------------------------------------------ login (PPS-SR-004)
def test_login_requires_a_paired_client(svc, admin_pw):
    for bad in (None, "", "garbage"):
        with pytest.raises(AuthenticationError, match="not paired"):
            svc.login("admin", admin_pw, bad)


def test_login_does_not_accept_an_access_token_as_client_token(svc, admin_pw):
    result = login(svc, "admin", admin_pw)
    with pytest.raises(AuthenticationError, match="not paired"):
        svc.login("admin", admin_pw, result.access_token)


def test_unpaired_login_attempts_do_not_count_toward_lockout(svc, admin_pw):
    for _ in range(ATTEMPTS + 2):
        with pytest.raises(AuthenticationError, match="not paired"):
            svc.login("admin", "wrong-password", None)
    login(svc, "admin", admin_pw)  # not locked


def test_login_returns_a_bearer_token_for_the_users_role(svc, admin_pw):
    result = login(svc, "ADMIN", admin_pw)  # usernames are case-insensitive
    assert (result.token_type, result.expires_in_s, result.role) == ("bearer", TTL, Role.ADMIN)
    assert svc.authenticate_token(result.access_token) == Principal("admin", Role.ADMIN)


def test_bad_password_and_unknown_user_are_indistinguishable(svc, admin_pw, store):
    client = svc.pair(PIN, "phone")
    messages = set()
    for name, pw in (("admin", "wrong-password"), ("nobody", "wrong-password")):
        with pytest.raises(AuthenticationError) as exc:
            svc.login(name, pw, client)
        messages.add(str(exc.value))
    assert messages == {"Invalid username or password"}
    reasons = [r["details"]["reason"] for r in store.list_audit() if r["action"] == "LOGIN_FAILED"]
    assert sorted(reasons) == ["bad_password", "unknown_user"]  # detail is for admins only


def test_unknown_user_still_costs_a_password_verification(svc, monkeypatch):
    calls = []
    real = auth.verify_password
    monkeypatch.setattr(auth, "verify_password", lambda p, s: calls.append(s) or real(p, s))
    client = svc.pair(PIN, "phone")
    with pytest.raises(AuthenticationError):
        svc.login("nobody", "wrong-password", client)
    # Verified against a real scrypt hash (same cost as a real account), so timing does not
    # reveal whether the name exists.
    assert calls == [svc._dummy_hash]
    assert svc._dummy_hash.startswith("scrypt$")


@pytest.mark.parametrize("username", [None, 123, "", "  ", "x" * 500, "bad name!"])
@pytest.mark.parametrize("password", [None, 123, "", "p" * 5000])
def test_malformed_credentials_fail_cleanly(svc, username, password):
    client = svc.pair(PIN, "phone")
    with pytest.raises(AuthenticationError):
        svc.login(username, password, client)


def test_login_lockout_is_per_username_and_expires(svc, admin_pw, clock, users):
    client = svc.pair(PIN, "phone")
    for _ in range(ATTEMPTS):
        with pytest.raises(AuthenticationError):
            svc.login("analyst1", "wrong-password", client)
    with pytest.raises(LockedOutError):  # the right password is refused while locked
        svc.login("analyst1", "secret-pw", client)
    svc.login("admin", admin_pw, client)  # other accounts are unaffected
    svc.login("trainee1", "secret-pw", client)

    clock.advance(LOCKOUT_S + 1)
    assert svc.login("analyst1", "secret-pw", client).username == "analyst1"


def test_lockout_applies_to_unknown_usernames_too(svc):
    client = svc.pair(PIN, "phone")
    for _ in range(ATTEMPTS):
        with pytest.raises(AuthenticationError):
            svc.login("ghost", "wrong-password", client)
    with pytest.raises(LockedOutError):  # same behaviour as a real account: no enumeration
        svc.login("ghost", "wrong-password", client)


def test_lockout_is_audited(svc, admin_pw, store):
    client = svc.pair(PIN, "phone")
    for _ in range(ATTEMPTS):
        with pytest.raises(AuthenticationError):
            svc.login("admin", "wrong-password", client)
    assert "LOGIN_LOCKOUT" in actions(store)


def test_access_token_expiry(svc, admin_pw, clock):
    token = login(svc, "admin", admin_pw).access_token
    clock.advance(TTL - 1)
    svc.authenticate_token(token)
    clock.advance(2)
    with pytest.raises(AuthenticationError, match="Invalid or expired"):
        svc.authenticate_token(token)


@pytest.mark.parametrize("token", [None, "", "garbage", 42])
def test_garbage_tokens_are_rejected(svc, token):
    with pytest.raises(AuthenticationError):
        svc.authenticate_token(token)


def test_client_token_is_not_an_access_token(svc):
    with pytest.raises(AuthenticationError):
        svc.authenticate_token(svc.pair(PIN, "phone"))


def test_logout_revokes_only_that_token(svc, admin_pw, store):
    t1 = login(svc, "admin", admin_pw).access_token
    t2 = login(svc, "admin", admin_pw).access_token
    assert t1 != t2
    svc.logout(t1)
    with pytest.raises(AuthenticationError):
        svc.authenticate_token(t1)
    svc.authenticate_token(t2)
    svc.logout("not-a-token")  # harmless
    assert actions(store).count("LOGOUT") == 1


def test_secrets_never_reach_the_audit_log(svc, admin_pw, store, users):
    client = svc.pair(PIN, "phone")
    token = svc.login("analyst1", "secret-pw", client).access_token
    with pytest.raises(AuthenticationError):
        svc.login("analyst1", "wrong-password-xyz", client)
    svc.change_own_password(users["analyst"], "secret-pw", "brand-new-pw")
    # actor/action/details only: the hash columns are hex and could match a short PIN by chance
    dump = json.dumps([[r["actor"], r["action"], r["details"]] for r in store.list_audit()])
    for secret in (admin_pw, "secret-pw", "wrong-password-xyz", "brand-new-pw", token, client, PIN):
        assert secret not in dump
    assert store.verify_audit()["ok"]


def test_unknown_role_in_database_denies_access(svc, store):
    store.upsert_user("mallory", hash_password("secret-pw"), "superuser")
    with pytest.raises(AuthenticationError):
        login(svc, "mallory", "secret-pw")


# ------------------------------------------------------------------ privilege boundaries
@pytest.mark.parametrize("role", ["analyst", "trainee"])
def test_non_admins_cannot_manage_users_or_pairing(svc, users, store, role):
    actor = users[role]
    before = {u["username"]: (u["role"], u["active"]) for u in store.list_users()}
    attempts = [
        lambda: svc.create_user(actor, "newuser", "secret-pw", "admin"),
        lambda: svc.set_role(actor, actor.username, "admin"),  # no self-promotion
        lambda: svc.set_role(actor, "admin", "trainee"),
        lambda: svc.set_active(actor, "admin", False),
        lambda: svc.reset_password(actor, "admin", "attacker-pw"),
        lambda: svc.rotate_pin(actor),
    ]
    for attempt in attempts:
        with pytest.raises(AuthorizationError):
            attempt()
    assert store.get_user("newuser") is None
    assert {u["username"]: (u["role"], u["active"]) for u in store.list_users()} == before
    assert verify_password("secret-pw", store.get_user(actor.username)["pw_hash"])
    assert svc.pin == PIN


def test_forged_lower_privilege_is_not_elevated_by_a_stale_token(svc, users):
    """A token minted while admin must not keep admin rights after a demotion."""
    svc.create_user(users["admin"], "boss2", "secret-pw", "admin")
    token = login(svc, "boss2", "secret-pw").access_token
    assert svc.authenticate_token(token).role is Role.ADMIN
    svc.set_role(users["admin"], "boss2", "trainee")
    assert svc.authenticate_token(token).role is Role.TRAINEE
    with pytest.raises(AuthorizationError):
        require_role(svc.authenticate_token(token), Role.ADMIN)


def test_token_check_rejects_users_disabled_behind_the_services_back(svc, users, store):
    """Defence in depth: a user disabled directly in storage (or a removed row) loses access."""
    token = login(svc, "analyst1", "secret-pw").access_token
    store.upsert_user("analyst1", None, "analyst", active=False)
    with pytest.raises(AuthenticationError):
        svc.authenticate_token(token)
    token2 = login(svc, "trainee1", "secret-pw").access_token
    store._exec("DELETE FROM users WHERE username=?", ("trainee1",))
    with pytest.raises(AuthenticationError):
        svc.authenticate_token(token2)


def test_disabling_a_user_revokes_their_sessions_immediately(svc, users, store):
    token = login(svc, "analyst1", "secret-pw").access_token
    svc.authenticate_token(token)
    svc.set_active(users["admin"], "analyst1", False)
    with pytest.raises(AuthenticationError):
        svc.authenticate_token(token)
    with pytest.raises(AuthenticationError):
        login(svc, "analyst1", "secret-pw")
    svc.set_active(users["admin"], "analyst1", True)
    assert login(svc, "analyst1", "secret-pw").username == "analyst1"
    assert {"USER_DISABLED", "USER_ENABLED"} <= set(actions(store))


# ------------------------------------------------------------------ user management (PPS-F-061)
def test_create_user_normalises_and_audits(svc, admin, store):
    svc.create_user(admin, "  Alice.W ", "secret-pw", "Analyst")
    user = store.get_user("alice.w")
    assert (user["role"], user["active"]) == ("analyst", 1)
    assert "secret-pw" not in user["pw_hash"]
    created = [r for r in store.list_audit() if r["details"].get("user") == "alice.w"]
    assert created[0]["actor"] == "admin" and created[0]["details"]["role"] == "analyst"


@pytest.mark.parametrize("name", ["ab", "-bad", "has space", "x" * 33, "semi;colon", "", None, 5])
def test_create_user_rejects_bad_usernames(svc, admin, name):
    with pytest.raises(UserValidationError, match="username"):
        svc.create_user(admin, name, "secret-pw", "analyst")


def test_create_user_rejects_duplicates_bad_roles_and_weak_passwords(svc, admin, store):
    with pytest.raises(UserValidationError, match="already exists"):
        svc.create_user(admin, "ADMIN", "secret-pw", "analyst")
    with pytest.raises(UserValidationError, match="role"):
        svc.create_user(admin, "someone", "secret-pw", "superuser")
    with pytest.raises(UserValidationError, match="password"):
        svc.create_user(admin, "someone", "short", "analyst")
    assert store.get_user("someone") is None
    assert store.user_count() == 1


def test_change_own_password_requires_the_current_one(svc, users):
    analyst = users["analyst"]
    old_token = login(svc, "analyst1", "secret-pw").access_token
    with pytest.raises(AuthenticationError):
        svc.change_own_password(analyst, "not-my-password", "brand-new-pw")
    svc.change_own_password(analyst, "secret-pw", "brand-new-pw")
    with pytest.raises(AuthenticationError):  # old sessions die with the old password
        svc.authenticate_token(old_token)
    with pytest.raises(AuthenticationError):
        login(svc, "analyst1", "secret-pw")
    assert login(svc, "analyst1", "brand-new-pw").username == "analyst1"


def test_change_own_password_guesses_are_rate_limited(svc, users):
    for _ in range(ATTEMPTS):
        with pytest.raises(AuthenticationError):
            svc.change_own_password(users["analyst"], "guess-guess", "brand-new-pw")
    with pytest.raises(LockedOutError):  # a stolen session cannot brute-force the password
        svc.change_own_password(users["analyst"], "secret-pw", "brand-new-pw")


def test_wrong_current_password_is_audited_as_a_password_change_failure(svc, users, store):
    with pytest.raises(AuthenticationError):
        svc.change_own_password(users["analyst"], "not-my-password", "brand-new-pw")
    seen = actions(store)
    assert "PASSWORD_CHANGE_FAILED" in seen
    assert "LOGIN_FAILED" not in seen
    for _ in range(ATTEMPTS - 1):  # one failure already recorded; this one reaches the limit
        with pytest.raises(AuthenticationError):
            svc.change_own_password(users["analyst"], "not-my-password", "brand-new-pw")
    assert "PASSWORD_CHANGE_LOCKOUT" in actions(store)


def test_new_password_must_meet_policy(svc, users):
    with pytest.raises(UserValidationError):
        svc.change_own_password(users["analyst"], "secret-pw", "short")
    assert login(svc, "analyst1", "secret-pw")


def test_admin_reset_revokes_target_sessions(svc, users):
    token = login(svc, "trainee1", "secret-pw").access_token
    svc.reset_password(users["admin"], "trainee1", "reset-by-admin")
    with pytest.raises(AuthenticationError):
        svc.authenticate_token(token)
    assert login(svc, "trainee1", "reset-by-admin").role is Role.TRAINEE


def test_operations_on_unknown_users(svc, admin):
    for op in (
        lambda: svc.set_role(admin, "ghost", "analyst"),
        lambda: svc.set_active(admin, "ghost", False),
        lambda: svc.reset_password(admin, "ghost", "secret-pw"),
    ):
        with pytest.raises(UserNotFoundError):
            op()


def test_role_change_is_audited_with_before_and_after(svc, users, store):
    svc.set_role(users["admin"], "trainee1", "analyst")
    entry = next(r for r in store.list_audit() if r["action"] == "ROLE_CHANGED")
    assert entry["details"] == {"user": "trainee1", "from": "trainee", "to": "analyst"}


# ------------------------------------------------------------------ last administrator
def test_last_admin_cannot_be_demoted_or_disabled(svc, admin, store):
    with pytest.raises(LastAdminError):
        svc.set_role(admin, "admin", "analyst")
    with pytest.raises(LastAdminError):
        svc.set_active(admin, "admin", False)
    user = store.get_user("admin")
    assert (user["role"], user["active"]) == ("admin", 1)
    svc.set_role(admin, "admin", "admin")  # no-ops are fine
    svc.set_active(admin, "admin", True)


def test_admin_can_be_removed_when_another_active_admin_exists(svc, admin):
    svc.create_user(admin, "boss2", "secret-pw", "admin")
    svc.set_role(admin, "boss2", "analyst")  # admin is still there
    svc.set_role(admin, "boss2", "admin")
    svc.set_active(admin, "boss2", False)
    with pytest.raises(LastAdminError):  # a disabled admin does not count as a spare
        svc.set_role(admin, "admin", "trainee")


def test_two_admins_cannot_demote_each_other_into_zero(svc, admin):
    svc.create_user(admin, "boss2", "secret-pw", "admin")
    boss2 = principal(svc, "boss2", "secret-pw")
    svc.set_role(boss2, "admin", "analyst")
    with pytest.raises(LastAdminError):
        svc.set_role(boss2, "boss2", "analyst")


# ------------------------------------------------------------------ memory bound
def test_tracked_lockout_state_has_a_hard_bound_and_keeps_live_lockouts(svc, monkeypatch):
    monkeypatch.setattr(auth, "_MAX_TRACKED_KEYS", 5)
    client = svc.pair(PIN, "phone")
    for _ in range(ATTEMPTS):
        with pytest.raises(AuthenticationError):
            svc.login("victim", "wrong-password", client)
    for i in range(30):  # flood of distinct, throwaway usernames inside one window
        with pytest.raises(AuthenticationError):
            svc.login(f"ghost{i}", "wrong-password", client)
        assert len(svc._login_limiter._state) <= 5
    with pytest.raises(LockedOutError):  # the existing lockout survived the flood
        svc.login("victim", "wrong-password", client)


def test_bound_still_holds_when_every_tracked_key_is_locked(svc, monkeypatch):
    monkeypatch.setattr(auth, "_MAX_TRACKED_KEYS", 3)
    client = svc.pair(PIN, "phone")
    for i in range(6):
        for _ in range(ATTEMPTS):
            with pytest.raises(AuthenticationError):
                svc.login(f"ghost{i}", "wrong-password", client)
            if len(svc._login_limiter._state) > 3:
                pytest.fail("tracked state exceeded its bound")


# ------------------------------------------------------------------ concurrency
def test_lockout_holds_under_concurrent_guessing(svc):
    outcomes = []

    def guess():
        try:
            svc.pair("111111", "attacker")
        except AuthenticationError:
            outcomes.append("wrong")
        except LockedOutError:
            outcomes.append("locked")

    threads = [threading.Thread(target=guess) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("wrong") == ATTEMPTS  # never more than the allowed guesses
    assert outcomes.count("locked") == 40 - ATTEMPTS
