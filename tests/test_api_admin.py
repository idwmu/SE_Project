"""TC-Cfg-02, TC-Sec-04/05 via the API: users, RBAC matrix, audit log."""

import json

from .conftest import API, PIN, login


def error_code(resp):
    return resp.json()["error"]["code"]


def patch_user(client, headers, username, **body):
    return client.patch(f"{API}/users/{username}", json=body, headers=headers)


def audit_status(client, headers, **params):
    return client.get(f"{API}/audit", params=params, headers=headers).status_code


def user_row(client, headers, username):
    users = client.get(f"{API}/users", headers=headers).json()
    return next(u for u in users if u["username"] == username)


# ------------------------------------------------------------------ role-based access
def test_rbac_matrix(client, role_headers):
    t, a, ad = role_headers["trainee"], role_headers["analyst"], role_headers["admin"]
    # trainee: read-only
    assert client.get(f"{API}/captures", headers=t).status_code == 200
    assert (
        client.post(f"{API}/captures", json={"source": "demo_all.pcap"}, headers=t).status_code
        == 403
    )
    assert (
        client.put(f"{API}/filters/presets/x", json={"expression": "dns"}, headers=t).status_code
        == 403
    )
    # analyst: no admin settings
    assert client.put(f"{API}/config", json={"max_packets": 5}, headers=a).status_code == 403
    assert client.get(f"{API}/users", headers=a).status_code == 403
    assert client.get(f"{API}/audit", headers=a).status_code == 403
    # admin: allowed
    assert client.put(f"{API}/config", json={"max_packets": 5}, headers=ad).status_code == 200


def test_admin_endpoints_require_auth(client):
    for method, path in (
        ("get", "/audit"),
        ("get", "/users"),
        ("post", "/users"),
        ("patch", "/users/admin"),
    ):
        assert getattr(client, method)(API + path).status_code == 401, (method, path)


def test_only_admins_may_manage_users_or_read_the_audit_log(client, role_headers):
    ad = role_headers["admin"]
    before = client.get(f"{API}/users", headers=ad).json()
    for role in ("analyst", "trainee"):
        h = role_headers[role]
        assert client.get(f"{API}/audit", headers=h).status_code == 403
        assert client.get(f"{API}/users", headers=h).status_code == 403
        body = {"username": "sneaky", "password": "secret-pw", "role": "admin"}
        assert client.post(f"{API}/users", json=body, headers=h).status_code == 403
        for patch in ({"role": "admin"}, {"active": False}, {"password": "attacker-pw1"}):
            assert client.patch(f"{API}/users/admin", json=patch, headers=h).status_code == 403
            # nor may they promote themselves
            assert client.patch(f"{API}/users/{role}1", json=patch, headers=h).status_code == 403
    assert client.get(f"{API}/users", headers=ad).json() == before  # nothing changed
    assert login(client, "admin", client.app.state.admin_password)  # admin password untouched


# ------------------------------------------------------------------ users (PPS-F-061)
def test_create_and_list_users(client, admin_h):
    r = client.post(
        f"{API}/users",
        json={"username": "  Alice.W ", "password": "secret-pw", "role": "Analyst"},
        headers=admin_h,
    )
    assert r.status_code == 201
    assert r.json() == {"username": "alice.w", "role": "analyst"}
    users = client.get(f"{API}/users", headers=admin_h).json()
    assert {"alice.w", "admin"} <= {u["username"] for u in users}
    assert all("pw_hash" not in u and "password" not in u for u in users)  # no hashes leak
    assert login(client, "alice.w", "secret-pw")


def test_create_user_validation(client, admin_h):
    def create(**kw):
        body = {"username": "someone", "password": "secret-pw", "role": "analyst", **kw}
        return client.post(f"{API}/users", json=body, headers=admin_h)

    assert create(username="admin").status_code == 400  # duplicate
    assert create(role="superuser").status_code == 400
    assert create(password="short").status_code == 400
    assert create(username="ab").status_code == 400
    assert create(username="bad name!").status_code == 400
    assert error_code(create(role="root")) == "BAD_REQUEST"
    assert [u["username"] for u in client.get(f"{API}/users", headers=admin_h).json()] == [
        "admin"
    ]


def test_role_assignment_takes_effect_immediately(client, role_headers):
    ad, t = role_headers["admin"], role_headers["trainee"]
    capture = {"source_type": "replay", "source": "demo_all.pcap", "replay_speed": 0}
    assert client.post(f"{API}/captures", json=capture, headers=t).status_code == 403
    r = client.patch(f"{API}/users/trainee1", json={"role": "analyst"}, headers=ad)
    assert r.status_code == 200
    assert user_row(client, ad, "trainee1")["role"] == "analyst"
    # the trainee's existing token now carries analyst rights, with no new login
    assert client.post(f"{API}/captures", json=capture, headers=t).status_code != 403
    client.patch(f"{API}/users/trainee1", json={"role": "trainee"}, headers=ad)
    assert client.post(f"{API}/captures", json=capture, headers=t).status_code == 403


def test_disabled_users_lose_access_at_once_and_can_be_re_enabled(client, role_headers):
    ad, a = role_headers["admin"], role_headers["analyst"]
    assert client.get(f"{API}/auth/me", headers=a).status_code == 200
    assert patch_user(client, ad, "analyst1", active=False).status_code == 200
    assert user_row(client, ad, "analyst1")["active"] in (0, False)
    assert client.get(f"{API}/auth/me", headers=a).status_code == 401  # token revoked
    token = client.post(f"{API}/pair", json={"pin": PIN, "client_name": "t"}).json()["client_token"]
    bad = client.post(
        f"{API}/auth/login",
        json={"username": "analyst1", "password": "secret-pw"},
        headers={"x-pps-client": token},
    )
    assert bad.status_code == 401
    assert patch_user(client, ad, "analyst1", active=True).status_code == 200
    again = login(client, "analyst1", "secret-pw")
    assert client.get(f"{API}/auth/me", headers=again).status_code == 200


def test_admin_can_reset_a_password(client, role_headers):
    ad, t = role_headers["admin"], role_headers["trainee"]
    r = client.patch(f"{API}/users/trainee1", json={"password": "new-secret-pw"}, headers=ad)
    assert r.status_code == 200
    assert client.get(f"{API}/auth/me", headers=t).status_code == 401  # old sessions end
    assert login(client, "trainee1", "new-secret-pw")


def test_patch_errors(client, admin_h):
    assert patch_user(client, admin_h, "ghost", role="analyst").status_code == 404
    assert patch_user(client, admin_h, "admin").status_code == 400  # nothing to change
    assert patch_user(client, admin_h, "admin", role="wizard").status_code == 400
    assert patch_user(client, admin_h, "admin", password="x").status_code == 400


def test_the_last_administrator_cannot_be_removed(client, admin_h):
    for patch in ({"role": "trainee"}, {"role": "analyst"}, {"active": False}):
        r = client.patch(f"{API}/users/admin", json=patch, headers=admin_h)
        assert r.status_code == 409, patch
        assert error_code(r) == "LAST_ADMIN"
    row = user_row(client, admin_h, "admin")
    assert (row["role"], row["active"]) == ("admin", 1)
    assert client.get(f"{API}/users", headers=admin_h).status_code == 200  # still an admin


def test_a_spare_administrator_makes_demotion_possible_but_only_once(client, admin_h):
    body = {"username": "boss2", "password": "secret-pw", "role": "admin"}
    assert client.post(f"{API}/users", json=body, headers=admin_h).status_code == 201
    boss2 = login(client, "boss2", "secret-pw")
    assert patch_user(client, boss2, "admin", role="analyst").status_code == 200
    r = patch_user(client, boss2, "boss2", active=False)
    assert r.status_code == 409 and error_code(r) == "LAST_ADMIN"


# ------------------------------------------------------------------ audit log (PPS-SR-005)
def test_audit_log_records_and_verifies(client, admin_h):
    client.put(f"{API}/config", json={"portscan_threshold": 25}, headers=admin_h)
    audit = client.get(f"{API}/audit", headers=admin_h).json()
    assert audit["verification"]["ok"] is True
    actions = [e["action"] for e in audit["entries"]]
    for needed in ("CONFIG_CHANGED", "LOGIN_OK", "PAIRING_OK", "USER_CREATED"):
        assert needed in actions


def test_user_management_is_audited_with_the_acting_admin(client, role_headers):
    ad = role_headers["admin"]
    client.patch(f"{API}/users/trainee1", json={"role": "analyst"}, headers=ad)
    client.patch(f"{API}/users/analyst1", json={"active": False}, headers=ad)
    client.patch(f"{API}/users/trainee1", json={"password": "new-secret-pw"}, headers=ad)
    entries = client.get(f"{API}/audit", headers=ad).json()["entries"]
    by_action = {e["action"]: e for e in entries}
    assert by_action["ROLE_CHANGED"]["actor"] == "admin"
    assert by_action["ROLE_CHANGED"]["details"] == {
        "user": "trainee1",
        "from": "trainee",
        "to": "analyst",
    }
    assert by_action["USER_DISABLED"]["details"] == {"user": "analyst1"}
    assert by_action["PASSWORD_CHANGED"]["details"] == {"user": "trainee1"}


def test_failed_logins_are_audited_without_secrets(client, app, admin_h):
    token = client.post(f"{API}/pair", json={"pin": PIN, "client_name": "probe"}).json()
    client.post(
        f"{API}/auth/login",
        json={"username": "admin", "password": "wrong-password-xyz"},
        headers={"x-pps-client": token["client_token"]},
    )
    client.post(f"{API}/pair", json={"pin": "000000", "client_name": "probe"})
    audit = client.get(f"{API}/audit", headers=admin_h).json()
    actions = [e["action"] for e in audit["entries"]]
    assert "LOGIN_FAILED" in actions and "PAIRING_FAILED" in actions
    dump = json.dumps([[e["actor"], e["action"], e["details"]] for e in audit["entries"]])
    for secret in (app.state.admin_password, "wrong-password-xyz", PIN, token["client_token"]):
        assert secret not in dump


def test_newest_entries_come_first_and_limit_applies(client, admin_h):
    for i in range(3):
        client.put(f"{API}/config", json={"portscan_threshold": 20 + i}, headers=admin_h)
    full = client.get(f"{API}/audit", headers=admin_h).json()
    ids = [e["id"] for e in full["entries"]]
    assert ids == sorted(ids, reverse=True)
    two = client.get(f"{API}/audit", params={"limit": 2}, headers=admin_h).json()
    assert [e["id"] for e in two["entries"]] == ids[:2]
    assert two["verification"]["entries"] == len(ids)  # verified over the whole chain, not the page


def test_audit_limit_is_validated(client, admin_h):
    for bad in (-1, 0, 2001, "x"):  # a negative LIMIT would make SQLite return every row
        assert audit_status(client, admin_h, limit=bad) == 422, bad
    for good in (1, 2000):
        assert audit_status(client, admin_h, limit=good) == 200


def test_tampering_with_the_log_is_reported_through_the_api(client, app, admin_h):
    for i in range(3):
        client.put(f"{API}/config", json={"portscan_threshold": 20 + i}, headers=admin_h)
    storage = app.state.core.storage
    target = storage.list_audit(100)[-2]["id"]  # an old entry, in the middle of the chain
    storage._exec("UPDATE audit_log SET actor='mallory' WHERE id=?", (target,))
    verification = client.get(f"{API}/audit", headers=admin_h).json()["verification"]
    assert verification["ok"] is False
    assert verification["broken_at"] == target


def test_deleting_an_entry_in_the_middle_is_reported(client, app, admin_h):
    for i in range(3):
        client.put(f"{API}/config", json={"portscan_threshold": 20 + i}, headers=admin_h)
    storage = app.state.core.storage
    middle = storage.list_audit(100)[2]["id"]
    storage._exec("DELETE FROM audit_log WHERE id=?", (middle,))
    assert client.get(f"{API}/audit", headers=admin_h).json()["verification"]["ok"] is False


def test_admin_tab_is_wired_into_the_dashboard(client):
    index = client.get("/").text
    assert '<script src="/static/js/admin.js"></script>' in index
    assert index.index("/static/js/core.js") < index.index("/static/js/admin.js")  # needs PPS
    script = client.get("/static/js/admin.js")
    assert script.status_code == 200 and "registerTab" in script.text
