"""Shared fixtures. Imports of the app are lazy so early PRs (before the API exists) still run."""

import logging
import sys
from pathlib import Path

import pytest

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

PIN = "424242"
API = "/api/v1"


@pytest.fixture(scope="session")
def demo_dir(tmp_path_factory):
    import make_demo_pcaps

    d = tmp_path_factory.mktemp("replay")
    make_demo_pcaps.build_all(d)
    return d


@pytest.fixture
def app(tmp_path, demo_dir):
    from pps.api.app import create_app
    from pps.settings import Settings

    settings = Settings(data_dir=tmp_path / "data")
    settings.ensure_dirs()
    for f in demo_dir.iterdir():
        (settings.replay_dir / f.name).write_bytes(f.read_bytes())
    a = create_app(settings, pin=PIN)
    a.state.admin_password = a.state.core.auth.bootstrap_admin()
    yield a
    a.state.core.close()


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield c


def pair(client) -> str:
    r = client.post(f"{API}/pair", json={"pin": PIN, "client_name": "pytest"})
    assert r.status_code == 200, r.text
    return r.json()["client_token"]


def login(client, username: str, password: str) -> dict:
    ct = pair(client)
    r = client.post(f"{API}/auth/login", json={"username": username, "password": password},
                    headers={"x-pps-client": ct})
    assert r.status_code == 200, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def admin_h(client, app):
    return login(client, "admin", app.state.admin_password)


@pytest.fixture
def role_headers(client, app, admin_h):
    out = {"admin": admin_h}
    for role in ("analyst", "trainee"):
        body = {"username": role + "1", "password": "secret-pw", "role": role}
        r = client.post(f"{API}/users", json=body, headers=admin_h)
        assert r.status_code == 201, r.text
        out[role] = login(client, role + "1", "secret-pw")
    return out


def start_replay(client, h, name="demo_all.pcap", **kw):
    body = {"source_type": "replay", "source": name, "replay_speed": 0, **kw}
    r = client.post(f"{API}/captures", json=body, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def wait_idle(client, h, timeout=20):
    import time

    end = time.time() + timeout
    while time.time() < end:
        st = client.get(f"{API}/capture/status", headers=h).json()
        if st["state"] in ("IDLE", "ERROR"):
            return st
        time.sleep(0.05)
    raise AssertionError("capture did not finish")
