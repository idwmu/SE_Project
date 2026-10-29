from pathlib import Path

import pytest

from pps.settings import Settings, SettingsError


def test_defaults_are_safe():
    s = Settings.from_env({})
    assert s.interface is None
    assert s.capture_duration_s is None
    assert s.capture_packet_limit is None
    assert s.api_host == "127.0.0.1"
    assert s.api_port == 8443
    assert s.tls_enabled is True
    assert s.data_dir == Path("data")


def test_env_overrides_are_parsed():
    s = Settings.from_env(
        {
            "PPS_INTERFACE": " wlan0 ",
            "PPS_CAPTURE_DURATION_S": "60",
            "PPS_CAPTURE_PACKET_LIMIT": "5000",
            "PPS_API_PORT": "9000",
            "PPS_TLS_ENABLED": "off",
            "PPS_DATA_DIR": "/var/lib/pps",
            "PPS_PORT_SCAN_THRESHOLD": "50",
        }
    )
    assert s.interface == "wlan0"
    assert s.capture_duration_s == 60
    assert s.capture_packet_limit == 5000
    assert s.api_port == 9000
    assert s.tls_enabled is False
    assert s.data_dir == Path("/var/lib/pps")
    assert s.port_scan_threshold == 50


def test_blank_values_fall_back_to_defaults():
    s = Settings.from_env({"PPS_INTERFACE": "  ", "PPS_API_PORT": ""})
    assert s.interface is None
    assert s.api_port == 8443


def test_unrelated_env_vars_are_ignored():
    assert Settings.from_env({"HOME": "/home/x", "API_PORT": "1"}) == Settings()


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("PPS_API_PORT", "not-a-number"),
        ("PPS_API_PORT", "0"),
        ("PPS_API_PORT", "70000"),
        ("PPS_TLS_ENABLED", "maybe"),
        ("PPS_CAPTURE_DURATION_S", "-5"),
        ("PPS_CAPTURE_PACKET_LIMIT", "0"),
        ("PPS_PORT_SCAN_THRESHOLD", "1"),
        ("PPS_PORT_SCAN_WINDOW_S", "0"),
        ("PPS_STORAGE_WARN_PERCENT", "100"),
    ],
)
def test_invalid_values_are_rejected(var, value):
    with pytest.raises(SettingsError):
        Settings.from_env({var: value})


def test_error_message_names_the_variable():
    with pytest.raises(SettingsError, match="PPS_API_PORT"):
        Settings.from_env({"PPS_API_PORT": "abc"})


def test_settings_are_immutable():
    s = Settings()
    with pytest.raises(AttributeError):
        s.api_port = 1  # type: ignore[misc]


def test_reads_process_environment_by_default(monkeypatch):
    monkeypatch.setenv("PPS_INTERFACE", "wlan1")
    assert Settings.from_env().interface == "wlan1"
