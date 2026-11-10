"""Command line entry point: `python -m pps`."""

from __future__ import annotations

import argparse
import dataclasses
import logging
import sys
from pathlib import Path

from .settings import Settings, SettingsError


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pps", description="Pocket Packet Sniffer server")
    ap.add_argument(
        "--host", help="bind address (default PPS_API_HOST or 127.0.0.1; 0.0.0.0 for LAN)"
    )
    ap.add_argument("--port", type=int, help="port (default PPS_API_PORT or 8443)")
    ap.add_argument("--data-dir", help="data folder (default PPS_DATA_DIR or ./data)")
    ap.add_argument("--no-tls", action="store_true", help="serve plain HTTP (development only)")
    ap.add_argument("--pin", help="fixed pairing PIN (default: random each start)")
    args = ap.parse_args(argv)

    import uvicorn

    from .api.app import create_app

    try:
        settings = Settings.from_env()
    except SettingsError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    overrides: dict = {}
    if args.host:
        overrides["api_host"] = args.host
    if args.port:
        overrides["api_port"] = args.port
    if args.data_dir:
        overrides["data_dir"] = Path(args.data_dir)
    if args.no_tls:
        overrides["tls_enabled"] = False
    settings = dataclasses.replace(settings, **overrides)
    app = create_app(settings, pin=args.pin)
    core = app.state.core
    admin_pw = core.auth.bootstrap_admin()

    ssl_kwargs: dict = {}
    scheme = "http"
    fp = None
    if settings.tls_enabled:
        from .tlsutil import ensure_cert  # PPS-SR-002

        cert, key, fp = ensure_cert(settings.data_dir / "tls")
        ssl_kwargs = {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}
        scheme = "https"

    shown_host = "localhost" if settings.api_host in ("127.0.0.1", "0.0.0.0") else settings.api_host
    bar = "=" * 62
    print(bar)
    print(" Pocket Packet Sniffer")
    print(f" Dashboard   : {scheme}://{shown_host}:{settings.api_port}/")
    print(f" Pairing PIN : {core.auth.pin}")
    if fp:
        print(f" TLS cert    : self-signed, SHA-256 {fp}")
    if admin_pw:
        print(f" First run   : user 'admin', password '{admin_pw}' (shown once, change it)")
    print(f" Data folder : {settings.data_dir.resolve()}")
    print(bar)
    sys.stdout.flush()
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    uvicorn.run(
        app, host=settings.api_host, port=settings.api_port, log_level="warning", **ssl_kwargs
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
