"""Command line: tlswatch check | serve | capabilities."""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tlswatch import __version__, report
from tlswatch.checks import worse_than
from tlswatch.config import ConfigError, Settings, load, parse_target
from tlswatch.exporter import Exporter
from tlswatch.model import GRADES, STARTTLS_PROTOCOLS, HostReport, Target
from tlswatch.probe import local_capabilities
from tlswatch.scan import scan_all


@dataclass(frozen=True, slots=True)
class Options:
    timeout: float
    warn_days: float
    critical_days: float
    workers: int
    min_grade: str


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="host, host:port, [v6]:port or smtp://host[:port]",
    )
    parser.add_argument("-c", "--config", type=Path, help="TOML file with [settings] and [[hosts]]")
    parser.add_argument(
        "--starttls",
        choices=STARTTLS_PROTOCOLS,
        help="upgrade the command-line targets with STARTTLS",
    )
    parser.add_argument(
        "--server-name", help="SNI and the name to verify, when it differs from the host"
    )
    parser.add_argument(
        "--ca-file", help="PEM file with extra trusted CA certificates (private CA)"
    )
    parser.add_argument("--timeout", type=float, help="seconds per connection (default 5)")
    parser.add_argument(
        "--warn-days", type=float, help="warn this many days before expiry (default 30)"
    )
    parser.add_argument(
        "--critical-days", type=float, help="critical this many days before expiry (default 7)"
    )
    parser.add_argument("--workers", type=int, help="hosts probed at the same time (default 8)")
    parser.add_argument("--min-grade", choices=GRADES, help="worst acceptable grade (default B)")
    parser.add_argument(
        "--no-protocols", action="store_true", help="skip the protocol-version probes"
    )
    parser.add_argument("--no-ciphers", action="store_true", help="skip the weak-cipher probes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tlswatch", description="Check TLS certificates and configuration."
    )
    parser.add_argument("--version", action="version", version=f"tlswatch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="check hosts once and print a report")
    _common(check)
    check.add_argument("--format", choices=("text", "json", "prometheus"), default="text")
    check.add_argument("-o", "--output", type=Path, help="write the report to a file")

    serve = sub.add_parser("serve", help="scan on a schedule and expose Prometheus metrics")
    _common(serve)
    serve.add_argument(
        "--listen", default="127.0.0.1:9117", help="address:port (default 127.0.0.1:9117)"
    )
    serve.add_argument(
        "--interval", type=float, default=300, help="seconds between scans (default 300)"
    )

    sub.add_parser("capabilities", help="show which probes this machine's OpenSSL can run")
    return parser


def _settings(args: argparse.Namespace) -> tuple[list[Target], Options]:
    file_settings = load(args.config) if args.config else Settings()
    targets = [
        parse_target(
            text, starttls=args.starttls, server_name=args.server_name, ca_file=args.ca_file
        )
        for text in args.targets
    ]
    targets += file_settings.targets

    def pick(name: str, default: Any) -> Any:
        value = getattr(args, name, None)
        if value is None:
            value = getattr(file_settings, name)
        return default if value is None else value

    options = Options(
        timeout=float(pick("timeout", 5.0)),
        warn_days=float(pick("warn_days", 30.0)),
        critical_days=float(pick("critical_days", 7.0)),
        workers=int(pick("workers", 8)),
        min_grade=str(pick("min_grade", "B")),
    )
    if options.critical_days > options.warn_days:
        raise ConfigError("critical_days cannot be larger than warn_days")
    if not targets:
        raise ConfigError("no hosts to check: give TARGET arguments or --config with [[hosts]]")
    return targets, options


def _scan(targets: list[Target], options: Options, args: argparse.Namespace) -> list[HostReport]:
    return scan_all(
        targets,
        workers=options.workers,
        timeout=options.timeout,
        warn_days=options.warn_days,
        critical_days=options.critical_days,
        protocols=not args.no_protocols,
        ciphers=not args.no_ciphers,
    )


def _check(args: argparse.Namespace) -> int:
    targets, options = _settings(args)
    reports = _scan(targets, options, args)
    min_grade = options.min_grade
    if args.format == "json":
        out = report.to_json(reports, min_grade)
    elif args.format == "prometheus":
        out = report.prometheus(reports)
    else:
        out = report.text(reports, min_grade)
    if args.output:
        args.output.write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    return 1 if any(worse_than(r.grade, min_grade) for r in reports) else 0


def _address(text: str) -> tuple[str, int]:
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit() or not 0 <= int(port) < 65536:
        raise ConfigError(f"--listen must look like 127.0.0.1:9117, got {text!r}")
    return host.strip("[]") or "127.0.0.1", int(port)


def _serve(args: argparse.Namespace) -> int:
    targets, options = _settings(args)
    if args.interval < 1:
        raise ConfigError("--interval must be at least 1 second")
    exporter = Exporter(
        lambda: _scan(targets, options, args), interval=args.interval, address=_address(args.listen)
    )
    stopping = threading.Event()

    def stop(signum: int, frame: object) -> None:
        if not stopping.is_set():
            stopping.set()
            threading.Thread(target=exporter.close, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)
    print(
        f"tlswatch: {len(targets)} hosts, metrics on http://{args.listen}/metrics", file=sys.stderr
    )
    exporter.serve_forever()
    return 0


def _capabilities() -> int:
    for name, available in local_capabilities().items():
        print(
            f"{name:<18} {'can be tested' if available else 'NOT available in this OpenSSL (reported as untestable)'}"
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check":
            return _check(args)
        if args.command == "serve":
            return _serve(args)
        return _capabilities()
    except ConfigError as exc:
        print(f"tlswatch: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"tlswatch: {exc.strerror or exc}", file=sys.stderr)
        return 2
