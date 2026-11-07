"""Host lists: from the command line (`host:port`, `smtp://host`) or a TOML file."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from tlswatch.model import GRADES, STARTTLS_PROTOCOLS, Target

DEFAULT_PORTS = {"smtp": 25, "imap": 143, "pop3": 110}
_SETTING_KEYS = {"timeout", "warn_days", "critical_days", "workers", "min_grade"}
_HOST_KEYS = {"host", "port", "server_name", "starttls", "ca_file"}


class ConfigError(ValueError):
    """A target or a configuration file that cannot be used."""


@dataclass(slots=True)
class Settings:
    targets: list[Target] = field(default_factory=list)
    timeout: float | None = None
    warn_days: float | None = None
    critical_days: float | None = None
    workers: int | None = None
    min_grade: str | None = None


def _port(text: str) -> int:
    if not text.isdigit() or not 0 < int(text) < 65536:
        raise ConfigError(f"invalid port {text!r}")
    return int(text)


def parse_target(
    text: str,
    *,
    starttls: str | None = None,
    server_name: str | None = None,
    ca_file: str | None = None,
) -> Target:
    """`host`, `host:port`, `[v6]:port` or `smtp://host[:port]` (smtp, imap, pop3, tls, https)."""
    rest = text.strip()
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
        scheme = scheme.lower()
        if scheme in STARTTLS_PROTOCOLS:
            starttls = scheme
        elif scheme not in ("tls", "https"):
            raise ConfigError(f"unknown scheme {scheme!r} in {text!r}")
    rest = rest.rstrip("/")
    port: int | None = None
    if rest.startswith("["):
        host, closed, tail = rest[1:].partition("]")
        if not closed:
            raise ConfigError(f"missing ] in {text!r}")
        if tail.startswith(":"):
            port = _port(tail[1:])
        elif tail:
            raise ConfigError(f"cannot read {text!r}")
    elif rest.count(":") == 1:
        host, _, tail = rest.partition(":")
        port = _port(tail)
    else:
        host = rest  # a name, or a bare IPv6 address
    if not host or any(ch.isspace() or ch in "/?#@" for ch in host):
        raise ConfigError(f"cannot read a host name from {text!r}")
    if starttls is not None and starttls not in STARTTLS_PROTOCOLS:
        raise ConfigError(f"unknown STARTTLS protocol {starttls!r}")
    if port is None:
        port = DEFAULT_PORTS.get(starttls or "", 443)
    return Target(host, port, server_name, starttls, ca_file)


def _number(value: object, key: str, minimum: float = 0) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < minimum:
        raise ConfigError(f"{key} must be a number >= {minimum:g}")
    return float(value)


def load(path: Path) -> Settings:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    unknown = set(data) - {"settings", "hosts"}
    if unknown:
        raise ConfigError(f"{path}: unknown section {sorted(unknown)[0]!r}")
    settings = Settings()
    section = data.get("settings", {})
    if not isinstance(section, dict) or set(section) - _SETTING_KEYS:
        bad = sorted(set(section) - _SETTING_KEYS) if isinstance(section, dict) else ["settings"]
        raise ConfigError(f"{path}: unknown setting {bad[0]!r}")
    if "timeout" in section:
        settings.timeout = _number(section["timeout"], "timeout", 0.1)
    if "warn_days" in section:
        settings.warn_days = _number(section["warn_days"], "warn_days")
    if "critical_days" in section:
        settings.critical_days = _number(section["critical_days"], "critical_days")
    if "workers" in section:
        settings.workers = int(_number(section["workers"], "workers", 1))
    if "min_grade" in section:
        if section["min_grade"] not in GRADES:
            raise ConfigError(f"min_grade must be one of {', '.join(GRADES)}")
        settings.min_grade = section["min_grade"]
    hosts = data.get("hosts", [])
    if not isinstance(hosts, list):
        raise ConfigError(f"{path}: 'hosts' must be a list of [[hosts]] tables")
    for entry in hosts:
        if not isinstance(entry, dict) or "host" not in entry:
            raise ConfigError(f"{path}: every [[hosts]] entry needs a 'host'")
        extra = set(entry) - _HOST_KEYS
        if extra:
            raise ConfigError(f"{path}: unknown key {sorted(extra)[0]!r} in a [[hosts]] entry")
        text = str(entry["host"])
        if "port" in entry:
            if not isinstance(entry["port"], int) or isinstance(entry["port"], bool):
                raise ConfigError(f"{path}: port must be an integer")
            text = f"{text}:{entry['port']}" if ":" not in text else text
        ca_file = entry.get("ca_file")
        if ca_file is not None:
            ca_file = str((path.parent / str(ca_file)).resolve())
        settings.targets.append(
            parse_target(
                text,
                starttls=entry.get("starttls"),
                server_name=entry.get("server_name"),
                ca_file=ca_file,
            )
        )
    return settings
