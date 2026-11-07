from __future__ import annotations

import ssl
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import pki
import servers
from tlswatch.model import Target
from tlswatch.probe import local_capabilities

CAPS = local_capabilities()
V = ssl.TLSVersion

# Only forward-secret AEAD suites: what a well-configured server offers.
STRONG = "ECDHE+AESGCM:ECDHE+CHACHA20"
LEGACY = ":@SECLEVEL=0"


def needs(*names: str) -> pytest.MarkDecorator:
    """Skip a test when this machine's OpenSSL cannot offer what the test probes."""
    missing = [n for n in names if not CAPS.get(n, False)]
    return pytest.mark.skipif(bool(missing), reason=f"local OpenSSL cannot offer {missing}")


@pytest.fixture(scope="session")
def ca() -> pki.Issued:
    return pki.issue("Test Root CA", ca=True, days_to=3650)


@pytest.fixture
def ca_file(ca: pki.Issued, tmp_path: Path) -> Path:
    return pki.write_ca(tmp_path, ca)


@pytest.fixture
def leaf(ca: pki.Issued) -> pki.Issued:
    return pki.issue("localhost", issuer=ca, sans=["localhost", "127.0.0.1"])


Start = Callable[..., servers.TlsServer]


@pytest.fixture
def start(tmp_path: Path) -> Iterator[Start]:
    """Start a local TLS server for a certificate; stopped when the test ends."""
    running: list[servers.TlsServer] = []
    counter = iter(range(1000))

    def _start(
        leaf: pki.Issued,
        *extra: pki.Issued,
        minimum: ssl.TLSVersion = V.TLSv1_2,
        maximum: ssl.TLSVersion = V.TLSv1_3,
        ciphers: str | None = STRONG,
        starttls: str | None = None,
    ) -> servers.TlsServer:
        chain, key = pki.write_chain(tmp_path, leaf, *extra, name=f"srv{next(counter)}")
        context = servers.server_context(
            chain, key, minimum=minimum, maximum=maximum, ciphers=ciphers
        )
        server = servers.TlsServer(context, starttls=starttls)
        server.__enter__()
        running.append(server)
        return server

    yield _start
    for server in reversed(running):
        server.__exit__(None, None, None)


def target_for(
    server: servers.TlsServer,
    ca_file: Path | None = None,
    *,
    name: str = "localhost",
    starttls: str | None = None,
) -> Target:
    return Target(
        "127.0.0.1",
        server.port,
        server_name=name,
        starttls=starttls,
        ca_file=str(ca_file) if ca_file else None,
    )
