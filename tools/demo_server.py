"""Start local TLS servers that are wrong in different ways, for demos and the Docker test.

    python tools/demo_server.py --dir /tmp/demo        # runs until interrupted

Writes DIR/hosts.toml (a tlswatch configuration listing every server) and DIR/ca.pem, prints one
line per server, then keeps serving. Nothing here touches the network beyond 127.0.0.1.
"""

from __future__ import annotations

import argparse
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

import pki
import servers

V = ssl.TLSVersion
STRONG = "ECDHE+AESGCM:ECDHE+CHACHA20"
LEGACY = ":@SECLEVEL=0"


def build(directory: Path) -> list[tuple[str, servers.TlsServer]]:
    ca = pki.issue("Demo Root CA", ca=True, days_to=3650)
    ca_path = pki.write_ca(directory, ca)
    started: list[tuple[str, servers.TlsServer]] = []

    def serve(label: str, leaf: pki.Issued, **options: object) -> None:
        chain, key = pki.write_chain(directory, leaf, name=label)
        options.setdefault("ciphers", STRONG)
        server = servers.TlsServer(servers.server_context(chain, key, **options))  # type: ignore[arg-type]
        server.__enter__()
        started.append((label, server))

    def good(name: str, **kw: object) -> pki.Issued:
        return pki.issue(name, issuer=ca, sans=[name], **kw)  # type: ignore[arg-type]

    serve("www.example.test", good("www.example.test", days_to=200))
    serve("api.example.test", good("api.example.test", days_to=80), maximum=V.TLSv1_2)
    serve("shop.example.test", good("shop.example.test", days_to=12))
    serve(
        "old.example.test",
        good("old.example.test", days_to=300),
        minimum=V.TLSv1,
        ciphers="ECDHE+AES" + LEGACY,
    )
    serve("expired.example.test", good("expired.example.test", days_from=-400, days_to=-3))
    serve(
        "wrong.example.test",
        pki.issue("other.example.test", issuer=ca, sans=["other.example.test"]),
    )
    serve("dev.example.test", pki.issue("dev.example.test", sans=["dev.example.test"], ca=None))

    lines = ["[settings]", "timeout = 5", 'min_grade = "B"', ""]
    for label, server in started:
        lines += [
            "[[hosts]]",
            'host = "127.0.0.1"',
            f"port = {server.port}",
            f'server_name = "{label}"',
        ]
        if label != "dev.example.test":
            lines.append(f'ca_file = "{ca_path.name}"')
        lines.append("")
    (directory / "hosts.toml").write_text("\n".join(lines), encoding="utf-8")
    return started


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=Path, required=True)
    args = parser.parse_args()
    args.dir.mkdir(parents=True, exist_ok=True)
    started = build(args.dir)
    for label, server in started:
        print(f"{label:<24} 127.0.0.1:{server.port}", flush=True)
    print(f"config written to {args.dir / 'hosts.toml'}", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for _, server in started:
            server.__exit__(None, None, None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
