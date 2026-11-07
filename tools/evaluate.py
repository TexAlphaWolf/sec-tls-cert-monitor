"""Measure tlswatch: parser accuracy, robustness to corrupt input, diagnoses, speed.

    python tools/evaluate.py [--certs 300] [--fuzz 20000]

Everything is local: certificates are generated here and served from 127.0.0.1, so the numbers
say how well tlswatch reads certificates and diagnoses known faults. They do NOT say how it
behaves on the public internet (see docs/evaluation.md and the Live workflow for that).
Needs the `cryptography` package (pip install -e ".[dev]").
"""

from __future__ import annotations

import argparse
import datetime as dt
import random
import ssl
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from cryptography.hazmat.primitives import hashes

import pki
import servers
from tlswatch import probe, x509
from tlswatch.der import DerError
from tlswatch.model import Target
from tlswatch.scan import scan_all, scan_one

V = ssl.TLSVersion
STRONG = "ECDHE+AESGCM:ECDHE+CHACHA20"
LEGACY = ":@SECLEVEL=0"


# --- 1. parser against the reference ---------------------------------------------------


def parser_accuracy(count: int, seed: int) -> None:
    rng = random.Random(seed)
    kinds = ["rsa2048", "rsa3072", "ec256", "ec384", "ec521", "ed25519"]
    pool = {kind: pki.make_key(kind) for kind in kinds}  # key generation is the slow part
    original = pki.make_key
    pki.make_key = lambda kind="rsa2048": pool[kind]  # type: ignore[assignment]
    ca = pki.issue("Eval CA", ca=True, days_to=3650)
    fields = certs = 0
    mismatches: list[str] = []
    try:
        for index in range(count):
            kind = rng.choice(kinds)
            names = [f"h{rng.randrange(10**6)}.example.org" for _ in range(rng.randint(0, 5))]
            if rng.random() < 0.3:
                names.append(f"*.w{index}.example.org")
            if rng.random() < 0.3:
                names.append(f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}")
            if rng.random() < 0.15:
                names.append("2001:db8::" + format(rng.randrange(1, 65535), "x"))
            start = dt.datetime(
                rng.randint(1990, 2040),
                rng.randint(1, 12),
                rng.randint(1, 28),
                rng.randint(0, 23),
                rng.randint(0, 59),
                rng.randint(0, 59),
                tzinfo=dt.UTC,
            )
            end = start + dt.timedelta(days=rng.randint(1, 365 * 40))
            cn = rng.choice([f"host{index}.example.org", "Ünïcode Ñame", "a" * 60, None])
            digest = rng.choice([hashes.SHA256(), hashes.SHA384(), hashes.SHA512()])
            serial = rng.getrandbits(rng.choice([8, 32, 64, 128, 158])) or 1
            is_ca = rng.choice([None, False, True])
            issued = pki.issue(
                cn,
                issuer=ca if rng.random() < 0.7 else None,
                sans=names or None,
                not_before=start,
                not_after=end,
                key_kind=kind,
                digest=digest,
                ca=is_ca,
                serial=serial,
                org=rng.choice([None, "Org Inc"]),
            )
            ours = x509.parse(issued.der)
            theirs = issued.cert
            dns = [n for n in names if not n[0].isdigit() and ":" not in n]
            ips = [n for n in names if n[0].isdigit() or ":" in n]
            checks = {
                "serial": ours.serial == theirs.serial_number,
                "not_before": ours.not_before == theirs.not_valid_before_utc,
                "not_after": ours.not_after == theirs.not_valid_after_utc,
                "common_name": ours.common_name == cn,
                "san_dns": list(ours.san_dns) == dns,
                "san_ip": sorted(ours.san_ip)
                == sorted(__import__("ipaddress").ip_address(i).compressed for i in ips),
                "is_ca": ours.is_ca == is_ca,
                "sha256": ours.sha256 == theirs.fingerprint(hashes.SHA256()).hex(),
                "key": (ours.key_type, ours.key_bits)
                == {
                    "rsa2048": ("RSA", 2048),
                    "rsa3072": ("RSA", 3072),
                    "ec256": ("EC", 256),
                    "ec384": ("EC", 384),
                    "ec521": ("EC", 521),
                    "ed25519": ("Ed25519", 256),
                }[kind],
            }
            certs += 1
            for name, ok in checks.items():
                fields += 1
                if not ok:
                    mismatches.append(f"cert {index} {kind}: {name}")
    finally:
        pki.make_key = original
    print("1. Parser against the `cryptography` package")
    print(f"   certificates compared: {certs}, fields compared: {fields}")
    print(f"   fields that differ: {len(mismatches)}")
    for line in mismatches[:10]:
        print(f"     {line}")
    print()


# --- 2. corrupt input ---------------------------------------------------------------------


def fuzz(count: int, seed: int) -> None:
    rng = random.Random(seed)
    ca = pki.issue("Eval CA", ca=True)
    seeds = [
        pki.issue(
            "fuzz.example.org", issuer=ca, sans=["fuzz.example.org", "10.1.2.3"], key_kind=k
        ).der
        for k in ("rsa2048", "ec256", "ed25519")
    ]
    accepted = refused = unexpected = 0
    slowest = 0.0
    for _ in range(count):
        data = bytearray(rng.choice(seeds))
        mode = rng.randrange(4)
        if mode == 0:
            for _ in range(rng.randint(1, 6)):
                data[rng.randrange(len(data))] = rng.randrange(256)
        elif mode == 1:
            del data[rng.randrange(len(data)) :]
        elif mode == 2:
            position = rng.randrange(len(data))
            data[position:position] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        else:
            start = rng.randrange(len(data))
            del data[start : start + rng.randint(1, 20)]
        began = time.perf_counter()
        try:
            x509.parse(bytes(data))
            accepted += 1
        except DerError:
            refused += 1
        except Exception as exc:  # anything else is a bug
            unexpected += 1
            print(f"   UNEXPECTED {type(exc).__name__}: {exc}")
        slowest = max(slowest, time.perf_counter() - began)
    print("2. Corrupt certificates (flipped, truncated, inserted and deleted bytes)")
    print(f"   inputs: {count}, parsed anyway: {accepted}, refused cleanly: {refused}")
    print(f"   unexpected exceptions: {unexpected}")
    print(f"   slowest single parse: {slowest * 1000:.2f} ms")
    print()


# --- 3. diagnoses ---------------------------------------------------------------------------


class Scenario:
    def __init__(
        self, name: str, grade: str | None, findings: set[str], build, error: str | None = None
    ) -> None:  # type: ignore[no-untyped-def]
        self.name, self.grade, self.findings, self.build, self.error = (
            name,
            grade,
            findings,
            build,
            error,
        )


def scenarios(ca: pki.Issued) -> list[Scenario]:
    def served(
        leaf: pki.Issued,
        *extra: pki.Issued,
        trusted: bool = True,
        name: str = "localhost",
        **options,
    ):  # type: ignore[no-untyped-def]
        def build(directory: Path):  # type: ignore[no-untyped-def]
            chain, key = pki.write_chain(directory, leaf, *extra, name=f"s{random.getrandbits(32)}")
            options.setdefault("ciphers", STRONG)
            server = servers.TlsServer(servers.server_context(chain, key, **options))
            ca_path = str(pki.write_ca(directory, ca)) if trusted else None
            return server, Target("127.0.0.1", 0, server_name=name, ca_file=ca_path)

        return build

    def good(**kw):  # type: ignore[no-untyped-def]
        return pki.issue("localhost", issuer=ca, sans=["localhost"], **kw)

    inter = pki.issue("Eval Intermediate", issuer=ca, ca=True, days_to=900)
    old_inter = pki.issue("Expired Intermediate", issuer=ca, ca=True, days_from=-400, days_to=-5)
    return [
        Scenario("modern server (TLS 1.2 and 1.3, ECDHE only)", "A", set(), served(good())),
        Scenario("TLS 1.2 only", "A", set(), served(good(), maximum=V.TLSv1_2)),
        Scenario("TLS 1.3 only", "A", set(), served(good(), minimum=V.TLSv1_3)),
        Scenario(
            "through an intermediate that is sent",
            "A",
            set(),
            served(pki.issue("localhost", issuer=inter, sans=["localhost"]), inter),
        ),
        Scenario(
            "RSA key exchange allowed (no forward secrecy)",
            "B",
            {"cipher-rsa-key-exchange"},
            served(good(), ciphers=f"{STRONG}:kRSA"),
        ),
        Scenario("expires in 20 days", "C", {"cert-expires-soon"}, served(good(days_to=20))),
        Scenario(
            "TLS 1.0 and 1.1 enabled",
            "C",
            {"protocol-deprecated"},
            served(good(), minimum=V.TLSv1, ciphers="ECDHE+AES" + LEGACY),
        ),
        Scenario("expires in 3 days", "D", {"cert-expires-soon"}, served(good(days_to=3))),
        Scenario(
            "expired 5 days ago", "F", {"cert-expired"}, served(good(days_from=-60, days_to=-5))
        ),
        Scenario(
            "not valid yet", "F", {"cert-not-yet-valid"}, served(good(days_from=3, days_to=90))
        ),
        Scenario(
            "certificate for another name",
            "F",
            {"hostname-mismatch"},
            served(pki.issue("other.example", issuer=ca, sans=["other.example"])),
        ),
        Scenario(
            "self-signed",
            "F",
            {"self-signed"},
            served(pki.issue("localhost", sans=["localhost"], ca=None), trusted=False),
        ),
        Scenario(
            "signed by an unknown CA", "F", {"untrusted-issuer"}, served(good(), trusted=False)
        ),
        Scenario(
            "intermediate not sent",
            "F",
            {"untrusted-issuer"},
            served(pki.issue("localhost", issuer=inter, sans=["localhost"])),
        ),
        Scenario(
            "expired intermediate",
            "F",
            {"chain-expired"},
            served(
                pki.issue("localhost", issuer=old_inter, sans=["localhost"], days_from=-300),
                old_inter,
            ),
        ),
        Scenario(
            "1024-bit RSA key",
            "F",
            {"key-short", "verification-failed"},
            served(good(key_kind="rsa1024"), ciphers=STRONG + LEGACY),
        ),
        Scenario(
            "anonymous cipher suites accepted",
            "F",
            {"cipher-anonymous"},
            served(good(), maximum=V.TLSv1_2, ciphers=f"{STRONG}:AECDH-AES128-SHA{LEGACY}"),
        ),
        Scenario(
            "NULL encryption accepted",
            "F",
            {"cipher-null-encryption"},
            served(good(), maximum=V.TLSv1_2, ciphers=f"{STRONG}:ECDHE-RSA-NULL-SHA{LEGACY}"),
        ),
    ]


def diagnoses(directory: Path) -> int:
    ca = pki.issue("Eval CA", ca=True, days_to=3650)
    rows = []
    correct = 0
    for scenario in scenarios(ca):
        server, target = scenario.build(directory)
        with server:
            target = Target(target.host, server.port, target.server_name, None, target.ca_file)
            report = scan_one(target, timeout=5)
        important = {f.id for f in report.findings if f.severity != "info"}
        ok = report.grade == scenario.grade and important == scenario.findings
        correct += ok
        rows.append(
            (
                scenario.name,
                scenario.grade or "-",
                report.grade or "-",
                ", ".join(sorted(important)) or "none",
                ok,
            )
        )
    # Faults that are not TLS configurations.
    import socket
    import threading

    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    dead_port = dead.getsockname()[1]
    dead.close()
    silent = servers.TlsServer(None, silent=True)
    plain = socket.socket()
    plain.bind(("127.0.0.1", 0))
    plain.listen(1)
    threading.Thread(
        target=lambda: (lambda c: (c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"), c.close()))(
            plain.accept()[0]
        ),
        daemon=True,
    ).start()
    faults = [
        ("nothing listens on the port", Target("127.0.0.1", dead_port), "connection refused", 3),
        ("name does not resolve", Target("no-such-host.invalid"), "does not resolve", 3),
        ("server accepts and never answers", None, "timed out", 1),
        (
            "server speaks plain text, not TLS",
            Target("127.0.0.1", plain.getsockname()[1]),
            "TLS error|connection closed by the server",
            3,
        ),
    ]
    with silent:
        for name, target, expected, timeout in faults:
            target = target or Target("127.0.0.1", silent.port)
            report = scan_one(target, timeout=timeout)
            ok = report.grade is None and any(
                part in (report.error or "") for part in expected.split("|")
            )
            correct += ok
            rows.append((name, "-", "-", (report.error or "no error")[:40], ok))
    plain.close()
    print("3. Diagnoses against local servers with a known fault")
    print(f"   {'scenario':<50} {'expect':>6} {'got':>4}  findings")
    for name, expected, got, found, ok in rows:
        print(f"   {name:<50} {expected:>6} {got:>4}  {found}{'' if ok else '   <-- WRONG'}")
    print(f"   scenarios correct: {correct} of {len(rows)}")
    print()
    return len(rows)


# --- 4. speed -------------------------------------------------------------------------------


def speed(directory: Path) -> None:
    ca = pki.issue("Eval CA", ca=True)
    leaf = pki.issue("localhost", issuer=ca, sans=["localhost"])
    chain, key = pki.write_chain(directory, leaf, name="speed")
    ca_path = str(pki.write_ca(directory, ca, "speedca"))
    context = servers.server_context(chain, key, ciphers=STRONG)
    with servers.TlsServer(context) as server:
        target = Target("127.0.0.1", server.port, server_name="localhost", ca_file=ca_path)
        times = []
        for _ in range(7):
            before = server.connections
            began = time.perf_counter()
            scan_one(target, timeout=5)
            times.append(time.perf_counter() - began)
            used = server.connections - before
        times.sort()
        began = time.perf_counter()
        scan_all([target] * 24, workers=8, timeout=5)
        batch = time.perf_counter() - began
    print("4. Speed (loopback: network latency is not included)")
    print(f"   connections per host (all probes): {used}")
    print(f"   one host, median of 7: {times[3] * 1000:.0f} ms")
    print(f"   24 hosts, 8 at a time: {batch:.2f} s ({batch / 24 * 1000:.0f} ms per host)")
    print()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certs", type=int, default=300)
    parser.add_argument("--fuzz", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    caps = probe.local_capabilities()
    missing = [name for name, ok in caps.items() if not ok]
    print(f"OpenSSL: {ssl.OPENSSL_VERSION}")
    print(f"probes this OpenSSL cannot run: {', '.join(missing) or 'none'}\n")
    parser_accuracy(args.certs, args.seed)
    fuzz(args.fuzz, args.seed)
    with tempfile.TemporaryDirectory() as tmp:
        diagnoses(Path(tmp))
        speed(Path(tmp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
