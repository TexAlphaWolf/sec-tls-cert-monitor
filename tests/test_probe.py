"""Real handshakes against local TLS servers that are configured to be wrong in one way each."""

import datetime as dt
import socket
import ssl
import threading

import pytest

import pki
from conftest import CAPS, LEGACY, STRONG, V, needs, target_for
from tlswatch import probe
from tlswatch.model import Target
from tlswatch.scan import scan_one


def scan(target, **kw):
    kw.setdefault("timeout", 4)
    return scan_one(target, **kw)


def ids(report):
    return {f.id: f.severity for f in report.findings}


def test_a_well_configured_server_gets_an_a(start, ca, ca_file, leaf):
    server = start(leaf)
    report = scan(target_for(server, ca_file))
    assert report.error is None
    assert report.verification.ok
    assert report.certificate.common_name == "localhost"
    assert report.protocols["TLSv1.2"].status == "supported"
    assert report.protocols["TLSv1.3"].status == "supported"
    assert report.protocols["TLSv1.1"].status == "rejected"
    assert report.ciphers["rsa-key-exchange"].status == "rejected"
    assert report.grade == "A", report.findings


def test_without_the_private_ca_the_chain_is_not_trusted(start, leaf):
    report = scan(target_for(start(leaf)))
    assert report.grade == "F"
    assert ids(report)["untrusted-issuer"] == "critical"
    assert report.certificate is not None  # still read, so the report can say what was sent


def test_a_self_signed_certificate(start):
    server = start(pki.issue("localhost", sans=["localhost"], ca=None))
    report = scan(target_for(server))
    assert ids(report)["self-signed"] == "critical"


def test_a_certificate_for_another_name(start, ca, ca_file):
    server = start(pki.issue("other.example", issuer=ca, sans=["other.example"]))
    report = scan(target_for(server, ca_file))
    finding = next(f for f in report.findings if f.id == "hostname-mismatch")
    assert "other.example" in finding.detail
    assert report.grade == "F"


def test_checking_a_name_the_certificate_does_have(start, ca, ca_file):
    server = start(pki.issue("a.example", issuer=ca, sans=["a.example", "b.example"]))
    assert "hostname-mismatch" not in ids(scan(target_for(server, ca_file, name="b.example")))
    assert "hostname-mismatch" in ids(scan(target_for(server, ca_file, name="c.example")))


def test_an_expired_certificate(start, ca, ca_file):
    server = start(pki.issue("localhost", issuer=ca, sans=["localhost"], days_from=-30, days_to=-2))
    report = scan(target_for(server, ca_file))
    assert ids(report)["cert-expired"] == "critical"
    assert (
        "expired 1 days ago" in next(f for f in report.findings if f.id == "cert-expired").detail
        or "2 days" in next(f for f in report.findings if f.id == "cert-expired").detail
    )
    assert [f.id for f in report.findings].count("cert-expired") == 1


def test_a_certificate_that_is_not_valid_yet(start, ca, ca_file):
    server = start(pki.issue("localhost", issuer=ca, sans=["localhost"], days_from=2, days_to=60))
    assert ids(scan(target_for(server, ca_file)))["cert-not-yet-valid"] == "critical"


def test_a_certificate_close_to_expiry(start, ca, ca_file):
    server = start(pki.issue("localhost", issuer=ca, sans=["localhost"], days_to=10))
    report = scan(target_for(server, ca_file))
    assert ids(report)["cert-expires-soon"] == "medium"
    assert report.grade == "C"


def test_the_chain_through_an_intermediate_is_trusted(start, ca, ca_file):
    inter = pki.issue("Test Intermediate", issuer=ca, ca=True, days_to=900)
    leaf = pki.issue("localhost", issuer=inter, sans=["localhost"])
    report = scan(target_for(start(leaf, inter), ca_file))
    assert report.verification.ok and report.grade == "A", report.findings
    if report.chain_complete:
        assert [c.common_name for c in report.chain] == ["Test Intermediate"]


def test_a_server_that_forgets_the_intermediate_is_not_trusted(start, ca, ca_file):
    inter = pki.issue("Test Intermediate", issuer=ca, ca=True, days_to=900)
    leaf = pki.issue("localhost", issuer=inter, sans=["localhost"])
    report = scan(target_for(start(leaf), ca_file))  # the intermediate is not sent
    assert ids(report)["untrusted-issuer"] == "critical"


def test_an_expired_intermediate_is_found(start, ca, ca_file):
    inter = pki.issue("Old Intermediate", issuer=ca, ca=True, days_from=-400, days_to=-5)
    leaf = pki.issue("localhost", issuer=inter, sans=["localhost"], days_from=-300, days_to=90)
    report = scan(target_for(start(leaf, inter), ca_file))
    assert ids(report)["chain-expired"] == "critical"
    assert "cert-expired" not in ids(report)


@needs("TLSv1.0", "TLSv1.1")
def test_old_protocol_versions_are_detected(start, leaf, ca_file):
    server = start(leaf, minimum=V.TLSv1, ciphers="ALL" + LEGACY)
    report = scan(target_for(server, ca_file), ciphers=False)
    assert report.protocols["TLSv1.0"].status == "supported"
    assert report.protocols["TLSv1.1"].status == "supported"
    assert ids(report)["protocol-deprecated"] == "medium"
    assert report.grade == "C"


def test_a_weak_key_is_still_inspected_and_graded(start, ca, ca_file):
    short = pki.issue("localhost", issuer=ca, sans=["localhost"], key_kind="rsa1024")
    report = scan(
        target_for(start(short, ciphers=STRONG + LEGACY), ca_file), protocols=False, ciphers=False
    )
    assert report.error is None
    assert ids(report)["key-short"] == "high"
    assert report.grade == "F"  # a modern client refuses the certificate, and the report says so
    assert "verification-failed" in ids(report)


@needs("TLSv1.0")
def test_a_server_stuck_on_tls10_is_reported_not_unreachable(start, leaf, ca_file):
    server = start(leaf, minimum=V.TLSv1, maximum=V.TLSv1, ciphers="ALL" + LEGACY)
    report = scan(target_for(server, ca_file))
    assert report.error is None and report.version == "TLSv1"
    assert report.protocols["TLSv1.0"].status == "supported"
    assert ids(report)["protocol-no-modern"] == "critical" and report.grade == "F"


def test_a_server_that_only_speaks_tls12(start, leaf, ca_file):
    report = scan(target_for(start(leaf, maximum=V.TLSv1_2), ca_file))
    assert report.protocols["TLSv1.3"].status == "rejected"
    assert report.protocols["TLSv1.2"].status == "supported"
    assert report.version == "TLSv1.2"
    assert ids(report).get("protocol-no-tls13") == "info" and report.grade == "A"


def test_a_server_that_only_speaks_tls13_skips_the_cipher_probes(start, leaf, ca_file):
    report = scan(target_for(start(leaf, minimum=V.TLSv1_3), ca_file))
    assert report.protocols["TLSv1.2"].status == "rejected"
    assert {o.status for o in report.ciphers.values()} == {"skipped"}
    assert report.grade == "A"


@needs("anonymous")
def test_anonymous_cipher_suites_are_detected(start, leaf, ca_file):
    server = start(leaf, ciphers=f"{STRONG}:aNULL{LEGACY}")
    report = scan(target_for(server, ca_file))
    assert report.ciphers["anonymous"].status == "supported"
    assert ids(report)["cipher-anonymous"] == "critical" and report.grade == "F"


@needs("null-encryption")
def test_null_encryption_is_detected(start, leaf, ca_file):
    server = start(leaf, maximum=V.TLSv1_2, ciphers=f"{STRONG}:eNULL{LEGACY}")
    report = scan(target_for(server, ca_file))
    assert report.ciphers["null-encryption"].status == "supported"
    assert report.grade == "F"


@needs("rsa-key-exchange")
def test_rsa_key_exchange_without_forward_secrecy_is_a_b(start, leaf, ca_file):
    server = start(leaf, ciphers=f"{STRONG}:kRSA")
    report = scan(target_for(server, ca_file))
    assert report.ciphers["rsa-key-exchange"].status == "supported"
    assert ids(report)["cipher-rsa-key-exchange"] == "low" and report.grade == "B"


@pytest.mark.skipif(CAPS["rc4"] or CAPS["3des"], reason="only meaningful where OpenSSL lacks them")
def test_ciphers_this_openssl_lacks_are_reported_as_untested_not_as_absent(start, leaf, ca_file):
    report = scan(target_for(start(leaf), ca_file))
    for name in ("rc4", "3des"):
        if not CAPS[name]:
            assert report.ciphers[name].status == "untestable"
    assert "probe-gaps" in ids(report)


def test_probes_can_be_switched_off(start, leaf, ca_file):
    server = start(leaf)
    report = scan(target_for(server, ca_file), protocols=False, ciphers=False)
    assert report.protocols == {} and report.ciphers == {}
    assert report.grade == "A"


def test_a_closed_port_is_unreachable():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    report = scan(Target("127.0.0.1", port))
    assert report.error == "connection refused"
    assert report.grade is None and ids(report) == {"unreachable": "critical"}


def test_a_name_that_does_not_resolve():
    report = scan(Target("no-such-host.invalid", 443))
    assert "does not resolve" in report.error


def test_a_server_that_never_answers_times_out():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        report = scan(Target("127.0.0.1", listener.getsockname()[1]), timeout=0.5)
    finally:
        listener.close()
    assert report.error == "timed out"


def test_a_server_that_does_not_speak_tls():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def answer():
        connection, _ = listener.accept()
        connection.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nthis is plain text\r\n")
        connection.close()

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    try:
        report = scan(Target("127.0.0.1", listener.getsockname()[1]))
    finally:
        listener.close()
        thread.join(timeout=3)
    # Linux reports a TLS error; Windows reports that the server aborted the connection.
    assert report.error.startswith(("TLS error", "connection closed by the server"))
    assert report.grade is None


def test_a_server_name_that_differs_from_the_host_is_sent_as_sni(start, ca, ca_file):
    server = start(pki.issue("virtual.example", issuer=ca, sans=["virtual.example"]))
    report = scan(
        Target("127.0.0.1", server.port, server_name="virtual.example", ca_file=str(ca_file))
    )
    assert report.verification.ok
    assert report.target.name == "virtual.example"


def test_the_scan_records_when_and_how_long(start, leaf, ca_file):
    now = dt.datetime(2030, 1, 1, tzinfo=dt.UTC)
    report = scan(target_for(start(leaf), ca_file), now=now)
    assert report.scanned_at == now and report.duration > 0


# --- failure classification, which needs no server -------------------------------------


def _ssl_error(reason):
    error = ssl.SSLError(1, f"[SSL] {reason}")
    error.reason = reason
    return error


@pytest.mark.parametrize("reason", ["NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"])
def test_a_refusal_by_our_own_openssl_is_untestable_not_rejected(reason):
    assert probe.classify_failure(_ssl_error(reason)).status == "untestable"


@pytest.mark.parametrize(
    "reason",
    [
        "TLSV1_ALERT_PROTOCOL_VERSION",
        "SSLV3_ALERT_HANDSHAKE_FAILURE",
        "WRONG_VERSION_NUMBER",
        "UNSUPPORTED_PROTOCOL",
    ],
)
def test_a_refusal_by_the_server_is_rejected(reason):
    assert probe.classify_failure(_ssl_error(reason)).status == "rejected"


def test_a_dropped_connection_counts_as_rejected_and_a_timeout_as_an_error():
    assert probe.classify_failure(ConnectionResetError()).status == "rejected"
    assert probe.classify_failure(TimeoutError()).status == "error"
    assert probe.classify_failure(OSError("odd")).status == "error"


def test_describe_error_wording():
    assert probe.describe_error(ConnectionRefusedError()) == "connection refused"
    assert probe.describe_error(TimeoutError()) == "timed out"
    assert probe.describe_error(socket.gaierror(-2, "Name or service not known")).startswith(
        "name does not resolve"
    )
    assert probe.describe_error(ConnectionAbortedError()).startswith(
        "connection closed by the server"
    )
    assert probe.describe_error(ValueError("x")) == "ValueError: x"


def test_local_capabilities_cover_every_probe():
    capabilities = probe.local_capabilities()
    assert set(capabilities) == set(probe.PROTOCOLS) | {n for n, _ in probe.CIPHER_CLASSES}
    assert capabilities["TLSv1.2"] and capabilities["TLSv1.3"]
