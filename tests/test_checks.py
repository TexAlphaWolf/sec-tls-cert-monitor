"""Findings and grades from known facts (no network): the rubric in docs/grading.md."""

import dataclasses
import datetime as dt
import json

import pytest

import pki
from tlswatch import checks, x509
from tlswatch.model import HostReport, Outcome, Target, Verification

NOW = dt.datetime(2026, 6, 1, 12, 0, tzinfo=dt.UTC)


def cert(**changes):
    base = x509.parse(
        pki.issue(
            "example.org",
            sans=["example.org", "www.example.org"],
            not_before=NOW - dt.timedelta(days=30),
            not_after=NOW + dt.timedelta(days=200),
        ).der
    )
    return dataclasses.replace(base, **changes)


def good_protocols():
    return {
        "TLSv1.0": Outcome("rejected"),
        "TLSv1.1": Outcome("rejected"),
        "TLSv1.2": Outcome("supported", "ECDHE-RSA-AES128-GCM-SHA256"),
        "TLSv1.3": Outcome("supported", "TLS_AES_256_GCM_SHA384"),
    }


def good_ciphers():
    names = ("null-encryption", "anonymous", "rc4", "3des", "rsa-key-exchange")
    return {name: Outcome("rejected") for name in names}


def report(**changes):
    base = HostReport(
        target=Target("example.org", 443),
        scanned_at=NOW,
        version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        certificate=cert(),
        chain=[],
        chain_complete=True,
        verification=Verification(True, "valid"),
        protocols=good_protocols(),
        ciphers=good_ciphers(),
    )
    return dataclasses.replace(base, **changes)


def ids(r):
    return {f.id: f.severity for f in r.findings}


def assess(r, **kw):
    return checks.assess(r, now=NOW, **kw)


def test_a_clean_host_is_an_a_with_no_findings():
    r = assess(report())
    assert r.grade == "A" and r.findings == []


@pytest.mark.parametrize(
    ("days", "grade", "severity"),
    [
        (200, "A", None),
        (31, "A", None),
        (30, "C", "medium"),
        (8, "C", "medium"),
        (7, "D", "high"),
        (1, "D", "high"),
        (-1, "F", "critical"),
    ],
)
def test_expiry_thresholds(days, grade, severity):
    expiring = cert(not_after=NOW + dt.timedelta(days=days))
    r = assess(report(certificate=expiring))
    assert r.grade == grade
    assert ids(r).get("cert-expired" if days < 0 else "cert-expires-soon") == severity


def test_thresholds_are_configurable():
    expiring = report(certificate=cert(not_after=NOW + dt.timedelta(days=45)))
    assert assess(expiring).grade == "A"
    assert assess(expiring, warn_days=60).grade == "C"
    assert assess(expiring, warn_days=60, critical_days=50).grade == "D"


def test_a_certificate_that_is_not_valid_yet_is_an_f():
    r = assess(report(certificate=cert(not_before=NOW + dt.timedelta(days=2))))
    assert r.grade == "F" and ids(r)["cert-not-yet-valid"] == "critical"


def test_expired_certificate_is_reported_once_even_though_verification_also_failed():
    r = assess(
        report(
            certificate=cert(not_after=NOW - dt.timedelta(days=3)),
            verification=Verification(False, "expired", "certificate has expired", 10),
        )
    )
    assert [f.id for f in r.findings if "expire" in f.id] == ["cert-expired"]
    assert "3 days ago" in r.findings[0].detail


def test_an_expired_certificate_elsewhere_in_the_chain_is_found_by_verification():
    r = assess(report(verification=Verification(False, "expired", "certificate has expired", 10)))
    assert r.grade == "F" and "chain-expired" in ids(r)


def test_chain_certificates_are_checked_for_expiry():
    soon = cert(subject="CN=Intermediate", not_after=NOW + dt.timedelta(days=3))
    gone = cert(subject="CN=Old", not_after=NOW - dt.timedelta(days=3))
    assert ids(assess(report(chain=[soon])))["chain-expires-soon"] == "high"
    assert ids(assess(report(chain=[gone])))["chain-expired"] == "critical"


@pytest.mark.parametrize(
    ("changes", "finding", "grade"),
    [
        ({"signature_algorithm": "sha1WithRSAEncryption"}, "sig-sha1", "D"),
        ({"signature_algorithm": "ecdsaWithSHA1"}, "sig-sha1", "D"),
        ({"signature_algorithm": "md5WithRSAEncryption"}, "sig-broken", "F"),
        ({"signature_algorithm": "md2WithRSAEncryption"}, "sig-broken", "F"),
        ({"key_type": "RSA", "key_bits": 1024}, "key-short", "D"),
        ({"key_type": "RSA", "key_bits": 512}, "key-weak", "F"),
        ({"key_type": "EC", "key_bits": 192}, "key-short", "D"),
        ({"key_type": "DSA", "key_bits": 0}, "key-dsa", "D"),
    ],
)
def test_weak_certificates(changes, finding, grade):
    r = assess(report(certificate=cert(**changes)))
    assert finding in ids(r) and r.grade == grade


@pytest.mark.parametrize(
    ("kind", "bits"), [("RSA", 2048), ("RSA", 4096), ("EC", 256), ("EC", 384), ("Ed25519", 256)]
)
def test_good_keys_are_not_flagged(kind, bits):
    assert assess(report(certificate=cert(key_type=kind, key_bits=bits))).findings == []


def test_sha256_and_ecdsa_signatures_are_fine():
    for name in (
        "sha256WithRSAEncryption",
        "ecdsaWithSHA384",
        "Ed25519",
        "sha512WithRSAEncryption",
    ):
        assert assess(report(certificate=cert(signature_algorithm=name))).findings == []


@pytest.mark.parametrize(
    ("verdict", "finding"),
    [
        ("self_signed", "self-signed"),
        ("untrusted", "untrusted-issuer"),
        ("invalid", "verification-failed"),
        ("hostname_mismatch", "hostname-mismatch"),
    ],
)
def test_verification_failures_are_critical(verdict, finding):
    r = assess(report(verification=Verification(False, verdict, "reason from OpenSSL")))
    assert ids(r)[finding] == "critical" and r.grade == "F"


def test_hostname_mismatch_lists_the_names_the_certificate_does_have():
    r = assess(
        report(
            target=Target("other.example"), verification=Verification(False, "hostname_mismatch")
        )
    )
    finding = next(f for f in r.findings if f.id == "hostname-mismatch")
    assert finding.title == "Certificate is not valid for other.example"
    assert finding.detail == "certificate names: example.org, www.example.org"


def test_untrusted_chain_says_how_many_certificates_were_sent():
    r = assess(
        report(
            verification=Verification(False, "untrusted", "unable to get local issuer certificate")
        )
    )
    assert (
        "the server sent 1 certificate"
        in next(f for f in r.findings if f.id == "untrusted-issuer").detail
    )
    r = assess(report(chain_complete=False, verification=Verification(False, "untrusted", "x")))
    assert "the server sent" not in next(f for f in r.findings if f.id == "untrusted-issuer").detail


def test_an_untrusted_chain_on_windows_mentions_the_windows_trust_store(monkeypatch):
    verification = Verification(False, "untrusted", "unable to get local issuer certificate")
    monkeypatch.setattr(checks.sys, "platform", "win32")
    detail = next(
        f for f in assess(report(verification=verification)).findings if f.id == "untrusted-issuer"
    ).detail
    assert "Windows certificate store" in detail and "--ca-file" in detail
    monkeypatch.setattr(checks.sys, "platform", "linux")
    detail = next(
        f for f in assess(report(verification=verification)).findings if f.id == "untrusted-issuer"
    ).detail
    assert "Windows" not in detail


def test_deprecated_protocols_cap_the_grade_at_c():
    protocols = good_protocols() | {
        "TLSv1.0": Outcome("supported", "x"),
        "TLSv1.1": Outcome("supported", "x"),
    }
    r = assess(report(protocols=protocols))
    assert r.grade == "C" and ids(r)["protocol-deprecated"] == "medium"
    assert "TLSv1.0, TLSv1.1" in r.findings[0].detail


def test_a_server_with_no_modern_protocol_is_an_f():
    protocols = good_protocols() | {
        "TLSv1.2": Outcome("rejected"),
        "TLSv1.3": Outcome("rejected"),
        "TLSv1.0": Outcome("supported", "x"),
    }
    assert assess(report(protocols=protocols)).grade == "F"


def test_not_being_able_to_test_a_modern_protocol_is_not_a_failure():
    protocols = good_protocols() | {
        "TLSv1.2": Outcome("untestable", "x"),
        "TLSv1.3": Outcome("rejected"),
    }
    r = assess(report(protocols=protocols))
    assert "protocol-no-modern" not in ids(r)


def test_missing_tls13_is_information_only():
    protocols = good_protocols() | {"TLSv1.3": Outcome("rejected")}
    r = assess(report(protocols=protocols))
    assert r.grade == "A" and ids(r) == {"protocol-no-tls13": "info"}


@pytest.mark.parametrize(
    ("cipher", "severity", "grade"),
    [
        ("null-encryption", "critical", "F"),
        ("anonymous", "critical", "F"),
        ("rc4", "high", "D"),
        ("3des", "high", "D"),
        ("rsa-key-exchange", "low", "B"),
    ],
)
def test_weak_cipher_classes(cipher, severity, grade):
    ciphers = good_ciphers() | {cipher: Outcome("supported", "TLSv1.2 SOMETHING")}
    r = assess(report(ciphers=ciphers))
    assert ids(r) == {f"cipher-{cipher}": severity} and r.grade == grade


def test_what_could_not_be_tested_is_listed_so_a_clean_report_is_not_overread():
    ciphers = good_ciphers() | {
        "rc4": Outcome("untestable", "no such cipher"),
        "3des": Outcome("untestable", "x"),
    }
    r = assess(report(ciphers=ciphers))
    assert r.grade == "A"
    gap = next(f for f in r.findings if f.id == "probe-gaps")
    assert gap.severity == "info" and gap.detail == "3des, rc4"


def test_the_worst_finding_decides_the_grade():
    r = assess(
        report(
            certificate=cert(signature_algorithm="sha1WithRSAEncryption"),
            ciphers=good_ciphers() | {"rsa-key-exchange": Outcome("supported", "x")},
        )
    )
    assert r.grade == "D"
    assert [f.severity for f in r.findings] == ["high", "low"]


def test_an_unreachable_host_has_no_grade_and_always_fails():
    r = assess(
        HostReport(target=Target("down.example"), scanned_at=NOW, error="connection refused")
    )
    assert r.grade is None and ids(r) == {"unreachable": "critical"}
    assert checks.worse_than(r.grade, "F")


def test_an_unparsable_certificate_is_reported():
    r = assess(report(certificate=None))
    assert ids(r)["cert-unreadable"] == "high"


def test_identical_findings_are_reported_once():
    gone = cert(subject="CN=Old", not_after=NOW - dt.timedelta(days=3))
    r = assess(report(chain=[gone, gone]))
    assert [f.id for f in r.findings] == ["chain-expired"]


def test_grade_of_nothing_is_a():
    assert checks.grade_of([]) == "A"


@pytest.mark.parametrize(
    ("grade", "limit", "worse"),
    [("A", "B", False), ("B", "B", False), ("C", "B", True), ("F", "D", True), ("D", "D", False)],
)
def test_worse_than(grade, limit, worse):
    assert checks.worse_than(grade, limit) is worse


def test_the_report_converts_to_json_without_losing_the_findings():
    r = assess(report(certificate=cert(signature_algorithm="sha1WithRSAEncryption")))
    data = json.loads(json.dumps(r.to_dict()))
    assert data["grade"] == "D" and data["findings"][0]["id"] == "sig-sha1"
    assert data["certificate"]["san_dns"] == ["example.org", "www.example.org"]
    assert data["protocols"]["TLSv1.3"]["status"] == "supported"
