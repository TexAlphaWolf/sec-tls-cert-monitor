"""The parser against the `cryptography` package, which is the reference here."""

import datetime as dt
import random

import pytest
from cryptography.hazmat.primitives import hashes

import pki
from tlswatch import x509
from tlswatch.der import DerError


@pytest.mark.parametrize("kind", ["rsa2048", "rsa3072", "ec256", "ec384", "ec521", "ed25519"])
def test_agrees_with_the_reference_for_every_key_type(ca, kind):
    issued = pki.issue(
        "host.example",
        issuer=ca,
        sans=["host.example", "*.wild.example", "10.1.2.3", "2001:db8::1"],
        key_kind=kind,
    )
    ours = x509.parse(issued.der)
    expected = issued.cert
    assert ours.serial == expected.serial_number
    assert ours.not_before == expected.not_valid_before_utc
    assert ours.not_after == expected.not_valid_after_utc
    assert ours.common_name == "host.example"
    assert ours.san_dns == ("host.example", "*.wild.example")
    assert ours.san_ip == ("10.1.2.3", "2001:db8::1")
    assert ours.is_ca is False
    assert ours.sha256 == expected.fingerprint(hashes.SHA256()).hex()
    bits = {
        "rsa2048": 2048,
        "rsa3072": 3072,
        "ec256": 256,
        "ec384": 384,
        "ec521": 521,
        "ed25519": 256,
    }[kind]
    assert ours.key_bits == bits
    assert ours.key_type == {"ed25519": "Ed25519"}.get(
        kind, kind[:2].upper() if kind.startswith("ec") else "RSA"
    )


@pytest.mark.parametrize(
    ("digest", "name"),
    [
        (hashes.SHA256(), "sha256WithRSAEncryption"),
        (hashes.SHA384(), "sha384WithRSAEncryption"),
        (hashes.SHA512(), "sha512WithRSAEncryption"),
    ],
)
def test_signature_algorithm_names(ca, digest, name):
    assert x509.parse(pki.issue("a", issuer=ca, digest=digest).der).signature_algorithm == name


def test_legacy_signature_algorithms_are_named(ca):
    """`cryptography` refuses to sign with SHA-1 or MD5, so rewrite the algorithm identifier in a
    real certificate (the signature is then invalid, which a parser that does not verify
    signatures does not notice)."""
    for last_byte, name in ((0x05, "sha1WithRSAEncryption"), (0x04, "md5WithRSAEncryption")):
        forged = pki.with_signature_oid(pki.issue("a", issuer=ca).der, last_byte)
        assert x509.parse(forged).signature_algorithm == name


def test_ecdsa_and_ed25519_signature_names():
    assert x509.parse(pki.issue("a", key_kind="ec256").der).signature_algorithm == "ecdsaWithSHA256"
    assert x509.parse(pki.issue("a", key_kind="ed25519").der).signature_algorithm == "Ed25519"


def test_names_are_read_in_openssl_order_and_utf8_is_kept():
    issued = pki.issue("Ünïcode.example", org="Org & Sons")
    parsed = x509.parse(issued.der)
    assert parsed.subject == "CN=Ünïcode.example, O=Org & Sons"
    assert parsed.self_issued
    assert parsed.issuer == parsed.subject


def test_ca_flag_and_missing_basic_constraints(ca):
    assert x509.parse(ca.der).is_ca is True
    assert x509.parse(pki.issue("a", issuer=ca, ca=None).der).is_ca is None


def test_dates_after_2049_use_generalized_time():
    far = dt.datetime(2071, 3, 4, 5, 6, 7, tzinfo=dt.UTC)
    parsed = x509.parse(pki.issue("a", not_after=far).der)
    assert parsed.not_after == far
    old = dt.datetime(1999, 12, 31, 23, 59, 59, tzinfo=dt.UTC)
    assert x509.parse(pki.issue("a", not_before=old, not_after=far).der).not_before == old


def test_a_certificate_with_no_name_and_no_san():
    parsed = x509.parse(pki.issue(None).der)
    assert parsed.subject == "" and parsed.common_name is None and parsed.san_dns == ()


def test_large_serial_numbers(ca):
    serial = (1 << 158) + 12345
    assert x509.parse(pki.issue("a", issuer=ca, serial=serial).der).serial == serial


def test_days_left(ca):
    parsed = x509.parse(pki.issue("a", issuer=ca, days_to=10).der)
    assert 9.9 < parsed.days_left(pki.now()) <= 10
    assert parsed.days_left(pki.now() + dt.timedelta(days=11)) < 0


def test_garbage_is_refused():
    for data in (b"", b"\x30\x00", b"not a certificate", b"\x30\x03\x02\x01\x01"):
        with pytest.raises(DerError):
            x509.parse(data)


def test_truncated_certificates_never_crash(ca):
    der = pki.issue("a", issuer=ca, sans=["a.example"]).der
    for cut in range(0, len(der), 7):
        with pytest.raises(DerError):
            x509.parse(der[:cut])


def test_random_corruption_only_ever_raises_der_error(ca):
    """Fuzz: flip bytes in a real certificate; the parser may accept or refuse, never crash."""
    der = pki.issue("a", issuer=ca, sans=["a.example", "10.0.0.1"]).der
    rng = random.Random(1234)
    accepted = refused = 0
    for _ in range(3000):
        data = bytearray(der)
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            x509.parse(bytes(data))
            accepted += 1
        except DerError:
            refused += 1
    assert accepted + refused == 3000
    assert refused > 0
