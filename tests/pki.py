"""Test certificates, generated at run time with the `cryptography` package (dev dependency)."""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

UTC = dt.UTC


def make_key(kind: str = "rsa2048"):  # type: ignore[no-untyped-def]
    if kind.startswith("rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(kind[3:]))
    if kind == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    if kind == "ec521":
        return ec.generate_private_key(ec.SECP521R1())
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(kind)


def _name(cn: str | None, org: str | None = None) -> x509.Name:
    attributes = []
    if org:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if cn:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attributes)


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


@dataclass
class Issued:
    cert: x509.Certificate
    key: object

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(  # type: ignore[attr-defined,no-any-return]
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def issue(
    cn: str | None,
    *,
    issuer: Issued | None = None,
    sans: list[str] | None = None,
    days_from: float = -1,
    days_to: float = 90,
    key_kind: str = "rsa2048",
    digest: hashes.HashAlgorithm | None = None,
    ca: bool | None = False,
    serial: int | None = None,
    org: str | None = None,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
) -> Issued:
    """Issue a certificate; self-signed when no issuer is given."""
    key = make_key(key_kind)
    subject = _name(cn, org)
    start = not_before or now() + dt.timedelta(days=days_from)
    end = not_after or now() + dt.timedelta(days=days_to)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
    )
    if ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True
        )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )
    signer = issuer.key if issuer else key
    if issuer:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )  # fmt: skip
    if sans:
        names: list[x509.GeneralName] = []
        for entry in sans:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(entry)))
            except ValueError:
                names.append(x509.DNSName(entry))
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if isinstance(signer, ed25519.Ed25519PrivateKey):
        digest = None
    elif digest is None:
        digest = hashes.SHA256()
    return Issued(builder.sign(signer, digest), key)  # type: ignore[arg-type]


def write_chain(
    directory: Path, leaf: Issued, *extra: Issued, name: str = "server"
) -> tuple[Path, Path]:
    """Write `leaf` followed by `extra` (intermediates) as one PEM file, and its key."""
    chain = directory / f"{name}.pem"
    chain.write_bytes(leaf.pem + b"".join(c.pem for c in extra))
    key = directory / f"{name}.key"
    key.write_bytes(leaf.key_pem)
    return chain, key


def write_ca(directory: Path, ca: Issued, name: str = "ca") -> Path:
    path = directory / f"{name}.pem"
    path.write_bytes(ca.pem)
    return path


_SHA256_RSA = bytes.fromhex("2a864886f70d01010b")


def with_signature_oid(der: bytes, last_byte: int) -> bytes:
    """Change sha256WithRSAEncryption to another PKCS#1 algorithm (0x05 SHA-1, 0x04 MD5).

    Both occurrences (inside the signed part and outside it) are rewritten, and the length does
    not change. The signature is no longer valid; only a parser that ignores signatures
    accepts the result.
    """
    assert der.count(_SHA256_RSA) == 2
    return der.replace(_SHA256_RSA, _SHA256_RSA[:-1] + bytes([last_byte]))
