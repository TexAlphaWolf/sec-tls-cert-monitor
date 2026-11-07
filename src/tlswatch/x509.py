"""Read the fields of an X.509 certificate that a monitor needs.

This is a reader, not a validator: signatures are not checked here (OpenSSL does that during the
handshake). It extracts validity dates, names, subject alternative names, the signature
algorithm, the key type and size, and whether the certificate says it is a CA.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

from tlswatch import der
from tlswatch.der import DerError, Tlv

SIGNATURE_ALGORITHMS = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsaWithSHA1",
    "1.2.840.10045.4.3.1": "ecdsaWithSHA224",
    "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
    "1.2.840.10040.4.3": "dsaWithSHA1",
    "2.16.840.1.101.3.4.3.2": "dsaWithSHA256",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

CURVES = {
    "1.2.840.10045.3.1.1": ("secp192r1", 192),
    "1.3.132.0.33": ("secp224r1", 224),
    "1.2.840.10045.3.1.7": ("secp256r1", 256),
    "1.3.132.0.34": ("secp384r1", 384),
    "1.3.132.0.35": ("secp521r1", 521),
}

_OID_RSA = "1.2.840.113549.1.1.1"
_OID_EC = "1.2.840.10045.2.1"
_OID_DSA = "1.2.840.10040.4.1"
_OID_ED25519 = "1.3.101.112"
_OID_ED448 = "1.3.101.113"
_OID_SAN = "2.5.29.17"
_OID_BASIC_CONSTRAINTS = "2.5.29.19"

# Short names for the attributes people expect to see in a name.
_ATTRIBUTES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
}


@dataclass(frozen=True, slots=True)
class Certificate:
    der: bytes
    serial: int
    not_before: datetime
    not_after: datetime
    subject: str
    issuer: str
    common_name: str | None
    san_dns: tuple[str, ...]
    san_ip: tuple[str, ...]
    signature_algorithm: str
    key_type: str
    key_bits: int
    is_ca: bool | None  # None: no basicConstraints extension

    @property
    def self_issued(self) -> bool:
        return self.subject == self.issuer

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    def days_left(self, now: datetime) -> float:
        return (self.not_after - now) / timedelta(days=1)


def _time(item: Tlv) -> datetime:
    text = item.value.decode("ascii", errors="replace")
    try:
        if item.tag == der.UTC_TIME:
            if len(text) != 13 or text[-1] != "Z":
                raise ValueError(text)
            year = int(text[0:2])
            year += 1900 if year >= 50 else 2000
            rest = text[2:-1]
        elif item.tag == der.GENERALIZED_TIME:
            if len(text) != 15 or text[-1] != "Z":
                raise ValueError(text)
            year = int(text[0:4])
            rest = text[4:-1]
        else:
            raise DerError(f"not a time: tag 0x{item.tag:02x}")
        if not rest.isdigit():
            raise ValueError(text)
        return datetime(
            year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]), int(rest[8:10]),
            tzinfo=UTC,
        )  # fmt: skip
    except ValueError as exc:
        raise DerError(f"invalid time {text!r}") from exc


def _name(item: Tlv) -> tuple[str, str | None]:
    """A distinguished name as 'CN=a, O=b' (most specific first, as OpenSSL prints it) and its CN."""
    der.expect(item, der.SEQUENCE, "name")
    parts: list[str] = []
    common_name: str | None = None
    for rdn in der.children(item.value):
        der.expect(rdn, der.SET, "relative distinguished name")
        for attribute in der.children(rdn.value):
            der.expect(attribute, der.SEQUENCE, "name attribute")
            pair = der.children(attribute.value)
            if len(pair) != 2:
                raise DerError("name attribute must have two parts")
            oid = der.decode_oid(der.expect(pair[0], der.OID, "attribute type").value)
            text = der.decode_string(pair[1])
            label = _ATTRIBUTES.get(oid, oid)
            parts.append(f"{label}={text}")
            if oid == "2.5.4.3" and common_name is None:
                common_name = text
    return ", ".join(reversed(parts)), common_name


def _public_key(spki: Tlv) -> tuple[str, int]:
    der.expect(spki, der.SEQUENCE, "subjectPublicKeyInfo")
    parts = der.children(spki.value)
    if len(parts) != 2:
        raise DerError("subjectPublicKeyInfo must have two parts")
    algorithm = der.children(der.expect(parts[0], der.SEQUENCE, "key algorithm").value)
    if not algorithm:
        raise DerError("empty key algorithm")
    oid = der.decode_oid(der.expect(algorithm[0], der.OID, "key algorithm").value)
    bits = der.expect(parts[1], der.BIT_STRING, "public key")
    if not bits.value or bits.value[0] != 0:
        raise DerError("public key bit string has unused bits")
    key = bits.value[1:]
    if oid == _OID_RSA:
        numbers = der.children(der.expect(der.parse(key), der.SEQUENCE, "RSA key").value)
        if len(numbers) != 2:
            raise DerError("RSA key must hold a modulus and an exponent")
        modulus = der.decode_integer(der.expect(numbers[0], der.INTEGER, "modulus").value)
        return "RSA", modulus.bit_length()
    if oid == _OID_EC:
        if len(algorithm) < 2 or algorithm[1].tag != der.OID:
            return "EC", 0
        curve = der.decode_oid(algorithm[1].value)
        _, size = CURVES.get(curve, (curve, 0))
        return "EC", size
    if oid == _OID_ED25519:
        return "Ed25519", 256
    if oid == _OID_ED448:
        return "Ed448", 448
    if oid == _OID_DSA:
        return "DSA", 0
    return oid, 0


def _alternative_names(value: bytes) -> tuple[list[str], list[str]]:
    dns: list[str] = []
    addresses: list[str] = []
    names = der.children(der.expect(der.parse(value), der.SEQUENCE, "subjectAltName").value)
    for entry in names:
        if entry.tag == 0x82:  # dNSName
            dns.append(entry.value.decode("ascii", errors="replace"))
        elif entry.tag == 0x87:  # iPAddress
            if len(entry.value) == 4:
                addresses.append(str(IPv4Address(entry.value)))
            elif len(entry.value) == 16:
                addresses.append(str(IPv6Address(entry.value)))
    return dns, addresses


def parse(data: bytes) -> Certificate:
    """Parse one DER certificate. Raises DerError if it is malformed."""
    top = der.expect(der.parse(data), der.SEQUENCE, "certificate")
    outer = der.children(top.value)
    if len(outer) != 3:
        raise DerError("certificate must have three parts")
    tbs = der.children(der.expect(outer[0], der.SEQUENCE, "tbsCertificate").value)
    outer_algorithm = der.children(der.expect(outer[1], der.SEQUENCE, "signatureAlgorithm").value)
    if not outer_algorithm:
        raise DerError("empty signature algorithm")
    index = 0
    if tbs and tbs[0].tag == 0xA0:  # explicit version
        index = 1
    if len(tbs) < index + 6:
        raise DerError("tbsCertificate is too short")
    serial = der.decode_integer(der.expect(tbs[index], der.INTEGER, "serial").value)
    inner_algorithm = der.children(der.expect(tbs[index + 1], der.SEQUENCE, "algorithm").value)
    if not inner_algorithm:
        raise DerError("empty signature algorithm")
    oid = der.decode_oid(der.expect(inner_algorithm[0], der.OID, "algorithm").value)
    issuer, _ = _name(tbs[index + 2])
    validity = der.children(der.expect(tbs[index + 3], der.SEQUENCE, "validity").value)
    if len(validity) != 2:
        raise DerError("validity must have two times")
    not_before, not_after = _time(validity[0]), _time(validity[1])
    subject, common_name = _name(tbs[index + 4])
    key_type, key_bits = _public_key(tbs[index + 5])

    san_dns: list[str] = []
    san_ip: list[str] = []
    is_ca: bool | None = None
    for field in tbs[index + 6 :]:
        if field.tag != 0xA3:  # only the extensions matter
            continue
        extensions = der.children(
            der.expect(der.parse(field.value), der.SEQUENCE, "extensions").value
        )
        for extension in extensions:
            parts = der.children(der.expect(extension, der.SEQUENCE, "extension").value)
            if len(parts) < 2:
                raise DerError("extension is too short")
            ext_oid = der.decode_oid(der.expect(parts[0], der.OID, "extension id").value)
            body = der.expect(parts[-1], der.OCTET_STRING, "extension value").value
            if ext_oid == _OID_SAN:
                san_dns, san_ip = _alternative_names(body)
            elif ext_oid == _OID_BASIC_CONSTRAINTS:
                fields = der.children(
                    der.expect(der.parse(body), der.SEQUENCE, "constraints").value
                )
                is_ca = bool(
                    fields
                    and fields[0].tag == der.BOOLEAN
                    and fields[0].value not in (b"", b"\x00")
                )
    return Certificate(
        der=data,
        serial=serial,
        not_before=not_before,
        not_after=not_after,
        subject=subject,
        issuer=issuer,
        common_name=common_name,
        san_dns=tuple(san_dns),
        san_ip=tuple(san_ip),
        signature_algorithm=SIGNATURE_ALGORITHMS.get(oid, oid),
        key_type=key_type,
        key_bits=key_bits,
        is_ca=is_ca,
    )
