"""A strict, small DER reader: just enough ASN.1 to read an X.509 certificate.

The input comes from a remote server, so it is hostile. Every length is checked against the
bytes that are really there, indefinite lengths and over-long length fields are refused, and
nesting is bounded by the caller reading one level at a time.
"""

from __future__ import annotations

from dataclasses import dataclass


class DerError(ValueError):
    """The bytes are not valid DER (or not the structure we expected)."""


# Universal tags used by certificates.
BOOLEAN = 0x01
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
UTF8_STRING = 0x0C
PRINTABLE_STRING = 0x13
T61_STRING = 0x14
IA5_STRING = 0x16
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18
UNIVERSAL_STRING = 0x1C
BMP_STRING = 0x1E
SEQUENCE = 0x30
SET = 0x31


@dataclass(frozen=True, slots=True)
class Tlv:
    """One tag-length-value element. `raw` is the whole encoding, header included."""

    tag: int
    value: bytes
    raw: bytes


def read_one(data: bytes, offset: int = 0) -> tuple[Tlv, int]:
    """Read the element starting at `offset`; return it and the offset just after it."""
    end = len(data)
    if offset >= end:
        raise DerError("unexpected end of data")
    start = offset
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tags are not used in certificates")
    offset += 1
    if offset >= end:
        raise DerError("missing length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0:
            raise DerError("indefinite length is not allowed in DER")
        if count > 4:
            raise DerError("length field too long")
        if offset + count > end:
            raise DerError("truncated length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
        # DER wants the shortest form.
        if length < 0x80 or (count > 1 and data[offset - count] == 0):
            raise DerError("length is not minimally encoded")
    if offset + length > end:
        raise DerError("element is longer than the data")
    return Tlv(tag, data[offset : offset + length], data[start : offset + length]), offset + length


def children(value: bytes) -> list[Tlv]:
    """All the elements packed back to back in `value` (the content of a SEQUENCE or SET)."""
    items: list[Tlv] = []
    offset = 0
    while offset < len(value):
        item, offset = read_one(value, offset)
        items.append(item)
    return items


def parse(data: bytes) -> Tlv:
    """Parse a single top-level element and refuse anything after it."""
    item, offset = read_one(data)
    if offset != len(data):
        raise DerError("trailing bytes after the element")
    return item


def expect(item: Tlv, tag: int, what: str) -> Tlv:
    if item.tag != tag:
        raise DerError(f"{what}: expected tag 0x{tag:02x}, found 0x{item.tag:02x}")
    return item


def decode_oid(value: bytes) -> str:
    """Dotted form of an OBJECT IDENTIFIER's content bytes."""
    if not value:
        raise DerError("empty object identifier")
    arcs: list[int] = []
    number = 0
    fresh = True
    for byte in value:
        if fresh and byte == 0x80:
            raise DerError("object identifier arc is not minimally encoded")
        number = (number << 7) | (byte & 0x7F)
        fresh = False
        if not byte & 0x80:
            arcs.append(number)
            number = 0
            fresh = True
    if not fresh:
        raise DerError("truncated object identifier")
    first = arcs[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(n) for n in head + arcs[1:])


def decode_integer(value: bytes) -> int:
    if not value:
        raise DerError("empty integer")
    if len(value) > 1 and (
        (value[0] == 0x00 and not value[1] & 0x80) or (value[0] == 0xFF and value[1] & 0x80)
    ):
        raise DerError("integer is not minimally encoded")
    return int.from_bytes(value, "big", signed=True)


def decode_string(item: Tlv) -> str:
    """Text of the string types that appear in distinguished names."""
    try:
        if item.tag in (UTF8_STRING, PRINTABLE_STRING, IA5_STRING):
            return item.value.decode("utf-8")
        if item.tag == T61_STRING:
            return item.value.decode("latin-1")
        if item.tag == BMP_STRING:
            return item.value.decode("utf-16-be")
        if item.tag == UNIVERSAL_STRING:
            return item.value.decode("utf-32-be")
    except UnicodeDecodeError as exc:
        raise DerError("string is not valid in its declared encoding") from exc
    raise DerError(f"unsupported string type 0x{item.tag:02x}")
