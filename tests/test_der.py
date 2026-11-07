import pytest

from tlswatch import der
from tlswatch.der import DerError


def test_reads_a_short_and_a_long_form_length():
    short, end = der.read_one(b"\x04\x03abc")
    assert (short.tag, short.value, end) == (4, b"abc", 5)
    body = b"x" * 200
    long, end = der.read_one(b"\x04\x81\xc8" + body)
    assert long.value == body and end == 203


@pytest.mark.parametrize(
    "data",
    [
        b"",  # nothing
        b"\x04",  # no length
        b"\x04\x05abc",  # claims more than there is
        b"\x04\x80abc",  # indefinite length
        b"\x04\x85\x00\x00\x00\x00\x01a",  # length field too long
        b"\x04\x81\x05abcde",  # long form for a short length
        b"\x04\x82\x00\x80" + b"x" * 128,  # leading zero in the length
        b"\x1f\x01\x00",  # multi-byte tag
        b"\x04\x83\x01",  # truncated length
    ],
)
def test_malformed_encodings_are_refused(data):
    with pytest.raises(DerError):
        der.read_one(data)


def test_parse_refuses_trailing_bytes():
    with pytest.raises(DerError, match="trailing"):
        der.parse(b"\x05\x00\x00")


def test_children_reads_back_to_back_elements():
    items = der.children(b"\x02\x01\x07\x04\x02hi")
    assert [(i.tag, i.value) for i in items] == [(2, b"\x07"), (4, b"hi")]


@pytest.mark.parametrize(
    ("raw", "dotted"),
    [
        (bytes.fromhex("2a864886f70d01010b"), "1.2.840.113549.1.1.11"),
        (bytes.fromhex("550403"), "2.5.4.3"),
        (bytes.fromhex("2b6570"), "1.3.101.112"),
        (bytes.fromhex("8837"), "2.999"),  # first arc 2: the second arc can exceed 39
    ],
)
def test_object_identifiers(raw, dotted):
    assert der.decode_oid(raw) == dotted


@pytest.mark.parametrize("raw", [b"", b"\x2a\x86", b"\x2a\x80\x01"])
def test_bad_object_identifiers(raw):
    with pytest.raises(DerError):
        der.decode_oid(raw)


@pytest.mark.parametrize(
    ("raw", "value"),
    [(b"\x00", 0), (b"\x7f", 127), (b"\x00\x80", 128), (b"\xff", -1), (b"\x01\x00", 256)],
)
def test_integers(raw, value):
    assert der.decode_integer(raw) == value


@pytest.mark.parametrize("raw", [b"", b"\x00\x01", b"\xff\x80"])
def test_non_minimal_integers_are_refused(raw):
    with pytest.raises(DerError):
        der.decode_integer(raw)


def test_strings_in_each_encoding():
    assert der.decode_string(der.Tlv(der.UTF8_STRING, "é".encode(), b"")) == "é"
    assert der.decode_string(der.Tlv(der.BMP_STRING, "é".encode("utf-16-be"), b"")) == "é"
    assert der.decode_string(der.Tlv(der.T61_STRING, b"\xe9", b"")) == "é"
    with pytest.raises(DerError):
        der.decode_string(der.Tlv(der.UTF8_STRING, b"\xff\xfe", b""))
    with pytest.raises(DerError):
        der.decode_string(der.Tlv(der.INTEGER, b"1", b""))
