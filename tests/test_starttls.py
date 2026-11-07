import socket
import threading

import pytest

from conftest import target_for
from tlswatch import starttls
from tlswatch.model import Target
from tlswatch.scan import scan_one


@pytest.mark.parametrize("protocol", ["smtp", "imap", "pop3"])
def test_mail_servers_are_upgraded_and_checked(start, leaf, ca_file, protocol):
    server = start(leaf, starttls=protocol)
    report = scan_one(target_for(server, ca_file, starttls=protocol), timeout=4)
    assert report.error is None, report.error
    assert report.verification.ok
    assert report.protocols["TLSv1.2"].status == "supported"
    assert report.grade == "A", report.findings


def _plain_server(script):
    """A plain-text server that runs `script(connection)` for one client."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def run():
        connection, _ = listener.accept()
        connection.settimeout(3)
        try:
            script(connection)
        except OSError:
            pass
        finally:
            connection.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return listener, thread


def _negotiate(protocol, script):
    listener, thread = _plain_server(script)
    try:
        with socket.create_connection(
            ("127.0.0.1", listener.getsockname()[1]), timeout=3
        ) as client:
            client.settimeout(3)
            starttls.negotiate(client, protocol)
    finally:
        listener.close()
        thread.join(timeout=3)


def _read_line(connection):
    data = b""
    while not data.endswith(b"\n"):
        data += connection.recv(1)
    return data


def test_smtp_server_without_starttls_is_reported():
    def script(c):
        c.sendall(b"220 hi\r\n")
        _read_line(c)
        c.sendall(b"250-hi\r\n250 8BITMIME\r\n")

    with pytest.raises(starttls.StarttlsError, match="does not offer STARTTLS"):
        _negotiate("smtp", script)


def test_smtp_multiline_replies_are_read_to_the_end():
    def script(c):
        c.sendall(b"220-first\r\n220 second\r\n")
        _read_line(c)
        c.sendall(b"250-hi\r\n250-SIZE 100\r\n250 STARTTLS\r\n")
        _read_line(c)
        c.sendall(b"220 ready\r\n")

    _negotiate("smtp", script)


@pytest.mark.parametrize(
    ("protocol", "greeting", "message"),
    [
        ("smtp", b"554 no service\r\n", "greeting was 554"),
        ("smtp", b"garbage\r\n", "unexpected SMTP reply"),
        ("imap", b"* BYE go away\r\n", "IMAP greeting"),
        ("pop3", b"-ERR busy\r\n", "POP3 greeting"),
    ],
)
def test_bad_greetings(protocol, greeting, message):
    with pytest.raises(starttls.StarttlsError, match=message):
        _negotiate(protocol, lambda c: c.sendall(greeting))


def test_imap_and_pop3_refusals():
    def imap(c):
        c.sendall(b"* OK hi\r\n")
        _read_line(c)
        c.sendall(b"* CAPABILITY X\r\na001 NO not now\r\n")

    def pop3(c):
        c.sendall(b"+OK hi\r\n")
        _read_line(c)
        c.sendall(b"-ERR no\r\n")

    with pytest.raises(starttls.StarttlsError, match="refused"):
        _negotiate("imap", imap)
    with pytest.raises(starttls.StarttlsError, match="refused"):
        _negotiate("pop3", pop3)


def test_a_server_that_hangs_up():
    with pytest.raises(starttls.StarttlsError, match="closed"):
        _negotiate("smtp", lambda c: None)


def test_an_endless_line_is_cut_off():
    with pytest.raises(starttls.StarttlsError, match="too long"):
        _negotiate("pop3", lambda c: c.sendall(b"+" * 6000))


def test_an_endless_reply_is_cut_off():
    with pytest.raises(starttls.StarttlsError, match="too many lines"):
        _negotiate("smtp", lambda c: c.sendall(b"220-x\r\n" * 100))


def test_unknown_protocol():
    with pytest.raises(starttls.StarttlsError, match="unknown"):
        starttls.negotiate(None, "gopher")  # type: ignore[arg-type]


def test_a_failed_negotiation_becomes_an_unreachable_host():
    listener, thread = _plain_server(lambda c: c.sendall(b"554 no\r\n"))
    try:
        report = scan_one(
            Target("127.0.0.1", listener.getsockname()[1], starttls="smtp"), timeout=3
        )
    finally:
        listener.close()
        thread.join(timeout=3)
    assert report.grade is None
    assert "SMTP greeting was 554" in report.error
