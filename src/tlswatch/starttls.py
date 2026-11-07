"""The few plain-text lines that upgrade a mail connection to TLS (SMTP, IMAP, POP3)."""

from __future__ import annotations

import socket

MAX_LINE = 4096
MAX_LINES = 64


class StarttlsError(Exception):
    """The server did not agree to switch to TLS."""


def _line(sock: socket.socket) -> bytes:
    # One byte at a time: anything read past the end of the reply would be lost to the TLS
    # handshake that follows.
    data = bytearray()
    while not data.endswith(b"\n"):
        if len(data) > MAX_LINE:
            raise StarttlsError("reply line is too long")
        chunk = sock.recv(1)
        if not chunk:
            raise StarttlsError("connection closed during STARTTLS negotiation")
        data += chunk
    return bytes(data)


def _smtp_reply(sock: socket.socket) -> tuple[int, list[str]]:
    lines: list[str] = []
    for _ in range(MAX_LINES):
        text = _line(sock).decode("ascii", errors="replace").rstrip("\r\n")
        if len(text) < 3 or not text[:3].isdigit():
            raise StarttlsError(f"unexpected SMTP reply: {text[:60]!r}")
        lines.append(text[4:])
        if text[3:4] != "-":
            return int(text[:3]), lines
    raise StarttlsError("SMTP reply has too many lines")


def negotiate(sock: socket.socket, protocol: str) -> None:
    """Run the plain-text part of the conversation; the caller then starts the TLS handshake."""
    if protocol == "smtp":
        code, _ = _smtp_reply(sock)
        if code != 220:
            raise StarttlsError(f"SMTP greeting was {code}, expected 220")
        sock.sendall(b"EHLO tlswatch.invalid\r\n")
        code, lines = _smtp_reply(sock)
        if code != 250:
            raise StarttlsError(f"EHLO was answered {code}")
        if not any(entry.upper().startswith("STARTTLS") for entry in lines):
            raise StarttlsError("the server does not offer STARTTLS")
        sock.sendall(b"STARTTLS\r\n")
        code, _ = _smtp_reply(sock)
        if code != 220:
            raise StarttlsError(f"STARTTLS was answered {code}")
    elif protocol == "imap":
        greeting = _line(sock)
        if not greeting.startswith((b"* OK", b"* PREAUTH")):
            raise StarttlsError(f"IMAP greeting was {greeting[:40]!r}")
        sock.sendall(b"a001 STARTTLS\r\n")
        for _ in range(MAX_LINES):
            reply = _line(sock)
            if reply.startswith(b"a001 "):
                if not reply.startswith(b"a001 OK"):
                    raise StarttlsError(f"STARTTLS was refused: {reply[:60]!r}")
                return
        raise StarttlsError("IMAP reply has too many lines")
    elif protocol == "pop3":
        greeting = _line(sock)
        if not greeting.startswith(b"+OK"):
            raise StarttlsError(f"POP3 greeting was {greeting[:40]!r}")
        sock.sendall(b"STLS\r\n")
        reply = _line(sock)
        if not reply.startswith(b"+OK"):
            raise StarttlsError(f"STLS was refused: {reply[:60]!r}")
    else:
        raise StarttlsError(f"unknown STARTTLS protocol {protocol!r}")
