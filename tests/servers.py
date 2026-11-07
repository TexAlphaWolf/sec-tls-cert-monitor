"""A small TLS server that can be told to behave badly, for tests and for tools/evaluate.py."""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
import warnings
from pathlib import Path
from types import TracebackType

V = ssl.TLSVersion


def server_context(
    chain: Path,
    key: Path,
    *,
    minimum: ssl.TLSVersion = V.TLSv1_2,
    maximum: ssl.TLSVersion = V.TLSv1_3,
    ciphers: str | None = None,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = minimum
        context.maximum_version = maximum
    if ciphers:
        context.set_ciphers(ciphers)
    context.load_cert_chain(str(chain), str(key))
    return context


class TlsServer:
    """Accepts connections on 127.0.0.1 and completes (or refuses) the TLS handshake.

    `starttls` is "smtp" or "imap" to speak a few lines of plain text first, as a mail server
    does. `silent` accepts connections and never answers, to test timeouts.
    """

    def __init__(
        self,
        context: ssl.SSLContext | None,
        *,
        starttls: str | None = None,
        silent: bool = False,
    ) -> None:
        self.context = context
        self.starttls = starttls
        self.silent = silent
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self._listener.settimeout(0.1)  # so the accept loop notices that it should stop
        self._stopping = threading.Event()
        self.port: int = self._listener.getsockname()[1]
        self.handshakes = 0
        self.connections = 0  # every TCP connection accepted, handshake or not
        self._connections: list[socket.socket] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> TlsServer:
        self._thread.start()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self._stopping.set()
        self._thread.join(timeout=5)
        self._listener.close()
        for connection in self._connections:
            with contextlib.suppress(OSError):
                connection.close()

    def _serve(self) -> None:
        while not self._stopping.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            self._connections.append(connection)
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _line(self, connection: socket.socket) -> bytes:
        data = b""
        while not data.endswith(b"\n"):
            chunk = connection.recv(1)
            if not chunk:
                break
            data += chunk
        return data

    def _handle(self, connection: socket.socket) -> None:
        try:
            if self.silent or self.context is None:
                self._stopping.wait(30)  # hold the connection open and say nothing
                return
            connection.settimeout(5)
            if self.starttls == "smtp":
                connection.sendall(b"220 test ESMTP\r\n")
                self._line(connection)  # EHLO
                connection.sendall(b"250-test\r\n250 STARTTLS\r\n")
                self._line(connection)  # STARTTLS
                connection.sendall(b"220 go ahead\r\n")
            elif self.starttls == "imap":
                connection.sendall(b"* OK IMAP ready\r\n")
                tag = self._line(connection).split(b" ")[0]
                connection.sendall(tag + b" OK begin TLS\r\n")
            elif self.starttls == "pop3":
                connection.sendall(b"+OK POP3 ready\r\n")
                self._line(connection)  # STLS
                connection.sendall(b"+OK begin TLS\r\n")
            wrapped = self.context.wrap_socket(connection, server_side=True)
            self.handshakes += 1
            with contextlib.suppress(OSError):
                wrapped.recv(1)
            wrapped.close()
        except (OSError, ssl.SSLError):
            pass
        finally:
            with contextlib.suppress(OSError):
                connection.close()
