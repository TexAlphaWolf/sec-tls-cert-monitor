"""A Prometheus exporter: scans in the background, serves the last result on /metrics."""

from __future__ import annotations

import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tlswatch import report
from tlswatch.model import HostReport

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class Exporter:
    def __init__(
        self,
        scan: Callable[[], list[HostReport]],
        *,
        interval: float,
        address: tuple[str, int] = ("127.0.0.1", 9117),
    ) -> None:
        self._scan = scan
        self.interval = interval
        self._lock = threading.Lock()
        self._metrics: str | None = None
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._loop, daemon=True)
        handler = self._handler()
        self.server = ThreadingHTTPServer(address, handler)
        self.server.daemon_threads = True

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def refresh(self) -> None:
        """Run one scan and keep its metrics. A failing scan keeps the previous metrics."""
        try:
            rendered = report.prometheus(self._scan())
        except Exception:  # keep serving the last good result
            return
        with self._lock:
            self._metrics = rendered

    def metrics(self) -> str | None:
        with self._lock:
            return self._metrics

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.refresh()
            self._stop.wait(self.interval)

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        exporter = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path == "/metrics":
                    body = exporter.metrics()
                    if body is None:
                        self._reply(503, "no scan has finished yet\n")
                    else:
                        self._reply(200, body, CONTENT_TYPE)
                elif path == "/healthz":
                    self._reply(200, "ok\n")
                elif path == "/":
                    self._reply(200, "tlswatch exporter: see /metrics\n")
                else:
                    self._reply(404, "not found\n")

            def _reply(
                self, status: int, body: str, content_type: str = "text/plain; charset=utf-8"
            ) -> None:
                data = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                return  # a scrape every few seconds would flood the log

        return Handler

    def start(self) -> None:
        self._worker.start()

    def serve_forever(self) -> None:
        self.start()
        self.server.serve_forever(poll_interval=0.2)

    def close(self) -> None:
        self._stop.set()
        self.server.shutdown()
        self.server.server_close()
        if self._worker.is_alive():
            self._worker.join(timeout=10)
