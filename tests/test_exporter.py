import threading
import time
import urllib.error
import urllib.request

import pytest

from test_checks import assess, report
from tlswatch.exporter import Exporter


def fetch(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
            return response.status, response.headers.get("Content-Type"), response.read().decode()
    except urllib.error.HTTPError as error:
        with error:  # closes the response body, or Python 3.14 warns about it
            return error.code, error.headers.get("Content-Type"), error.read().decode()


@pytest.fixture
def run():
    started = []

    def _run(scan, interval=60):
        exporter = Exporter(scan, interval=interval, address=("127.0.0.1", 0))
        thread = threading.Thread(target=exporter.serve_forever, daemon=True)
        thread.start()
        started.append((exporter, thread))
        return exporter

    yield _run
    for exporter, thread in started:
        exporter.close()
        thread.join(timeout=10)


def wait_for(condition, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


def test_metrics_are_served_after_the_first_scan(run):
    exporter = run(lambda: [assess(report())])
    assert wait_for(lambda: exporter.metrics() is not None)
    status, content_type, body = fetch(exporter.port, "/metrics")
    assert status == 200 and content_type.startswith("text/plain; version=0.0.4")
    assert 'tlswatch_grade_info{host="example.org",port="443",grade="A"} 1' in body


def test_503_until_a_scan_has_finished(run):
    release = threading.Event()

    def slow():
        release.wait(5)
        return [assess(report())]

    exporter = run(slow)
    try:
        assert fetch(exporter.port, "/metrics")[0] == 503
        assert fetch(exporter.port, "/healthz")[0] == 200
    finally:
        release.set()
    assert wait_for(lambda: exporter.metrics() is not None)
    assert fetch(exporter.port, "/metrics")[0] == 200


def test_other_paths(run):
    exporter = run(lambda: [])
    assert fetch(exporter.port, "/")[0] == 200
    assert fetch(exporter.port, "/nope")[0] == 404
    assert fetch(exporter.port, "/metrics?x=1")[0] in (200, 503)


def test_a_failing_scan_keeps_the_last_good_metrics(run):
    calls = []

    def scan():
        calls.append(1)
        if len(calls) > 1:
            raise RuntimeError("scan blew up")
        return [assess(report())]

    exporter = run(scan, interval=0.05)
    assert wait_for(lambda: len(calls) >= 3)
    assert 'tlswatch_up{host="example.org"' in fetch(exporter.port, "/metrics")[2]


def test_it_rescans_on_the_interval(run):
    calls = []
    exporter = run(lambda: calls.append(1) or [], interval=0.05)
    assert wait_for(lambda: len(calls) >= 3)
    assert exporter.metrics() is not None
