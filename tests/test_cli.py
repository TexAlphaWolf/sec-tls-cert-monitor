import json
import socket
import threading
import urllib.request

import pytest

from tlswatch import cli


def run(capsys, *args):
    code = cli.main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def args_for(server, ca_file, *extra):
    return [
        "check",
        f"127.0.0.1:{server.port}",
        "--server-name",
        "localhost",
        "--ca-file",
        str(ca_file),
        *extra,
    ]


def test_a_good_host_exits_zero(capsys, start, leaf, ca_file):
    code, out, _ = run(capsys, *args_for(start(leaf), ca_file))
    assert code == 0 and "grade A" in out


def test_a_bad_host_exits_one(capsys, start, ca_file):
    import pki

    expired = pki.issue("localhost", sans=["localhost"], days_from=-20, days_to=-1)
    code, out, _ = run(capsys, *args_for(start(expired), ca_file))
    assert code == 1 and "grade F" in out


def test_min_grade_moves_the_line(capsys, start, ca, ca_file):
    import pki

    soon = pki.issue("localhost", issuer=ca, sans=["localhost"], days_to=10)  # a C
    server = start(soon)
    assert run(capsys, *args_for(server, ca_file))[0] == 1
    assert run(capsys, *args_for(server, ca_file, "--min-grade", "C"))[0] == 0
    assert (
        run(capsys, *args_for(server, ca_file, "--warn-days", "5", "--critical-days", "2"))[0] == 0
    )


def test_an_unreachable_host_always_fails(capsys):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    code, out, _ = run(capsys, "check", f"127.0.0.1:{port}", "--min-grade", "F")
    assert code == 1 and "connection refused" in out


def test_json_and_prometheus_formats_and_output_file(capsys, start, leaf, ca_file, tmp_path):
    server = start(leaf)
    code, out, _ = run(capsys, *args_for(server, ca_file, "--format", "json"))
    assert code == 0 and json.loads(out)["hosts"][0]["grade"] == "A"
    code, out, _ = run(capsys, *args_for(server, ca_file, "--format", "prometheus"))
    assert code == 0 and "tlswatch_grade_score" in out
    target = tmp_path / "report.txt"
    code, out, _ = run(capsys, *args_for(server, ca_file, "-o", str(target)))
    assert out == "" and "grade A" in target.read_text()


def test_probe_switches(capsys, start, leaf, ca_file):
    code, out, _ = run(
        capsys,
        *args_for(start(leaf), ca_file, "--no-protocols", "--no-ciphers", "--format", "json"),
    )
    data = json.loads(out)["hosts"][0]
    assert code == 0 and data["protocols"] == {} and data["ciphers"] == {}


def test_a_config_file_and_command_line_targets_are_combined(
    capsys, start, leaf, ca_file, tmp_path
):
    one, two = start(leaf), start(leaf)
    config = tmp_path / "hosts.toml"
    config.write_text(
        f'[settings]\ntimeout = 4\nmin_grade = "A"\n[[hosts]]\nhost = "127.0.0.1"\nport = {two.port}\n'
        f'server_name = "localhost"\nca_file = "{ca_file.name}"\n',
        encoding="utf-8",
    )
    code, out, _ = run(
        capsys,
        "check",
        f"127.0.0.1:{one.port}",
        "--server-name",
        "localhost",
        "--ca-file",
        str(ca_file),
        "-c",
        str(config),
        "--format",
        "json",
    )
    data = json.loads(out)
    assert code == 0 and [h["port"] for h in data["hosts"]] == [one.port, two.port]
    assert data["min_grade"] == "A"  # from the file


def test_the_command_line_beats_the_config_file(capsys, tmp_path):
    config = tmp_path / "hosts.toml"
    config.write_text(
        '[settings]\nmin_grade = "A"\n[[hosts]]\nhost = "127.0.0.1"\nport = 1\n', encoding="utf-8"
    )
    _, out, _ = run(
        capsys, "check", "-c", str(config), "--min-grade", "D", "--format", "json", "--timeout", "1"
    )
    assert json.loads(out)["min_grade"] == "D"


@pytest.mark.parametrize(
    "args",
    [
        ["check"],  # nothing to check
        ["check", "bad host"],
        ["check", "example.org", "--warn-days", "3", "--critical-days", "9"],
        ["check", "-c", "/nonexistent/file.toml"],
        ["serve", "example.org", "--listen", "nonsense"],
        ["serve", "example.org", "--interval", "0"],
    ],
)
def test_usage_errors_exit_two(capsys, args):
    code, _, err = run(capsys, *args)
    assert code == 2 and err.startswith("tlswatch: ")


def test_writing_to_an_impossible_path_is_an_error_not_a_traceback(
    capsys, start, leaf, ca_file, tmp_path
):
    code, _, err = run(
        capsys, *args_for(start(leaf), ca_file, "-o", str(tmp_path / "missing" / "r.txt"))
    )
    assert code == 2 and err.startswith("tlswatch: ")


def test_capabilities_lists_every_probe(capsys):
    code, out, _ = run(capsys, "capabilities")
    assert code == 0
    for name in ("TLSv1.2", "TLSv1.3", "rc4", "3des", "anonymous"):
        assert name in out


def test_version_and_help_exit_cleanly(capsys):
    for flag in ("--version", "--help"):
        with pytest.raises(SystemExit) as stop:
            cli.main([flag])
        assert stop.value.code == 0
    capsys.readouterr()


def test_serve_exposes_metrics_and_stops_on_a_signal(capsys, start, leaf, ca_file, monkeypatch):
    server = start(leaf)
    started = threading.Event()
    holder = {}
    real = cli.Exporter

    class Spy(real):
        def start(self):
            holder["exporter"] = self
            super().start()
            started.set()

    monkeypatch.setattr(cli, "Exporter", Spy)
    result = {}
    handlers = {}
    monkeypatch.setattr(
        cli.signal, "signal", lambda number, handler: handlers.__setitem__(number, handler)
    )
    thread = threading.Thread(
        target=lambda: result.update(
            code=cli.main(
                [
                    "serve",
                    f"127.0.0.1:{server.port}",
                    "--server-name",
                    "localhost",
                    "--ca-file",
                    str(ca_file),
                    "--listen",
                    "127.0.0.1:0",
                    "--interval",
                    "30",
                    "--no-ciphers",
                ]
            )
        ),
        daemon=True,
    )
    thread.start()
    assert started.wait(10)
    exporter = holder["exporter"]
    import time

    deadline = time.monotonic() + 15
    while exporter.metrics() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    with urllib.request.urlopen(f"http://127.0.0.1:{exporter.port}/metrics", timeout=5) as response:
        body = response.read().decode()
    assert 'tlswatch_up{host="127.0.0.1"' in body
    handlers[cli.signal.SIGINT](cli.signal.SIGINT, None)
    handlers[cli.signal.SIGINT](cli.signal.SIGINT, None)  # a second signal is harmless
    thread.join(timeout=15)
    assert result == {"code": 0}
