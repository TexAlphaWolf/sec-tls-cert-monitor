import datetime as dt
import json
import re

import pytest

from conftest import target_for
from test_checks import NOW, assess, cert, report
from tlswatch import report as rendering
from tlswatch.model import HostReport, Outcome, Target
from tlswatch.scan import scan_all


def reports():
    good = assess(report())
    bad = assess(
        report(
            target=Target("old.example", 8443),
            certificate=cert(signature_algorithm="sha1WithRSAEncryption"),
        )
    )
    down = assess(
        HostReport(target=Target("down.example"), scanned_at=NOW, error="connection refused")
    )
    return [good, bad, down]


def test_text_report_is_ascii_and_lists_every_host():
    out = rendering.text(reports(), "B", now=NOW)
    out.encode("ascii")  # a Windows console in a legacy code page must be able to print it
    assert "example.org:443  grade A" in out
    assert "old.example:8443  grade D" in out
    assert "down.example:443  grade -" in out
    assert "unreachable: connection refused" in out
    assert "[high    ] Certificate is signed with SHA-1: sha1WithRSAEncryption" in out
    assert out.strip().splitlines()[-1] == "3 hosts checked, 1 at grade B or better, 2 below"


def test_text_report_shows_dates_and_untested_probes():
    r = assess(
        report(ciphers={"rc4": Outcome("untestable", "x"), "anonymous": Outcome("rejected")})
    )
    out = rendering.text([r], "B", now=NOW)
    assert "valid until 2026-12-18 (200 days left)" in out
    assert "not tested from this machine: rc4" in out
    assert "protocols    1.0 no, 1.1 no, 1.2 yes, 1.3 yes" in out


def test_text_report_for_an_expired_certificate():
    r = assess(report(certificate=cert(not_after=NOW - dt.timedelta(days=4))))
    assert "expired 4 days ago" in rendering.text([r], "B", now=NOW)


def test_one_host_is_not_plural():
    assert (
        rendering.text([assess(report())], "B", now=NOW)
        .strip()
        .endswith("1 host checked, 1 at grade B or better, 0 below")
    )


def test_json_report():
    data = json.loads(rendering.to_json(reports(), "B"))
    assert data["failing"] == 2 and data["min_grade"] == "B"
    assert [h["grade"] for h in data["hosts"]] == ["A", "D", None]
    assert data["hosts"][2]["error"] == "connection refused"
    assert data["hosts"][0]["certificate"]["key"] == "RSA 2048"


def metrics(text):
    """A strict reader for the exposition format: every sample must follow its TYPE line."""
    samples = {}
    declared = set()
    for line in text.splitlines():
        if line.startswith("# HELP "):
            continue
        if line.startswith("# TYPE "):
            declared.add(line.split()[2])
            continue
        match = re.fullmatch(r"(\w+)(?:\{(.*)\})? (-?[0-9.e+-]+)", line)
        assert match, f"not a valid sample line: {line!r}"
        name, labels, value = match.groups()
        assert name in declared
        found = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', labels or ""))
        samples.setdefault(name, []).append((found, float(value)))
    return samples


def test_prometheus_output_is_well_formed_and_has_the_documented_metrics():
    samples = metrics(rendering.prometheus(reports(), now=NOW))
    assert set(samples) >= {
        "tlswatch_up",
        "tlswatch_cert_not_after_timestamp_seconds",
        "tlswatch_cert_days_remaining",
        "tlswatch_cert_verified",
        "tlswatch_grade_score",
        "tlswatch_grade_info",
        "tlswatch_protocol_supported",
        "tlswatch_weak_cipher_accepted",
        "tlswatch_findings",
    }
    up = {s[0]["host"]: s[1] for s in samples["tlswatch_up"]}
    assert up == {"example.org": 1, "old.example": 1, "down.example": 0}
    score = {s[0]["host"]: s[1] for s in samples["tlswatch_grade_score"]}
    assert score == {"example.org": 4, "old.example": 1}  # no grade for the host that is down
    days = {s[0]["host"]: s[1] for s in samples["tlswatch_cert_days_remaining"]}
    assert days["example.org"] == pytest.approx(200.0)
    assert ({"host": "old.example", "port": "8443", "grade": "D"}, 1.0) in samples[
        "tlswatch_grade_info"
    ]
    high = [
        v
        for labels, v in samples["tlswatch_findings"]
        if labels["host"] == "old.example" and labels["severity"] == "high"
    ]
    assert high == [1.0]


def test_untestable_probes_are_left_out_of_the_metrics():
    r = assess(
        report(
            protocols={"TLSv1.0": Outcome("untestable"), "TLSv1.2": Outcome("supported")},
            ciphers={"rc4": Outcome("untestable")},
        )
    )
    samples = metrics(rendering.prometheus([r], now=NOW))
    assert [s[0]["protocol"] for s in samples["tlswatch_protocol_supported"]] == ["TLSv1.2"]
    assert "tlswatch_weak_cipher_accepted" not in samples


def test_label_values_are_escaped():
    r = assess(HostReport(target=Target('we"ird\\host\nname'), scanned_at=NOW, error="x"))
    out = rendering.prometheus([r], now=NOW)
    assert 'host="we\\"ird\\\\host\\nname"' in out
    metrics(out)


def test_an_empty_list_renders_nothing_harmful():
    assert rendering.prometheus([], now=NOW) == "\n"


def test_scan_all_keeps_the_input_order_and_survives_a_dead_host(start, leaf, ca_file):
    first, second = start(leaf), start(leaf)
    targets = [target_for(first, ca_file), Target("127.0.0.1", 1), target_for(second, ca_file)]
    result = scan_all(targets, workers=3, timeout=3, protocols=False, ciphers=False)
    assert [r.target for r in result] == targets
    assert [r.grade for r in result] == ["A", None, "A"]
    assert scan_all([]) == []
