"""Render reports as text, JSON or the Prometheus exposition format."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from tlswatch.model import GRADES, SEVERITIES, HostReport
from tlswatch.probe import PROTOCOLS

GRADE_SCORE = {grade: len(GRADES) - 1 - index for index, grade in enumerate(GRADES)}  # A=4 .. F=0


def _yes_no(status: str) -> str:
    return {"supported": "yes", "rejected": "no"}.get(status, status)


def text(reports: list[HostReport], min_grade: str, now: datetime | None = None) -> str:
    from tlswatch.checks import worse_than

    now = now or datetime.now(UTC)
    lines: list[str] = []
    for report in reports:
        grade = report.grade or "-"
        lines.append(f"{report.target.label}  grade {grade}")
        cert = report.certificate
        if report.error:
            lines.append(f"  unreachable: {report.error}")
        if cert is not None:
            days = cert.days_left(now)
            lines.append(f"  certificate  {cert.subject}")
            lines.append(f"               issued by {cert.issuer}")
            when = f"{cert.not_after:%Y-%m-%d}"
            left = f"{int(days)} days left" if days >= 0 else f"expired {int(-days)} days ago"
            lines.append(f"               valid until {when} ({left})")
            key = f"{cert.key_type} {cert.key_bits}" if cert.key_bits else cert.key_type
            lines.append(f"               {key}, {cert.signature_algorithm}")
        if report.verification is not None:
            v = report.verification
            lines.append(f"  trust        {'verified' if v.ok else 'NOT verified: ' + v.verdict}")
        if report.version:
            lines.append(f"  negotiated   {report.version} {report.cipher}")
        if report.protocols:
            shown = ", ".join(
                f"{p[4:]} {_yes_no(report.protocols[p].status)}"
                for p in PROTOCOLS
                if p in report.protocols
            )
            lines.append(f"  protocols    {shown}")
        if report.ciphers:
            accepted = [n for n, o in report.ciphers.items() if o.status == "supported"]
            untested = [n for n, o in report.ciphers.items() if o.status in ("untestable", "error")]
            summary = ", ".join(accepted) if accepted else "none accepted"
            lines.append(f"  weak ciphers {summary}")
            if untested:
                lines.append(f"               not tested from this machine: {', '.join(untested)}")
        for finding in report.findings:
            if finding.severity == "info" and finding.id == "unreachable":
                continue
            detail = f": {finding.detail}" if finding.detail else ""
            lines.append(f"  [{finding.severity:<8}] {finding.title}{detail}")
        lines.append("")
    failing = sum(1 for r in reports if worse_than(r.grade, min_grade))
    lines.append(
        f"{len(reports)} host{'s' if len(reports) != 1 else ''} checked, "
        f"{len(reports) - failing} at grade {min_grade} or better, {failing} below"
    )
    return "\n".join(lines) + "\n"


def to_json(reports: list[HostReport], min_grade: str) -> str:
    from tlswatch.checks import worse_than

    document = {
        "min_grade": min_grade,
        "failing": sum(1 for r in reports if worse_than(r.grade, min_grade)),
        "hosts": [r.to_dict() for r in reports],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def prometheus(reports: list[HostReport], now: datetime | None = None) -> str:
    """Metrics in the text exposition format (version 0.0.4)."""
    now = now or datetime.now(UTC)
    metrics: dict[str, tuple[str, str, list[str]]] = {}

    def add(name: str, help_text: str, kind: str, labels: str, value: float | int) -> None:
        entry = metrics.setdefault(name, (help_text, kind, []))
        entry[2].append(f"{name}{{{labels}}} {value:g}" if labels else f"{name} {value:g}")

    for r in reports:
        base = f'host="{_label(r.target.host)}",port="{r.target.port}"'
        add(
            "tlswatch_up",
            "1 if a TLS handshake with the host succeeded",
            "gauge",
            base,
            int(r.error is None),
        )
        add(
            "tlswatch_scan_duration_seconds",
            "Time spent probing the host",
            "gauge",
            base,
            r.duration,
        )
        add(
            "tlswatch_last_scan_timestamp_seconds",
            "Unix time of the last probe",
            "gauge",
            base,
            r.scanned_at.timestamp(),
        )
        if r.certificate is not None:
            add(
                "tlswatch_cert_not_after_timestamp_seconds",
                "Unix time the leaf certificate expires",
                "gauge",
                base,
                r.certificate.not_after.timestamp(),
            )
            add(
                "tlswatch_cert_days_remaining",
                "Days until the leaf certificate expires (negative: expired)",
                "gauge",
                base,
                round(r.certificate.days_left(now), 3),
            )
        if r.verification is not None:
            add(
                "tlswatch_cert_verified",
                "1 if a normal client would trust the certificate chain for this name",
                "gauge",
                base,
                int(r.verification.ok),
            )
        if r.grade is not None:
            add(
                "tlswatch_grade_score",
                "Grade as a number: A=4, B=3, C=2, D=1, F=0",
                "gauge",
                base,
                GRADE_SCORE[r.grade],
            )
            add(
                "tlswatch_grade_info",
                "The grade as a label",
                "gauge",
                f'{base},grade="{r.grade}"',
                1,
            )
        for protocol, outcome in r.protocols.items():
            if outcome.status in ("supported", "rejected"):
                add(
                    "tlswatch_protocol_supported",
                    "1 if the server accepts the TLS version, 0 if it refuses it",
                    "gauge",
                    f'{base},protocol="{protocol}"',
                    int(outcome.status == "supported"),
                )
        for name, outcome in r.ciphers.items():
            if outcome.status in ("supported", "rejected"):
                add(
                    "tlswatch_weak_cipher_accepted",
                    "1 if the server accepts a class of weak cipher suites",
                    "gauge",
                    f'{base},class="{name}"',
                    int(outcome.status == "supported"),
                )
        for severity in SEVERITIES:
            count = sum(1 for f in r.findings if f.severity == severity)
            add(
                "tlswatch_findings",
                "Number of findings by severity",
                "gauge",
                f'{base},severity="{severity}"',
                count,
            )

    out: list[str] = []
    for name, (help_text, kind, samples) in metrics.items():
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        out.extend(samples)
    return "\n".join(out) + "\n"
