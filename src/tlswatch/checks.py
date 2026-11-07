"""Turn the facts a probe collected into findings and a grade.

The rubric is deliberately small and written down in docs/grading.md. It is not the SSL Labs
algorithm: it answers "what should I fix first on my own hosts", with reasons.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime

from tlswatch.model import GRADES, SEVERITY_GRADE, Finding, HostReport
from tlswatch.x509 import Certificate

BROKEN_SIGNATURES = ("md2", "md5")
WEAK_SIGNATURES = ("sha1", "dsawithsha1")
OLD_PROTOCOLS = ("TLSv1.0", "TLSv1.1")

CIPHER_FINDINGS = {
    "null-encryption": ("critical", "Cipher suites without encryption are accepted"),
    "anonymous": ("critical", "Cipher suites without authentication are accepted"),
    "rc4": ("high", "RC4 cipher suites are accepted"),
    "3des": ("high", "3DES cipher suites are accepted (Sweet32)"),
    "rsa-key-exchange": ("low", "Cipher suites without forward secrecy are accepted"),
}


def _platform_hint() -> str:
    """On Windows the trusted roots come from the Windows certificate store."""
    if sys.platform != "win32":
        return ""
    return (
        "on Windows the trusted roots are those in the Windows certificate store, which can "
        "lack a root that a browser would trust; if you believe this site is fine, run again "
        "with --ca-file pointing at a CA bundle such as Mozilla's"
    )


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def _remaining(days: float) -> str:
    if days < 0:
        return f"expired {_plural(int(-days), 'day')} ago" if -days >= 1 else "expired today"
    if days < 1:
        return f"expires in {int(days * 24)} hours"
    return f"expires in {_plural(int(days), 'day')}"


def _certificate_findings(
    cert: Certificate, now: datetime, warn_days: float, critical_days: float
) -> list[Finding]:
    found: list[Finding] = []
    days = cert.days_left(now)
    if now < cert.not_before:
        found.append(
            Finding("cert-not-yet-valid", "critical", "Certificate is not valid yet",
                    f"valid from {cert.not_before:%Y-%m-%d}")
        )  # fmt: skip
    elif days < 0:
        found.append(
            Finding("cert-expired", "critical", "Certificate has expired", _remaining(days))
        )
    elif days <= critical_days:
        found.append(
            Finding("cert-expires-soon", "high", "Certificate is about to expire", _remaining(days))
        )
    elif days <= warn_days:
        found.append(
            Finding("cert-expires-soon", "medium", "Certificate expires soon", _remaining(days))
        )

    algorithm = cert.signature_algorithm.lower()
    if any(algorithm.startswith(name) for name in BROKEN_SIGNATURES):
        found.append(Finding("sig-broken", "critical", "Certificate is signed with a broken hash",
                             cert.signature_algorithm))  # fmt: skip
    elif any(algorithm.startswith(name) for name in WEAK_SIGNATURES) or algorithm.endswith("sha1"):
        found.append(
            Finding(
                "sig-sha1", "high", "Certificate is signed with SHA-1", cert.signature_algorithm
            )
        )

    if cert.key_type == "RSA":
        if cert.key_bits < 1024:
            found.append(
                Finding("key-weak", "critical", "RSA key is far too short", f"{cert.key_bits} bits")
            )
        elif cert.key_bits < 2048:
            found.append(
                Finding(
                    "key-short",
                    "high",
                    "RSA key is shorter than 2048 bits",
                    f"{cert.key_bits} bits",
                )
            )
    elif cert.key_type == "EC" and 0 < cert.key_bits < 224:
        found.append(
            Finding(
                "key-short",
                "high",
                "Elliptic-curve key is shorter than 224 bits",
                f"{cert.key_bits} bits",
            )
        )
    elif cert.key_type == "DSA":
        found.append(
            Finding(
                "key-dsa", "high", "Certificate uses a DSA key", "DSA certificates are obsolete"
            )
        )
    return found


def _verification_findings(report: HostReport, now: datetime) -> list[Finding]:
    verification = report.verification
    if verification is None or verification.ok:
        return []
    cert = report.certificate
    verdict = verification.verdict
    message = verification.message
    if verdict in ("expired", "not_yet_valid"):
        leaf_reported = cert is not None and (cert.not_after < now or cert.not_before > now)
        if leaf_reported:
            return []  # the certificate checks already say so, with the dates
        return [Finding("chain-expired", "critical",
                        "A certificate in the chain has expired or is not valid yet", message)]  # fmt: skip
    if verdict == "hostname_mismatch":
        names = ""
        if cert is not None:
            listed = list(cert.san_dns) + list(cert.san_ip) or [cert.common_name or "no name"]
            names = (
                "certificate names: " + ", ".join(listed[:8]) + (" ..." if len(listed) > 8 else "")
            )
        return [Finding("hostname-mismatch", "critical",
                        f"Certificate is not valid for {report.target.name}", names)]  # fmt: skip
    if verdict == "self_signed":
        return [Finding("self-signed", "critical", "Certificate is self-signed", message)]
    if verdict == "untrusted":
        sent = len(report.chain) + 1 if report.certificate else 0
        hint = (
            "" if not report.chain_complete else f"the server sent {_plural(sent, 'certificate')}"
        )
        return [Finding("untrusted-issuer", "critical",
                        "Certificate chain is not trusted (unknown issuer or missing intermediate)",
                        "; ".join(part for part in (message, hint, _platform_hint()) if part))]  # fmt: skip
    return [Finding("verification-failed", "critical", "Certificate verification failed", message)]


def _protocol_findings(report: HostReport) -> list[Finding]:
    if not report.protocols:
        return []
    found: list[Finding] = []
    status = {name: outcome.status for name, outcome in report.protocols.items()}
    old = [name for name in OLD_PROTOCOLS if status.get(name) == "supported"]
    if old:
        found.append(Finding("protocol-deprecated", "medium",
                             "Deprecated protocol versions are enabled (RFC 8996)",
                             ", ".join(old)))  # fmt: skip
    modern = [status.get("TLSv1.2"), status.get("TLSv1.3")]
    if "supported" not in modern and "untestable" not in modern and "error" not in modern:
        found.append(Finding("protocol-no-modern", "critical",
                             "The server supports neither TLS 1.2 nor TLS 1.3"))  # fmt: skip
    if status.get("TLSv1.3") == "rejected":
        found.append(Finding("protocol-no-tls13", "info", "TLS 1.3 is not supported"))
    return found


def _cipher_findings(report: HostReport) -> list[Finding]:
    found: list[Finding] = []
    for name, outcome in report.ciphers.items():
        if outcome.status == "supported" and name in CIPHER_FINDINGS:
            severity, title = CIPHER_FINDINGS[name]
            found.append(Finding(f"cipher-{name}", severity, title, outcome.detail))
    return found


def _probe_gaps(report: HostReport) -> list[Finding]:
    """Say what could not be tested, so a clean report is not read as a clean bill of health."""
    skipped = sorted(
        [n for n, o in report.protocols.items() if o.status in ("untestable", "error")]
        + [n for n, o in report.ciphers.items() if o.status in ("untestable", "error")]
    )
    if not skipped:
        return []
    return [Finding("probe-gaps", "info", "Some checks could not be run from this machine",
                    ", ".join(skipped))]  # fmt: skip


def assess(
    report: HostReport,
    *,
    now: datetime | None = None,
    warn_days: float = 30,
    critical_days: float = 7,
) -> HostReport:
    """Fill `findings` and `grade` on a report (in place) and return it."""
    now = now or datetime.now(UTC)
    if report.error is not None:
        report.findings = [
            Finding("unreachable", "critical", "The host could not be checked", report.error)
        ]
        report.grade = None
        return report
    findings: list[Finding] = []
    if report.certificate is None:
        findings.append(Finding("cert-unreadable", "high",
                                "The certificate could not be parsed", "malformed or unusual encoding"))  # fmt: skip
    else:
        findings += _certificate_findings(report.certificate, now, warn_days, critical_days)
    for index, cert in enumerate(report.chain, start=1):
        if cert.not_after < now:
            findings.append(Finding("chain-expired", "critical",
                                    f"Chain certificate {index} has expired", cert.subject))  # fmt: skip
        elif cert.days_left(now) <= critical_days:
            findings.append(Finding("chain-expires-soon", "high",
                                    f"Chain certificate {index} is about to expire",
                                    f"{cert.subject}: {_remaining(cert.days_left(now))}"))  # fmt: skip
    findings += _verification_findings(report, now)
    findings += _protocol_findings(report)
    findings += _cipher_findings(report)
    findings += _probe_gaps(report)
    # One finding per id and detail, most severe first.
    seen: set[tuple[str, str]] = set()
    unique = []
    for finding in findings:
        key = (finding.id, finding.detail)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    order = {name: i for i, name in enumerate(("critical", "high", "medium", "low", "info"))}
    report.findings = sorted(unique, key=lambda f: order[f.severity])
    report.grade = grade_of(report.findings)
    return report


def grade_of(findings: list[Finding]) -> str:
    """The worst grade any finding allows; A when there is nothing."""
    worst = 0
    for finding in findings:
        worst = max(worst, GRADES.index(SEVERITY_GRADE[finding.severity]))
    return GRADES[worst]


def worse_than(grade: str | None, limit: str) -> bool:
    """True if `grade` is worse than `limit`. An unassessed host (None) is worse than anything."""
    return grade is None or GRADES.index(grade) > GRADES.index(limit)
