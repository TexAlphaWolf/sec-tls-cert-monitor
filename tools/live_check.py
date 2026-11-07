"""Check tlswatch against the public test hosts of badssl.com.

    python tools/live_check.py

Needs internet access. It asserts only what each host is built to demonstrate and prints the
rest for a human to read. The run is not part of the normal CI because it depends on a third
party staying up; the Live workflow runs it weekly.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field

from tlswatch.config import parse_target
from tlswatch.model import HostReport
from tlswatch.scan import scan_all

BAD_NAME_ISSUES = {
    "cert-expired",
    "hostname-mismatch",
    "self-signed",
    "untrusted-issuer",
    "cert-unreadable",
}


@dataclass
class Case:
    target: str
    what: str
    any_of: set[str] = field(default_factory=set)  # at least one of these findings must be present
    absent: set[str] = field(default_factory=set)  # none of these may be present
    check: Callable[[HostReport], bool] | None = None
    informational: bool = False


CASES = [
    Case("badssl.com", "a valid site", absent=BAD_NAME_ISSUES),
    Case("expired.badssl.com", "expired certificate", any_of={"cert-expired"}),
    Case("wrong.host.badssl.com", "certificate for another name", any_of={"hostname-mismatch"}),
    Case("self-signed.badssl.com", "self-signed certificate", any_of={"self-signed"}),
    Case("untrusted-root.badssl.com", "root that is not trusted", any_of={"untrusted-issuer"}),
    Case(
        "tls-v1-0.badssl.com:1010",
        "TLS 1.0 accepted",
        any_of={"protocol-deprecated", "protocol-no-modern"},
    ),
    Case(
        "tls-v1-1.badssl.com:1011",
        "TLS 1.1 accepted",
        any_of={"protocol-deprecated", "protocol-no-modern"},
    ),
    Case(
        "1000-sans.badssl.com",
        "1,000 names in one certificate (parser)",
        absent={"cert-unreadable"},
        check=lambda r: r.certificate is not None and len(r.certificate.san_dns) >= 900,
    ),
    Case(
        "no-common-name.badssl.com",
        "certificate without a common name (parser)",
        absent={"cert-unreadable"},
        check=lambda r: r.certificate is not None and r.certificate.common_name is None,
    ),
    Case(
        "no-subject.badssl.com",
        "certificate with an empty subject (parser)",
        absent={"cert-unreadable"},
        check=lambda r: r.certificate is not None and r.certificate.subject == "",
    ),
    Case(
        "rsa8192.badssl.com",
        "8192-bit RSA key (parser)",
        absent={"cert-unreadable"},
        check=lambda r: r.certificate is not None and r.certificate.key_bits == 8192,
    ),
    Case(
        "ecc384.badssl.com",
        "P-384 key (parser)",
        absent={"cert-unreadable"},
        check=lambda r: (
            r.certificate is not None
            and (r.certificate.key_type, r.certificate.key_bits) == ("EC", 384)
        ),
    ),
    Case("incomplete-chain.badssl.com", "server omits the intermediate", informational=True),
    Case(
        "revoked.badssl.com",
        "revoked certificate (not detected: no revocation checks)",
        informational=True,
    ),
    Case("rc4.badssl.com", "RC4 (only testable if this OpenSSL has RC4)", informational=True),
    Case("3des.badssl.com", "3DES (only testable if this OpenSSL has 3DES)", informational=True),
    Case("null.badssl.com", "NULL cipher", informational=True),
]


def main() -> int:
    reports = scan_all([parse_target(c.target) for c in CASES], workers=6, timeout=15)
    failures = 0
    print(f"{'host':<34} {'grade':>5}  result")
    for case, report in zip(CASES, reports, strict=True):
        found = {f.id for f in report.findings}
        problems = []
        if case.any_of and not (case.any_of & found):
            problems.append(f"expected one of {sorted(case.any_of)}")
        if case.absent & found:
            problems.append(f"unexpected {sorted(case.absent & found)}")
        if case.check is not None and not case.check(report):
            problems.append("certificate fields differ from what the host is built to show")
        if report.error and not case.informational:
            problems.append(f"unreachable: {report.error}")
        status = (
            "info" if case.informational else ("FAIL: " + "; ".join(problems) if problems else "ok")
        )
        failures += bool(problems) and not case.informational
        print(f"{case.target:<34} {report.grade or '-':>5}  {status}  ({case.what})")
        # Always show why a host got its grade, so a surprising one can be read, not guessed at.
        reasons = ", ".join(f.id for f in report.findings if f.severity != "info") or "no findings"
        print(f"{'':<42}{reasons}{'; ' + report.error if report.error else ''}")
    print(f"\nchecks failed: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
