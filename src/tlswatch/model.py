"""Plain data shared by the probes, the checks and the reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from tlswatch.x509 import Certificate

# From best to worst. There is no "E": the scale is A, B, C, D, F.
GRADES = ("A", "B", "C", "D", "F")
SEVERITIES = ("critical", "high", "medium", "low", "info")
# The grade a finding of each severity caps the host at.
SEVERITY_GRADE = {"critical": "F", "high": "D", "medium": "C", "low": "B", "info": "A"}

STARTTLS_PROTOCOLS = ("smtp", "imap", "pop3")


@dataclass(frozen=True, slots=True)
class Target:
    host: str
    port: int = 443
    server_name: str | None = None  # SNI and the name the certificate is checked against
    starttls: str | None = None  # smtp | imap | pop3
    ca_file: str | None = None  # extra trusted CA certificates (PEM), on top of the system's

    @property
    def label(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def name(self) -> str:
        return self.server_name or self.host


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    severity: str  # one of SEVERITIES
    title: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class Outcome:
    """What happened when one protocol version or cipher class was offered to the server."""

    status: str  # supported | rejected | untestable | error | skipped
    detail: str = ""  # negotiated cipher, or the reason


@dataclass(slots=True)
class Verification:
    ok: bool
    verdict: str  # valid | expired | not_yet_valid | hostname_mismatch | self_signed | untrusted | invalid
    message: str = ""
    code: int | None = None


@dataclass(slots=True)
class HostReport:
    target: Target
    scanned_at: datetime
    duration: float = 0.0
    error: str | None = None  # the host could not be reached or did not speak TLS
    version: str | None = None  # TLS version a modern client gets
    cipher: str | None = None
    certificate: Certificate | None = None
    chain: list[Certificate] = field(default_factory=list)
    chain_complete: bool = False  # False when the Python in use cannot read the chain (< 3.13)
    verification: Verification | None = None
    protocols: dict[str, Outcome] = field(default_factory=dict)
    ciphers: dict[str, Outcome] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    grade: str | None = None  # None when the host could not be assessed

    def to_dict(self) -> dict[str, Any]:
        cert = self.certificate
        return {
            "host": self.target.host,
            "port": self.target.port,
            "server_name": self.target.name,
            "starttls": self.target.starttls,
            "scanned_at": self.scanned_at.isoformat(),
            "duration_seconds": round(self.duration, 3),
            "error": self.error,
            "grade": self.grade,
            "negotiated": {"version": self.version, "cipher": self.cipher},
            "certificate": None
            if cert is None
            else {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "serial": f"{cert.serial:x}",
                "not_before": cert.not_before.isoformat(),
                "not_after": cert.not_after.isoformat(),
                "san_dns": list(cert.san_dns),
                "san_ip": list(cert.san_ip),
                "signature_algorithm": cert.signature_algorithm,
                "key": f"{cert.key_type} {cert.key_bits}" if cert.key_bits else cert.key_type,
                "sha256": cert.sha256,
            },
            "chain_length": len(self.chain),
            "chain_complete": self.chain_complete,
            "verification": None
            if self.verification is None
            else {
                "ok": self.verification.ok,
                "verdict": self.verification.verdict,
                "message": self.verification.message,
            },
            "protocols": {
                k: {"status": v.status, "detail": v.detail} for k, v in self.protocols.items()
            },
            "ciphers": {
                k: {"status": v.status, "detail": v.detail} for k, v in self.ciphers.items()
            },
            "findings": [f.to_dict() for f in self.findings],
        }
