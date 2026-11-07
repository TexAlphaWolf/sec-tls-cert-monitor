"""The network side: open connections and record what the server did.

Every function here returns facts. Deciding whether a fact is a problem is `checks.py`.
"""

from __future__ import annotations

import socket
import ssl
import time
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime

from tlswatch import starttls, x509
from tlswatch.der import DerError
from tlswatch.model import HostReport, Outcome, Target, Verification

# Offering old protocols or weak ciphers needs OpenSSL's lowest security level.
LEGACY = ":@SECLEVEL=0"
# "ALL" leaves out the NULL-encryption suites; a monitor has to be able to talk to a server that
# offers nothing else, in order to report it.
EVERYTHING = "ALL:eNULL" + LEGACY

PROTOCOLS = ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")

# (id, OpenSSL cipher string). Only what the local OpenSSL can offer can be tested.
CIPHER_CLASSES = (
    ("null-encryption", "eNULL"),
    ("anonymous", "aNULL"),
    ("rc4", "RC4"),
    ("3des", "3DES"),
    ("rsa-key-exchange", "kRSA"),
)

# OpenSSL reasons that mean "this client cannot do that", as opposed to "the server said no".
# UNSUPPORTED_PROTOCOL is deliberately not here: a client also gets it when the server answers
# with a version outside the range it offered, which is the server saying no.
_LOCAL_REASONS = {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH"}

# X509_V_ERR_* codes from OpenSSL's x509_vfy.h.
_VERDICTS = {
    10: "expired",
    9: "not_yet_valid",
    62: "hostname_mismatch",
    64: "hostname_mismatch",
    18: "self_signed",
    19: "untrusted",
    20: "untrusted",
    21: "untrusted",
    2: "untrusted",
}


class ProbeError(Exception):
    """The host could not be reached or did not complete a TLS handshake."""


@dataclass(slots=True)
class Session:
    version: str
    cipher: str
    cert_der: bytes
    chain_der: list[bytes]
    chain_complete: bool


def _version_object(name: str) -> ssl.TLSVersion:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return {
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }[name]


def _limit(context: ssl.SSLContext, low: str, high: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = _version_object(low)
        context.maximum_version = _version_object(high)


def _unverified_context(*, legacy: bool = False) -> ssl.SSLContext:
    """A client that accepts any certificate, so that a bad one can still be examined.

    The security level is lowered too: at the default level OpenSSL refuses to finish a
    handshake with a 1024-bit RSA certificate, and then there would be nothing to report.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if legacy:
        context.set_ciphers(EVERYTHING)
        _limit(context, "TLSv1.0", "TLSv1.3")
    else:
        context.set_ciphers("DEFAULT" + LEGACY)
    return context


def _verifying_context(ca_file: str | None) -> ssl.SSLContext:
    context = ssl.create_default_context()  # system trust store
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
    return context


def _connect(
    target: Target, context: ssl.SSLContext, timeout: float, *, need_certificate: bool = True
) -> Session:
    """One complete handshake. Raises OSError / ssl.SSLError / ProbeError.

    Anonymous cipher suites have no certificate, so the weak-cipher probes do not need one.
    """
    with socket.create_connection((target.host, target.port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        if target.starttls:
            try:
                starttls.negotiate(raw, target.starttls)
            except starttls.StarttlsError as exc:
                raise ProbeError(str(exc)) from exc
        with context.wrap_socket(raw, server_hostname=target.name) as tls:
            der = tls.getpeercert(binary_form=True)
            if der is None:
                if need_certificate:
                    raise ProbeError("the server sent no certificate")
                der = b""
            chain = [der]
            complete = False
            reader = getattr(tls, "get_unverified_chain", None)  # Python 3.13+
            if reader is not None:
                chain = [bytes(item) for item in (reader() or [])] or [der]
                complete = True
            cipher = tls.cipher()
            return Session(
                version=tls.version() or "unknown",
                cipher=cipher[0] if cipher else "unknown",
                cert_der=der,
                chain_der=chain,
                chain_complete=complete,
            )


def describe_error(exc: BaseException) -> str:
    """A short, readable reason for a failed connection."""
    if isinstance(exc, socket.gaierror):
        return f"name does not resolve ({exc.strerror or exc})"
    if isinstance(exc, TimeoutError):
        return "timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, ConnectionError):
        # Reset, aborted or broken pipe. Windows reports a server that answers a TLS hello with
        # plain text and hangs up this way, where Linux reports a TLS error.
        return "connection closed by the server during the handshake"
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {getattr(exc, 'reason', None) or exc}"
    if isinstance(exc, ProbeError):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


def verify(target: Target, timeout: float) -> Verification:
    """Does a normal, verifying client accept this server? And if not, why?"""
    try:
        _connect(target, _verifying_context(target.ca_file), timeout)
    except ssl.SSLCertVerificationError as exc:
        code = exc.verify_code
        return Verification(
            ok=False,
            verdict=_VERDICTS.get(code, "invalid"),
            message=exc.verify_message or str(exc),
            code=code,
        )
    except (OSError, ssl.SSLError, ProbeError) as exc:
        # Reachable a moment ago (the unverified handshake worked), so this is a different
        # kind of failure; report it as invalid rather than guess.
        return Verification(ok=False, verdict="invalid", message=describe_error(exc))
    return Verification(ok=True, verdict="valid")


def classify_failure(exc: BaseException) -> Outcome:
    """Turn the exception of an old-protocol or weak-cipher attempt into an outcome."""
    if isinstance(exc, ssl.SSLError):
        reason = getattr(exc, "reason", None) or ""
        if reason in _LOCAL_REASONS:
            return Outcome("untestable", f"this client cannot offer it ({reason})")
        return Outcome("rejected", reason.replace("_", " ").lower() or "handshake refused")
    if isinstance(exc, ConnectionError):
        return Outcome("rejected", "connection closed by the server")
    if isinstance(exc, TimeoutError):
        return Outcome("error", "timed out")
    return Outcome("error", describe_error(exc))


def probe_protocol(target: Target, protocol: str, timeout: float) -> Outcome:
    """Offer the server exactly one TLS version."""
    context = _unverified_context()
    try:
        context.set_ciphers(EVERYTHING)
        _limit(context, protocol, protocol)
    except (ssl.SSLError, ValueError) as exc:
        return Outcome("untestable", f"this client cannot offer it ({exc})")
    try:
        session = _connect(target, context, timeout, need_certificate=False)
    except (OSError, ssl.SSLError, ProbeError) as exc:
        return classify_failure(exc)
    return Outcome("supported", session.cipher)


def probe_cipher_class(target: Target, spec: str, timeout: float) -> Outcome:
    """Offer the server only the ciphers of one weak class (TLS 1.0 to 1.2)."""
    context = _unverified_context()
    try:
        context.set_ciphers(spec + LEGACY)
        _limit(context, "TLSv1.0", "TLSv1.2")
    except (ssl.SSLError, ValueError):
        return Outcome("untestable", "the local OpenSSL has no such cipher")
    try:
        session = _connect(target, context, timeout, need_certificate=False)
    except (OSError, ssl.SSLError, ProbeError) as exc:
        return classify_failure(exc)
    return Outcome("supported", f"{session.version} {session.cipher}")


def local_capabilities() -> dict[str, bool]:
    """What this machine's OpenSSL can offer, so a report can say "not tested" honestly."""
    result: dict[str, bool] = {}
    for protocol in PROTOCOLS:
        context = _unverified_context()
        try:
            context.set_ciphers(EVERYTHING)
            _limit(context, protocol, protocol)
            result[protocol] = True
        except (ssl.SSLError, ValueError):
            result[protocol] = False
    for name, spec in CIPHER_CLASSES:
        context = _unverified_context()
        try:
            context.set_ciphers(spec + LEGACY)
            result[name] = True
        except ssl.SSLError:
            result[name] = False
    return result


def _parse(der: bytes) -> x509.Certificate | None:
    try:
        return x509.parse(der)
    except DerError:
        return None


def _first_session(target: Target, timeout: float) -> tuple[Session | None, str]:
    """The handshake that reads the certificate: a modern client, then a legacy one."""
    try:
        return _connect(target, _unverified_context(), timeout), ""
    except (OSError, ssl.SSLError, ProbeError) as exc:
        failure = describe_error(exc)
        if not isinstance(exc, ssl.SSLError):
            return None, failure
    # A server stuck on TLS 1.0 or 1.1 refuses a modern client. That is exactly the kind of host
    # to report, so try again with a client that speaks the old protocols.
    try:
        return _connect(target, _unverified_context(legacy=True), timeout), ""
    except (OSError, ssl.SSLError, ProbeError):
        return None, failure + (_missing_cipher_hint() if _is_cipher_refusal(failure) else "")


def _is_cipher_refusal(failure: str) -> bool:
    return any(
        word in failure
        for word in ("HANDSHAKE_FAILURE", "NO_SHARED_CIPHER", "INSUFFICIENT_SECURITY")
    )


def _missing_cipher_hint() -> str:
    """A handshake that fails everywhere may be a server that only offers what this OpenSSL lacks."""
    missing = [name for name in ("rc4", "3des") if not local_capabilities().get(name, True)]
    if not missing:
        return ""
    return (
        f" (this machine's OpenSSL has no {' and no '.join(m.upper() for m in missing)}, so a "
        "server that offers only those cannot be examined from here)"
    )


def collect(
    target: Target,
    *,
    timeout: float = 5.0,
    protocols: bool = True,
    ciphers: bool = True,
    now: datetime | None = None,
) -> HostReport:
    """Probe one host and return the raw facts (no findings, no grade yet)."""
    started = time.monotonic()
    report = HostReport(target=target, scanned_at=now or datetime.now(UTC))
    session, failure = _first_session(target, timeout)
    if session is None:
        report.error = failure
        report.duration = time.monotonic() - started
        return report

    report.version = session.version
    report.cipher = session.cipher
    report.chain_complete = session.chain_complete
    parsed = [_parse(item) for item in session.chain_der]
    report.certificate = parsed[0]
    report.chain = [item for item in parsed[1:] if item is not None]
    report.verification = verify(target, timeout)

    if protocols:
        for protocol in PROTOCOLS:
            report.protocols[protocol] = probe_protocol(target, protocol, timeout)
    if ciphers:
        speaks_legacy = not protocols or any(
            report.protocols[p].status == "supported" for p in PROTOCOLS[:3]
        )
        for name, spec in CIPHER_CLASSES:
            if speaks_legacy:
                report.ciphers[name] = probe_cipher_class(target, spec, timeout)
            else:
                report.ciphers[name] = Outcome("skipped", "the server only speaks TLS 1.3")
    report.duration = time.monotonic() - started
    return report
