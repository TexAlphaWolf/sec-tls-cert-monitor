"""Scan many hosts, a few at a time."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from tlswatch import checks, probe
from tlswatch.model import HostReport, Target


def scan_one(
    target: Target,
    *,
    timeout: float = 5.0,
    warn_days: float = 30,
    critical_days: float = 7,
    protocols: bool = True,
    ciphers: bool = True,
    now: datetime | None = None,
) -> HostReport:
    try:
        report = probe.collect(
            target, timeout=timeout, protocols=protocols, ciphers=ciphers, now=now
        )
    except Exception as exc:  # one broken host must not take the whole run down
        report = HostReport(target=target, scanned_at=now or datetime.now(UTC))
        report.error = f"internal error: {type(exc).__name__}: {exc}"
    return checks.assess(report, now=now, warn_days=warn_days, critical_days=critical_days)


def scan_all(
    targets: list[Target],
    *,
    workers: int = 8,
    timeout: float = 5.0,
    warn_days: float = 30,
    critical_days: float = 7,
    protocols: bool = True,
    ciphers: bool = True,
    now: datetime | None = None,
) -> list[HostReport]:
    """Reports in the same order as `targets`."""
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        futures = [
            pool.submit(
                scan_one,
                target,
                timeout=timeout,
                warn_days=warn_days,
                critical_days=critical_days,
                protocols=protocols,
                ciphers=ciphers,
                now=now,
            )
            for target in targets
        ]
        return [future.result() for future in futures]
