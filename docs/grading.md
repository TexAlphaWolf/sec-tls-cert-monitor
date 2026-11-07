# Grading

Every finding has a severity, and the severity decides the highest grade the host can have. The grade of a host is the worst one any of its findings allows; with no findings it is **A**.

| Severity | Grade cap |
|---|---|
| critical | F |
| high | D |
| medium | C |
| low | B |
| info | none |

A host that cannot be checked (nothing listens, no answer, not TLS) has **no grade** (`-`) and always counts as failing.

## Findings

| Finding id | Severity | When |
|---|---|---|
| `cert-expired` | critical | `notAfter` is in the past |
| `cert-not-yet-valid` | critical | `notBefore` is in the future |
| `cert-expires-soon` | high / medium | within `critical_days` (7) / within `warn_days` (30) |
| `sig-broken` | critical | MD2 or MD5 signature |
| `sig-sha1` | high | SHA-1 signature |
| `key-weak` | critical | RSA below 1024 bits |
| `key-short` | high | RSA 1024-2047 bits, EC below 224 bits |
| `key-dsa` | high | DSA key |
| `cert-unreadable` | high | the certificate could not be parsed |
| `hostname-mismatch` | critical | the certificate is not valid for the name checked (lists the names it has) |
| `self-signed` | critical | OpenSSL: self-signed certificate |
| `untrusted-issuer` | critical | unknown issuer, or the server did not send the intermediate |
| `chain-expired` | critical | an intermediate is expired or not yet valid |
| `chain-expires-soon` | high | an intermediate expires within `critical_days` (Python 3.13+ only) |
| `verification-failed` | critical | any other reason a normal client refuses the chain |
| `protocol-deprecated` | medium | TLS 1.0 or 1.1 accepted |
| `protocol-no-modern` | critical | neither TLS 1.2 nor TLS 1.3 accepted |
| `protocol-no-tls13` | info | TLS 1.3 not accepted |
| `cipher-null-encryption` | critical | NULL-encryption suites accepted |
| `cipher-anonymous` | critical | anonymous (unauthenticated) suites accepted |
| `cipher-rc4`, `cipher-3des` | high | RC4 / 3DES accepted |
| `cipher-rsa-key-exchange` | low | RSA key exchange accepted (no forward secrecy) |
| `probe-gaps` | info | some probes could not run from this machine; lists which |
| `unreachable` | critical | the host could not be checked |

The same expired certificate is reported once, as `cert-expired`, even though OpenSSL also refuses it.

## Why these choices

- **Expiry is graded, not only alerted.** A certificate with 20 days left is a C, so the default `--min-grade B` fails a job before the outage, not after.
- **TLS 1.3 missing is information only.** A well-run TLS 1.2 server is not a problem in itself.
- **RSA key exchange is only a B.** It means no forward secrecy for those suites; modern clients negotiate ECDHE anyway.
- **There is no "A+" and no E.** The scale is A, B, C, D, F so that a threshold is easy to say aloud.

The rubric is deliberately small: it answers "what should I fix first on my own hosts". Change it by editing `src/tlswatch/checks.py`; `tests/test_checks.py` has one test per row.
