# Prometheus metrics

`tlswatch serve` scans every `--interval` seconds (default 300) and serves the last complete result. If a scan fails as a whole, the previous metrics stay; `tlswatch_last_scan_timestamp_seconds` shows how old each host's data is. `/metrics` answers 503 until the first scan has finished.

Every metric has the labels `host` and `port`.

| Metric | Meaning |
|---|---|
| `tlswatch_up` | 1 if a TLS handshake succeeded, 0 otherwise |
| `tlswatch_scan_duration_seconds` | time spent probing the host |
| `tlswatch_last_scan_timestamp_seconds` | when the host was last probed |
| `tlswatch_cert_not_after_timestamp_seconds` | when the leaf certificate expires |
| `tlswatch_cert_days_remaining` | days to expiry, negative once expired |
| `tlswatch_cert_verified` | 1 if a normal client would trust the chain for this name |
| `tlswatch_grade_score` | A=4, B=3, C=2, D=1, F=0 (absent for an unreachable host) |
| `tlswatch_grade_info` | always 1; the label `grade` carries the letter |
| `tlswatch_protocol_supported` | label `protocol`; 1 accepted, 0 refused (not exported when it could not be tested) |
| `tlswatch_weak_cipher_accepted` | label `class`; 1 if a weak cipher class is accepted (not exported when untestable) |
| `tlswatch_findings` | label `severity`; number of findings |

The alert rules in [`examples/prometheus-alerts.yml`](../examples/prometheus-alerts.yml) use these names; a test checks that each metric they use exists.

Binding: the default is `127.0.0.1:9117`. There is no authentication and no TLS on the exporter, so keep it on a private network or behind a reverse proxy. In a container use `--listen 0.0.0.0:9117` and publish the port only where Prometheus can reach it.
