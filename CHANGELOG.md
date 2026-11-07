# Changelog

## 1.0.0

First release. Reads the certificate with a small DER/X.509 reader (no dependencies), asks OpenSSL whether a normal client would trust it, offers each TLS version and each class of weak cipher suite on its own, and grades every host A to F with reasons. Targets from the command line or a TOML file, STARTTLS for SMTP, IMAP and POP3, text / JSON / Prometheus output, a `serve` mode that exports metrics, a Docker image, alert rules, and tools that measure the parser, corrupt-input handling, diagnoses and speed.
