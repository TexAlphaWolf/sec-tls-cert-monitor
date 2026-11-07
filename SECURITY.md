# Security policy

tlswatch connects to servers you name and parses what they send, so a malicious server is part of its threat model. If you find a way to make it crash, hang, run code, or report a bad certificate as healthy by crafting a server response (a certificate, a STARTTLS reply), please use GitHub's **private vulnerability reporting** (Security tab, "Report a vulnerability") rather than a public issue. You will get an answer within a few days.

A check that is missing (revocation, for instance) is a feature request, not a vulnerability. [docs/limitations.md](docs/limitations.md) lists what is known.

Supported: the latest release.

What the code does about hostile servers: the DER reader refuses indefinite and non-minimal lengths and anything longer than the data; STARTTLS replies are limited to 4 KiB per line and 64 lines; every connection has a timeout; the exporter does not accept input and binds to localhost by default.
