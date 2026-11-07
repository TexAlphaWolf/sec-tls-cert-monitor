# Limitations

What tlswatch does not do, or does with a caveat. A monitor that hides its blind spots is worse than none.

## What this machine's OpenSSL can offer

The protocol and cipher probes work by making the local OpenSSL offer one thing at a time. If the local OpenSSL does not contain it, the probe cannot run and the report says **"not tested from this machine"** (`probe-gaps`, status `untestable`); it never reports it as "not accepted".

- On the machines this was developed and tested on (OpenSSL 3.0.13 and 3.5.7, Debian-based) **RC4 and 3DES cannot be offered**. A server that accepts only those is not examined for them, and `cipher-rc4` / `cipher-3des` can never appear there. `tlswatch capabilities` lists what yours can do.
- The `Dockerfile` uses Debian's OpenSSL, so it has the same gaps. Run `tlswatch` where an OpenSSL built with `enable-weak-ssl-ciphers` is available if you need those two probes.
- Export-grade suites, weak Diffie-Hellman parameters and old SSL versions (SSLv2/v3) are not probed at all.

## What is not checked

- **Revocation** (CRL, OCSP, OCSP stapling) and **Certificate Transparency** are not checked. `revoked.badssl.com` is reported as healthy by design.
- **Key usage, extended key usage, name constraints and policy** are not inspected beyond what OpenSSL enforces when it verifies the chain.
- **Hostname verification and chain building are OpenSSL's.** The tlswatch parser reads fields; it does not validate signatures.
- **TLS 1.3 cipher suites** are not enumerated; all are considered acceptable.
- **HSTS, HTTP headers and application behaviour** are out of scope.
- **Client-certificate (mTLS) servers** that abort the handshake without one are reported as a failure to connect.

## Behaviour to know about

- **The intermediate certificates of the chain are read only on Python 3.13+**, where `ssl` exposes them. On 3.11 and 3.12 the leaf is checked and the chain is judged only through OpenSSL's verdict (`chain_complete` is false in the JSON).
- **The certificate is read by a client that accepts anything** (at security level 0), so that a bad certificate can be reported rather than refused. A 1024-bit RSA certificate is therefore inspected, and the report also says that a normal client rejects it.
- **"Rejected" for a protocol includes a dropped connection.** Some servers reset the connection instead of sending an alert when offered TLS 1.0.
- **Virtual hosts:** the name sent as SNI and checked is the host, or `--server-name` / `server_name` when you connect by address. A server that serves different certificates by name needs one entry per name.
- **STARTTLS** works for SMTP, IMAP and POP3 only.
- **It is an active scanner**: about 11 connections per host. Use it on your own systems.
- **Private CAs:** `--ca-file` adds to the system trust store, it does not replace it.
- **Time:** expiry is computed from the clock of the machine running `tlswatch`.
