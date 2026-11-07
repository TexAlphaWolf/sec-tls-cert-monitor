# Limitations

What tlswatch does not do, or does with a caveat. A monitor that hides its blind spots is worse than none.

## What this machine's OpenSSL can offer

The protocol and cipher probes work by making the local OpenSSL offer one thing at a time. If the local OpenSSL does not contain it, the probe cannot run and the report says **"not tested from this machine"** (`probe-gaps`, status `untestable`); it never reports it as "not accepted".

- On the machines this was developed and tested on (OpenSSL 3.0.13 and 3.5.7, Debian-based) **RC4 and 3DES cannot be offered**. A server that accepts only those is not examined for them, and `cipher-rc4` / `cipher-3des` can never appear there. `tlswatch capabilities` lists what yours can do.
- The `Dockerfile` uses Debian's OpenSSL, so it has the same gaps. Run `tlswatch` where an OpenSSL built with `enable-weak-ssl-ciphers` is available if you need those two probes.
- **A server that offers only RC4 or only 3DES cannot be examined from such a machine at all**: no handshake is possible, so it is reported as unreachable, with a note that this OpenSSL lacks those suites (seen with `rc4.badssl.com` and `3des.badssl.com`). A server that offers only NULL-encryption suites can be examined and is graded F.
- Export-grade suites, weak Diffie-Hellman parameters and old SSL versions (SSLv2/v3) are not probed at all.

## Which roots are trusted

Trust is whatever the Python running tlswatch trusts. On Linux that is the system bundle (`ca-certificates`); on Windows it is the Windows certificate store, so two machines can disagree about the same site.

One observed case, with the cause **not proven**: on a Windows PC (Python 3.14, OpenSSL 3.5.9) the first run of `tlswatch check example.org` graded it F with `untrusted-issuer` ("unable to get local issuer certificate"). Minutes later, with no change to tlswatch, a plain `ssl.create_default_context()` handshake and tlswatch both verified it (grade C, for TLS 1.0/1.1 only). It is consistent with Windows adding a root to its store on demand, but I could not check what the store held at the time. Treat an `untrusted-issuer` on Windows for a site a browser accepts as suspect, and run again with `--ca-file` and a CA bundle (for example Mozilla's `cacert.pem`, or the one in the `certifi` package) to separate a real problem from a local trust gap.

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
