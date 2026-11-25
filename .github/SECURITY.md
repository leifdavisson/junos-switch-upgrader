# Security Policy

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.
Instead, report them privately via **GitHub Security Advisories** (**Security -> Advisories -> Report a vulnerability**).

Include:
- Affected module(s) and version
- Reproduction steps or proof of concept (using redacted/RFC 5737 test data)
- Potential impact

## Operational Security (OPSEC) Guidelines

`junos-switch-upgrader` interacts with network infrastructure and stages firmware over HTTP/SCP:

1. **Credentials**: Keep `credentials.json` out of version control (`.gitignore` excludes it and `tests/test_opsec_hygiene.py` enforces public-file hygiene). Prefer `JUNOS_PASSWORD`, `--password-stdin`, or SSH keys over passing `--password` on the command line.
2. **HTTP Staging & Topology UI**:
   - `topology --serve` binds to `127.0.0.1` by default; avoid `--allow-remote-ui` on untrusted networks.
   - `stage` and `upgrade` protect firmware downloads with a per-session cryptographic token (`/firmware/<token>/...`). Use `--restrict-firmware-clients` when switches fetch directly without NAT.
3. **Checksums**: Keep `--allow-unverified-checksums` disabled in production; populate real SHA-256/MD5 checksums in your release manifest.
4. **Firmware Downloads**: `firmware pull` enforces `https://` with TLS verification and blocks non-global/private/loopback/CGNAT redirect targets.
