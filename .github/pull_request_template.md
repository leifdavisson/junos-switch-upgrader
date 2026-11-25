## Summary

<!-- Briefly describe what this PR fixes or adds. -->

## Related Issue

<!-- Fixes # -->

## Checklist

- [ ] `ruff check .` passes with zero errors
- [ ] `ruff format --check .` passes with zero formatting diffs
- [ ] `pytest -v` passes (with mocked SSH/HTTP/device calls; no real network calls)
- [ ] If `manifests/approved-releases.yml` changed, `src/junos_upgrader/data/approved-releases.yml` is an identical copy (`cmp -s manifests/approved-releases.yml src/junos_upgrader/data/approved-releases.yml`)
- [ ] **OPSEC check:** No real hostnames, RFC 1918 IPs, serial numbers, MAC addresses, `credentials.json`, or `deliverables/` data included (use `192.0.2.x` / `198.51.100.x` / `203.0.113.x` and `00:00:5e:00:53:xx` in tests/examples)
- [ ] Updated `README.md` / CLI help if user-facing flags or behavior changed
