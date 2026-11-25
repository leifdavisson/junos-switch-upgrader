# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generic OPSEC regression tests ensuring no private IPs, paths, keys, or secrets leak into public files."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# RFC 1918 private IPv4 blocks constructed numerically (zero literal private IPs in source)
_RFC1918_NETWORKS = (
    ipaddress.IPv4Network((0x0A000000, 8)),
    ipaddress.IPv4Network((0xAC100000, 12)),
    ipaddress.IPv4Network((0xC0A80000, 16)),
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Local workstation home paths (character classes avoid triggering on this regex itself)
_HOME_PATH_RE = re.compile(r"(?:/[h]ome/|/[U]sers/|C:\\[U]sers\\)", re.IGNORECASE)

# MAC addresses (colon or Junos dot format); RFC 7042 documentation range 00:00:5e:00:53:xx is permitted
_COLON_MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.IGNORECASE)
_DOT_MAC_RE = re.compile(r"\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b", re.IGNORECASE)
_ALLOWED_MAC_PREFIXES = ("00005e0053", "000000000000", "ffffffffffff")

# Email addresses outside RFC 2606 documentation domains
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_ALLOWED_EMAIL_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "example.invalid",
    "example.internal",
)

# High-confidence credential / private key markers
_SECRET_MARKER_RE = re.compile(
    r"(?:-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[pousr]_[A-Za-z0-9]{36}\b)",
)


def _iter_public_files() -> list[Path]:
    targets: list[Path] = [
        REPO_ROOT / "pyproject.toml",
        REPO_ROOT / ".gitignore",
        REPO_ROOT / "README.md",
        REPO_ROOT / "setup-windows.ps1",
        REPO_ROOT / "credentials.example.json",
    ]
    manifests_dir = REPO_ROOT / "manifests"
    if manifests_dir.is_dir():
        targets.extend(sorted(manifests_dir.glob("*.yml")))
        targets.extend(sorted(manifests_dir.glob("*.yaml")))
    bundled_data = REPO_ROOT / "src" / "junos_upgrader" / "data"
    if bundled_data.is_dir():
        targets.extend(sorted(bundled_data.glob("*.yml")))
        targets.extend(sorted(bundled_data.glob("*.yaml")))
    targets.extend(sorted((REPO_ROOT / "src").rglob("*.py")))
    targets.extend(sorted((REPO_ROOT / "tests").rglob("*.py")))
    return [p for p in targets if p.is_file()]


def _load_local_denylist() -> list[str]:
    """Load optional gitignored site/operator terms from deliverables/.opsec-denylist.txt or env."""
    candidates: list[Path] = [REPO_ROOT / "deliverables" / ".opsec-denylist.txt"]
    env_path = os.environ.get("OPSEC_DENYLIST_FILE", "").strip()
    if env_path:
        candidates.append(Path(env_path))
    terms: list[str] = []
    for path in candidates:
        if not path.is_file():
            continue
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            term = raw_line.strip()
            if term and not term.startswith("#"):
                terms.append(term)
    return terms


def _is_rfc1918_ip(token: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(token)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918_NETWORKS)


def _is_disallowed_mac(token: str) -> bool:
    hex_only = re.sub(r"[:.]", "", token).lower()
    return not any(hex_only.startswith(prefix) for prefix in _ALLOWED_MAC_PREFIXES)


def test_no_proprietary_or_operator_leaks_in_public_files() -> None:
    denylist = _load_local_denylist()
    denylist_re = (
        re.compile("|".join(re.escape(t) for t in denylist), re.IGNORECASE) if denylist else None
    )

    leaks: list[str] = []
    for file_path in _iter_public_files():
        rel = file_path.relative_to(REPO_ROOT)
        text = file_path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for ip_match in _IPV4_RE.finditer(line):
                ip_str = ip_match.group(0)
                if _is_rfc1918_ip(ip_str):
                    leaks.append(f"{rel}:{lineno}: RFC 1918 private IP {ip_str!r}")

            home_m = _HOME_PATH_RE.search(line)
            if home_m:
                leaks.append(f"{rel}:{lineno}: local home path {home_m.group(0)!r}")

            for mac_re in (_COLON_MAC_RE, _DOT_MAC_RE):
                for mac_m in mac_re.finditer(line):
                    mac_str = mac_m.group(0)
                    if _is_disallowed_mac(mac_str):
                        leaks.append(f"{rel}:{lineno}: non-RFC-7042 MAC {mac_str!r}")

            for email_m in _EMAIL_RE.finditer(line):
                domain = email_m.group(1).lower()
                if domain not in _ALLOWED_EMAIL_DOMAINS:
                    leaks.append(f"{rel}:{lineno}: non-documentation email {email_m.group(0)!r}")

            sec_m = _SECRET_MARKER_RE.search(line)
            if sec_m:
                leaks.append(f"{rel}:{lineno}: secret/key material {sec_m.group(0)!r}")

            if denylist_re is not None:
                deny_m = denylist_re.search(line)
                if deny_m:
                    leaks.append(f"{rel}:{lineno}: local denylist match {deny_m.group(0)!r}")

    assert not leaks, "OPSEC leak(s) detected:\n" + "\n".join(leaks)


def test_deliverables_and_credentials_are_gitignored() -> None:
    gi = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    required_patterns = (
        "deliverables/*",
        "!deliverables/.gitkeep",
        "firmware/*",
        "!firmware/.gitkeep",
        "credentials.json",
        "credentials.*.json",
        "!credentials.example.json",
        ".env",
        "*.pem",
        "*.key",
        "id_rsa*",
        "id_ed25519*",
        "manifests/*.json",
        "manifests/bleeding-edge*.yml",
        "recovery.txt",
        "*.tgz",
    )
    missing = [pat for pat in required_patterns if pat not in gi.splitlines()]
    assert not missing, f"Missing required .gitignore entries: {missing}"
    assert (REPO_ROOT / "deliverables" / ".gitkeep").exists()
    assert (REPO_ROOT / "firmware" / ".gitkeep").exists()
