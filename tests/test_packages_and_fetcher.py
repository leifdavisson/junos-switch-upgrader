# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for packages.py and firmware_fetcher.py security, integrity, and ingestion fixes."""

from __future__ import annotations

import io
import ipaddress
import json
import socket
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from junos_upgrader import __version__
from junos_upgrader.firmware_fetcher import (
    USER_AGENT,
    ShoppingListItem,
    _SafeHTTPSRedirectHandler,
    build_shopping_list,
    generate_bleeding_edge_manifest,
    interactive_portal_session,
    pull_signed_urls,
    scan_and_ingest_directory,
)
from junos_upgrader.models import HopSpec, SwitchRecord, SwitchState
from junos_upgrader.packages import (
    extract_switch_arch,
    infer_arch_from_filename,
    inspect_local_tgz,
    validate_package_match,
)
from junos_upgrader.planner import (
    compute_remaining_hops,
    load_release_catalog,
    match_platform_policy,
)

RELEASES_YML = Path(__file__).resolve().parents[1] / "manifests" / "approved-releases.yml"


def _make_tgz(dest: Path, comment: str = "arm-32", extra_files: int = 0) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, "w:gz") as tf:
        data = comment.encode("utf-8")
        ti = tarfile.TarInfo("+COMMENT")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
        for i in range(extra_files):
            payload = f"entry-{i}".encode()
            eti = tarfile.TarInfo(f"meta/file_{i}.txt")
            eti.size = len(payload)
            tf.addfile(eti, io.BytesIO(payload))
    return dest


def _make_sw(
    hostname: str,
    model: str = "ex3400-48p",
    version: str = "23.2R2-S3",
    arch: str = "arm-32",
    ip: str = "192.0.2.10",
) -> SwitchRecord:
    return SwitchRecord(
        site="SITE",
        hostname=hostname,
        management_ip=ip,
        model=model,
        serial_number=f"SN_{hostname}",
        current_version=version,
        role="Access",
        management_method="SSH",
        kernel_arch=arch,
        state=SwitchState.READY,
    )


def test_extract_switch_arch_platform_precedence_and_hostname_isolation() -> None:
    # QFX5120 / QFX5200 / EX4650 / EX4600 with VMHost and x86-64 in show version must NOT be misclassified
    qfx5120_txt = (
        "Hostname: core-qfx-01\nModel: qfx5120-48y-8c\nJunos: 22.4R3-S7\n"
        "JUNOS OS VMHost Software [22.4R3-S7]\nJUNOS Base OS boot [x86-64]\n"
    )
    assert extract_switch_arch(qfx5120_txt) == "qfx-5e"

    ex4650_txt = (
        "Hostname: core-4650-01\nModel: ex4650-48y\nJunos: 22.4R3-S7\n"
        "JUNOS Base OS boot [x86-64]\nJUNOS OS VMHost Software\n"
    )
    assert extract_switch_arch(ex4650_txt) == "ex-4650"

    ex4600_txt = (
        "Hostname: core-4600-01\nModel: ex4600-40f\nJunos: 20.4R3-S10\nJUNOS Host OS [amd64]\n"
    )
    assert extract_switch_arch(ex4600_txt) == "qfx-5"

    # Hostname containing another platform name or pkg tag must NOT hijack classification
    ex3400_tricky = "Hostname: ex4300-48mp-replacement-01\nModel: ex3400-48p\nJunos: 23.2R2-S3\n"
    assert extract_switch_arch(ex3400_tricky) == "arm-32"
    ex3400_qfx_host = "Hostname: qfx-5e-lab\nModel: ex3400-48p\nJunos: 23.2R2-S3\n"
    assert extract_switch_arch(ex3400_qfx_host) == "arm-32"
    ex3400_evo_host = "Hostname: junos-evo-gw\nModel: ex3400-48p\nJunos: 23.2R2-S3\n"
    assert extract_switch_arch(ex3400_evo_host) == "arm-32"

    # JSON output with Junos OS Evolved must always win
    evo_json = json.dumps(
        {
            "software-information": [
                {
                    "product-model": [{"data": "qfx5200-32c"}],
                    "package-information": [
                        {
                            "package-name": [{"data": "junos-evo-install-qfx-x86-64"}],
                            "comment": [{"data": "Junos OS Evolved"}],
                        }
                    ],
                }
            ]
        }
    )
    assert extract_switch_arch(evo_json) == "junos-evo"

    # Standard platforms
    assert extract_switch_arch("Model: ex4300-48mp\nJUNOS VMHost") == "x86-64-vmhost"
    assert extract_switch_arch("Model: ex4300-48p\nJUNOS Base OS") == "powerpc"
    assert extract_switch_arch("Model: ex4400-48mp\nJUNOS x86-64") == "x86-64"
    assert extract_switch_arch("Model: ex4100-48mp\nJUNOS arm-64") == "arm-64"


def test_inspect_local_tgz_catches_truncation_crc_corruption_and_zipslip(tmp_path: Path) -> None:
    # 1. Missing file returns structured invalid metadata without raising OSError
    missing = inspect_local_tgz(tmp_path / "does-not-exist.tgz")
    assert not missing.valid_tgz
    assert missing.errors

    # 2. Non-gzip HTML file rejected before hashing
    html_pkg = tmp_path / "junos-arm-32-23.4R2-S8.tgz"
    html_pkg.write_text("<html>Sign In</html>", encoding="utf-8")
    html_meta = inspect_local_tgz(html_pkg)
    assert not html_meta.valid_tgz
    assert html_meta.md5 == ""

    # 3. 50%-truncated archive with >40 entries before payload must FAIL (no early break!)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("+COMMENT")
        ti.size = 6
        tf.addfile(ti, io.BytesIO(b"arm-32"))
        for i in range(45):
            eti = tarfile.TarInfo(f"meta/f{i}.txt")
            eti.size = 10
            tf.addfile(eti, io.BytesIO(b"0123456789"))
        payload = bytes(range(256)) * 4096
        big = tarfile.TarInfo("junos-rootfs.img")
        big.size = len(payload)
        tf.addfile(big, io.BytesIO(payload))
    raw = buf.getvalue()
    trunc_pkg = tmp_path / "junos-arm-32-23.4R2-S8-trunc.tgz"
    trunc_pkg.write_bytes(raw[: len(raw) // 2])
    assert not inspect_local_tgz(trunc_pkg).valid_tgz

    # 4. 2-entry archive with flipped mid/tail byte (CRC32 mismatch) must FAIL
    buf2 = io.BytesIO()
    with tarfile.open(fileobj=buf2, mode="w:gz") as tf:
        ti = tarfile.TarInfo("+COMMENT")
        ti.size = 6
        tf.addfile(ti, io.BytesIO(b"arm-32"))
        data = b"A" * 50000 + b"B" * 50000
        big = tarfile.TarInfo("payload.bin")
        big.size = len(data)
        tf.addfile(big, io.BytesIO(data))
    corrupt_tail = bytearray(buf2.getvalue())
    corrupt_tail[-4] ^= 0xFF
    bad_crc = tmp_path / "junos-arm-32-23.4R2-S8-badcrc.tgz"
    bad_crc.write_bytes(bytes(corrupt_tail))
    assert not inspect_local_tgz(bad_crc).valid_tgz

    # 5. ZipSlip traversal member (`../evil`) and absolute member (`/etc/passwd`) rejected
    for bad_member in ("../escape.sh", "/etc/shadow"):
        zpath = tmp_path / f"junos-arm-32-23.4R2-S8-{abs(hash(bad_member))}.tgz"
        with tarfile.open(zpath, "w:gz") as tf:
            ti = tarfile.TarInfo(bad_member)
            ti.size = 4
            tf.addfile(ti, io.BytesIO(b"evil"))
        zmeta = inspect_local_tgz(zpath)
        assert not zmeta.valid_tgz
        assert any("Unsafe tar member" in e for e in zmeta.errors)

    # 6. Special FIFO/device member rejected
    fifo_path = tmp_path / "junos-arm-32-23.4R2-S8-fifo.tgz"
    with tarfile.open(fifo_path, "w:gz") as tf:
        ti = tarfile.TarInfo("bad_fifo")
        ti.type = tarfile.FIFOTYPE
        tf.addfile(ti)
    fmeta = inspect_local_tgz(fifo_path)
    assert not fmeta.valid_tgz
    assert any("device/FIFO" in e for e in fmeta.errors)


def test_validate_package_match_prefix_checksums_versions_and_unknowns(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol4600 = match_platform_policy("ex4600-40f", policies)
    pol3400 = match_platform_policy("ex3400-48p", policies)
    assert pol4600 and pol3400

    # 1. Prefix collision: qfx-5e must NOT pass ex4600 (jinstall-host-qfx-5)
    sw4600 = _make_sw("CORE_4600", "ex4600-40f", "20.4R3-S10", arch="qfx-5")
    hop_5e = HopSpec(
        "23.4", "23.4R2-S8", "jinstall-host-qfx-5e-23.4R2-S8-signed.tgz", "md5", "a" * 32
    )
    res_5e = validate_package_match(sw4600, pol4600, hop_5e, local_file=None)
    assert not res_5e[0].passed and res_5e[0].severity == "fail"

    # 1b. EX4600 native package prefix (jinstall-host-ex-4600-*) also matches ex4600* (qfx-5)
    assert infer_arch_from_filename("jinstall-host-ex-4600-21.4R3-S12.5-signed.tgz") == "qfx-5"
    res_4600_native = validate_package_match(
        sw4600,
        pol4600,
        HopSpec(
            "21.4R3-S12",
            "21.4R3-S12.5",
            "jinstall-host-ex-4600-21.4R3-S12.5-signed.tgz",
            "md5",
            "a" * 32,
        ),
        local_file=None,
    )
    assert all(r.passed for r in res_4600_native if r.hard_stop)

    # 2. install-media .tgz must fail with severity="fail" (not "info")
    sw3400 = _make_sw("IDF_3400", "ex3400-48p", "23.2R2-S3", arch="arm-32")
    hop_usb = HopSpec(
        "23.4", "23.4R2-S8", "junos-arm-32-install-media-23.4R2-S8.tgz", "md5", "a" * 32
    )
    res_usb = validate_package_match(sw3400, pol3400, hop_usb, local_file=None)
    assert not res_usb[0].passed and res_usb[0].severity == "fail"

    # 3. Placeholder / empty checksum hard-stops by default, warns with UNVERIFIED when explicitly allowed
    pkg = _make_tgz(tmp_path / "junos-arm-32-23.4R2-S8.tgz", comment="arm-32")
    meta = inspect_local_tgz(pkg)
    assert (
        meta.valid_tgz and len(meta.md5) == 32 and len(meta.sha1) == 40 and len(meta.sha256) == 64
    )

    for placeholder_chk in ("REPLACE_WITH_JUNIPER_MD5", ""):
        hop_ph = HopSpec("23.4", "23.4R2-S8", pkg.name, "md5", placeholder_chk)
        denied = validate_package_match(sw3400, pol3400, hop_ph, local_file=pkg)
        integ = next(c for c in denied if c.name == "local_tgz_integrity")
        assert not integ.passed and integ.hard_stop and integ.severity == "fail"

        allowed = validate_package_match(
            sw3400, pol3400, hop_ph, local_file=pkg, allow_unverified_checksums=True
        )
        integ_ok = next(c for c in allowed if c.name == "local_tgz_integrity")
        assert integ_ok.passed and not integ_ok.hard_stop and integ_ok.severity == "warn"
        assert "UNVERIFIED: placeholder checksum skipped" in integ_ok.message
        assert "Verified local" not in integ_ok.message

    # 4. Real md5, sha1, sha256, and sha-256 checksums pass; bad digest or unsupported algo fails
    for algo, digest in (
        ("md5", meta.md5),
        ("sha1", meta.sha1),
        ("sha256", meta.sha256),
        ("sha-256", meta.sha256),
    ):
        hop_ok = HopSpec("23.4", "23.4R2-S8", pkg.name, algo, digest)
        checks_ok = validate_package_match(sw3400, pol3400, hop_ok, local_file=pkg)
        integ = next(c for c in checks_ok if c.name == "local_tgz_integrity")
        assert integ.passed and integ.severity == "info"

    hop_bad_algo = HopSpec("23.4", "23.4R2-S8", pkg.name, "crc32", "12345678")
    checks_algo = validate_package_match(sw3400, pol3400, hop_bad_algo, local_file=pkg)
    assert any(
        c.name == "local_tgz_integrity"
        and not c.passed
        and "Unsupported checksum_type" in c.message
        for c in checks_algo
    )

    # 5. Version mismatch between filename and hop.target_version fails hard-stop
    wrong_ver_pkg = _make_tgz(tmp_path / "junos-arm-32-22.2R3-S5.tgz", comment="arm-32")
    wrong_meta = inspect_local_tgz(wrong_ver_pkg)
    hop_wrong = HopSpec("23.4", "23.4R2-S8", wrong_ver_pkg.name, "md5", wrong_meta.md5)
    checks_ver = validate_package_match(sw3400, pol3400, hop_wrong, local_file=wrong_ver_pkg)
    assert any(
        c.name == "local_tgz_integrity" and not c.passed and "version_ok=False" in c.message
        for c in checks_ver
    )

    # 6. Unknown live_arch emits warning (not info)
    sw_unk = _make_sw("IDF_UNK", "ex3400-48p", "23.2R2-S3", arch="")
    checks_unk = validate_package_match(
        sw_unk, pol3400, HopSpec("23.4", "23.4R2-S8", pkg.name, "md5", meta.md5), local_file=pkg
    )
    arch_chk = next(c for c in checks_unk if c.name == "switch_arch_match")
    assert arch_chk.passed and arch_chk.severity == "warn"


def test_pull_signed_urls_ssrf_https_redirects_html_size_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert USER_AGENT == f"junos-switch-upgrader/{__version__}"
    rel = tmp_path / "releases.yml"
    rel.write_text(RELEASES_YML.read_text(encoding="utf-8"), encoding="utf-8")
    _, policies, _ = load_release_catalog(rel)
    fw_dir = tmp_path / "firmware"

    # 1. Local file://, plaintext http://, ftp://, and traversal URLs are all rejected
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET", encoding="utf-8")

    # Mock DNS resolution to test public, mapped-IPv4, loopback, private, CGNAT, and link-local SSRF
    private_ip = str(ipaddress.IPv4Address(0x0A000001))
    cgnat_ip = str(ipaddress.IPv4Address(0x64400001))  # 100.64.0.1 (RFC 6598)
    cloud_meta_cgnat = str(ipaddress.IPv4Address(0x646464C8))  # 100.100.100.200

    def fake_getaddrinfo(host: str, port: int, *_args: Any, **_kwargs: Any) -> list[Any]:
        if host == "cdn.example.net":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        if host == "mapped-public.example.net":
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:93.184.216.34", port))]
        if host == "mapped-loopback.example.net":
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", port))]
        if host == "loopback.example.net":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        if host == "private.example.net":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (private_ip, port))]
        if host == "cgnat.example.net":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (cgnat_ip, port))]
        if host == "cgnat-meta.example.net":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (cloud_meta_cgnat, port))]
        if host == "metadata.example.net":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr("junos_upgrader.firmware_fetcher.socket.getaddrinfo", fake_getaddrinfo)

    # Build a valid gzipped tar stream in memory for the good URL
    good_tgz = _make_tgz(tmp_path / "src.tgz", comment="arm-32")
    good_bytes = good_tgz.read_bytes()

    class _FakeResp:
        def __init__(
            self, body: bytes, ctype: str = "application/octet-stream", status: int = 200
        ) -> None:
            self._bio = io.BytesIO(body)
            self.headers = {"Content-Type": ctype}
            self.status = status

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

        def __enter__(self) -> _FakeResp:  # noqa: PYI034
            return self

        def __exit__(self, *_: object) -> None:
            return None

    class _FakeOpener:
        def open(self, req: urllib.request.Request, timeout: int = 120) -> _FakeResp:
            assert req.get_header("User-agent") == USER_AGENT
            if "html-sso" in req.full_url:
                return _FakeResp(b"<html><body>SSO Login</body></html>", ctype="text/html")
            if "oversize" in req.full_url:
                return _FakeResp(good_bytes + b"\x00" * 4096)
            if "not-found" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
            return _FakeResp(good_bytes)

    monkeypatch.setattr(
        "junos_upgrader.firmware_fetcher.urllib.request.build_opener",
        lambda *_handlers: _FakeOpener(),
    )

    urls = [
        secret.as_uri(),  # file:// rejected
        "http://cdn.example.net/junos-arm-32-23.4R2-S8.tgz",  # plaintext HTTP rejected
        "https://loopback.example.net/junos-arm-32-23.4R2-S8.tgz",  # loopback SSRF rejected
        "https://mapped-loopback.example.net/junos-arm-32-23.4R2-S8.tgz",  # ::ffff:127.0.0.1 rejected
        "https://private.example.net/junos-arm-32-23.4R2-S8.tgz",  # private IP SSRF rejected
        "https://cgnat.example.net/junos-arm-32-23.4R2-S8.tgz",  # RFC 6598 CGNAT rejected
        "https://cgnat-meta.example.net/junos-arm-32-23.4R2-S8.tgz",  # cloud metadata CGNAT rejected
        "https://metadata.example.net/junos-arm-32-23.4R2-S8.tgz",  # link-local SSRF rejected
        "https://cdn.example.net/foo/..%5c..%5cevil.tgz",  # backslash traversal rejected
        "https://cdn.example.net/junos-arm-32-23.4R2-S8;reboot.tgz",  # shell metachar rejected
        "https://cdn.example.net/html-sso-23.4R2-S8.tgz",  # HTML response rejected
        "https://cdn.example.net/oversize-23.4R2-S8.tgz",  # exceeds max_bytes rejected
        "https://cdn.example.net/not-found-23.4R2-S8.tgz",  # 404 isolated
        "https://cdn.example.net/junos-arm-32-23.4R2-S8.tgz?token=abc",  # valid IPv4!
        "https://mapped-public.example.net/junos-arm-32-23.2R2-S3.tgz?token=xyz",  # valid ::ffff:public!
    ]
    res = pull_signed_urls(urls, fw_dir, rel, policies, max_bytes=len(good_bytes) + 128)
    rejected = [r for r in res if r["status"] == "rejected"]
    ingested = [r for r in res if r["status"] == "ingested"]
    assert len(rejected) == 13
    assert len(ingested) == 2
    assert Path(ingested[0]["file"]).is_file()
    # Temp staging directory cleaned up — zero leftover files in _incoming!
    assert list((fw_dir / "_incoming").rglob("*")) == []

    # 2. Custom redirect handler blocks HTTPS->HTTP downgrade and SSRF redirect
    handler = _SafeHTTPSRedirectHandler()
    req = urllib.request.Request("https://cdn.example.net/junos-arm-32-23.4R2-S8.tgz")
    with pytest.raises(ValueError, match="non-HTTPS"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://cdn.example.net/pkg.tgz")
    with pytest.raises(ValueError, match="SSRF protection"):
        handler.redirect_request(
            req, None, 302, "Found", {}, "https://loopback.example.net/pkg.tgz"
        )


def test_scan_and_ingest_unknown_arch_install_media_and_no_downgrade(tmp_path: Path) -> None:
    rel = tmp_path / "releases.yml"
    rel.write_text(RELEASES_YML.read_text(encoding="utf-8"), encoding="utf-8")
    _, policies, _ = load_release_catalog(rel)
    scan_dir = tmp_path / "scan"
    fw_dir = tmp_path / "fw"
    scan_dir.mkdir()

    # 1. Unknown arch with matching train must NOT contaminate 11 platforms
    _make_tgz(scan_dir / "random-backup-23.4R2-S8.tgz", comment="unrelated archive")
    # 2. Install-media .tgz must be rejected
    _make_tgz(scan_dir / "junos-arm-32-install-media-net-23.4R2-S8.tgz", comment="arm-32")
    # 3. S10 and S8 scanned together: version-sorted so S10 wins (not lexicographically overwritten by S8!)
    _make_tgz(scan_dir / "junos-arm-32-23.4R2-S10.tgz", comment="arm-32")
    _make_tgz(scan_dir / "junos-arm-32-23.4R2-S8.tgz", comment="arm-32")

    res = scan_and_ingest_directory(scan_dir, fw_dir, rel, policies, update_manifest=True)
    by_name = {Path(r["file"]).name: r for r in res}
    assert by_name["random-backup-23.4R2-S8.tgz"]["status"] == "unmatched"
    assert by_name["junos-arm-32-install-media-net-23.4R2-S8.tgz"]["status"] == "rejected"

    _, updated, _ = load_release_catalog(rel)
    pol3400 = match_platform_policy("ex3400-48p", updated)
    assert pol3400 is not None
    assert pol3400.final_target == "23.4R2-S10"
    assert pol3400.hops[-1].train == "23.4R2-S10"
    assert pol3400.hops[-1].package_filename == "junos-arm-32-23.4R2-S10.tgz"

    # Re-scanning an older release in the same train (23.4R2.13) must NOT downgrade manifest from S10!
    older_dir = tmp_path / "older"
    older_dir.mkdir()
    _make_tgz(older_dir / "junos-arm-32-23.4R2.13.tgz", comment="arm-32")
    scan_and_ingest_directory(older_dir, fw_dir, rel, updated, update_manifest=True)
    _, after_old, _ = load_release_catalog(rel)
    pol3400_after = match_platform_policy("ex3400-48p", after_old)
    assert pol3400_after is not None
    assert pol3400_after.final_target == "23.4R2-S10"


def test_generate_bleeding_edge_preserves_install_opts_dedupes_train_and_skips_empty(
    tmp_path: Path,
) -> None:
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    out_empty = tmp_path / "should-not-exist.yml"
    summary_empty = generate_bleeding_edge_manifest(
        [empty_dir], RELEASES_YML, tmp_path / "fw0", out_empty
    )
    assert summary_empty["added_hops"] == []
    assert not out_empty.exists()

    scan_dir = tmp_path / "dl"
    fw_dir = tmp_path / "fw"
    out_yml = tmp_path / "bleed.yml"
    scan_dir.mkdir()

    # VMHost QFX5120 jump >4 quarters (23.4 -> 25.4 = 8q -> gap warning) + preserves force-host!
    _make_tgz(scan_dir / "jinstall-host-qfx-5e-25.4R1.10-signed.tgz", comment="qfx-5e")
    # Same-train 23.4R2-S9 replaces 23.4R2-S8 + two 24.4 releases dedupe to 24.4R2.23
    _make_tgz(scan_dir / "junos-arm-32-23.4R2-S9.tgz", comment="arm-32")
    _make_tgz(scan_dir / "junos-arm-32-24.4R1.9.tgz", comment="arm-32")
    _make_tgz(scan_dir / "junos-arm-32-24.4R2.23.tgz", comment="arm-32")
    # Install-media ignored
    _make_tgz(scan_dir / "junos-arm-32-install-media-25.2R1.1.tgz", comment="arm-32")

    summary = generate_bleeding_edge_manifest([scan_dir], RELEASES_YML, fw_dir, out_yml)
    assert out_yml.exists()
    assert any("jumps ~8 quarterly releases" in w for w in summary["gap_warnings"])

    _, b_policies, _ = load_release_catalog(out_yml)
    pqfx = match_platform_policy("qfx5120-48y", b_policies)
    assert pqfx is not None
    assert pqfx.final_target == "25.4R1.10"
    assert "force-host" in pqfx.hops[-1].install_options
    assert "no-validate" in pqfx.hops[-1].install_options

    p3400 = match_platform_policy("ex3400-48p", b_policies)
    assert p3400 is not None
    # From 23.2R2-S3: single hop in 23.4 (23.4R2-S9, replaced S8) + single hop in 24.4 (24.4R2.23)
    assert [h.target_version for h in compute_remaining_hops("23.2R2-S3", p3400)] == [
        "23.4R2-S9",
        "24.4R2.23",
    ]


def test_build_shopping_list_deduplicates_by_arch_and_skips_unparseable_versions(
    tmp_path: Path,
) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    switches = [
        _make_sw("SW_2300_MP", "ex2300-24mp", "23.2R2-S3"),
        _make_sw("SW_2300_C", "ex2300-c-12p", "23.2R2-S3"),
        _make_sw("SW_3400", "ex3400-48p", "23.2R2-S3"),
        _make_sw("SW_UNKNOWN", "ex3400-48p", "unknown"),
    ]
    items = build_shopping_list(switches, policies, tmp_path / "fw")
    assert len(items) == 1
    assert items[0].package_filename == "junos-arm-32-23.4R2-S8.tgz"
    assert items[0].switch_count == 3

    # portal_url properly URL-encodes portal_slug
    item = ShoppingListItem(
        family_dir="ex3400",
        portal_slug="EX 3400&x=1",
        train="23.4R2-S8",
        target_version="23.4R2-S8",
        package_filename="junos-arm-32-23.4R2-S8.tgz",
        expected_arch="arm-32",
        checksum_type="md5",
        expected_checksum="a" * 32,
        switch_count=1,
        present_locally=False,
    )
    assert "?p=EX%203400%26x%3D1" in item.portal_url


def test_interactive_portal_session_stability_and_missing_watch_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rel = tmp_path / "releases.yml"
    rel.write_text(RELEASES_YML.read_text(encoding="utf-8"), encoding="utf-8")
    _, policies, _ = load_release_catalog(rel)
    fw_dir = tmp_path / "fw"

    item = ShoppingListItem(
        family_dir="ex3400",
        portal_slug="EX3400",
        train="23.4R2-S8",
        target_version="23.4R2-S8",
        package_filename="junos-arm-32-23.4R2-S8.tgz",
        expected_arch="arm-32",
        checksum_type="md5",
        expected_checksum="REPLACE_WITH_JUNIPER_MD5",
        switch_count=1,
        present_locally=False,
    )

    # Non-existent watch_dir fails immediately instead of hanging until timeout
    with pytest.raises(FileNotFoundError, match="Watch directory does not exist"):
        interactive_portal_session(
            [item], fw_dir, rel, policies, watch_dir=tmp_path / "missing_dir", timeout_seconds=5
        )

    watch_dir = tmp_path / "downloads"
    watch_dir.mkdir()
    _make_tgz(watch_dir / "junos-arm-32-23.4R2-S8.tgz", comment="arm-32")
    # Also place an in-progress .crdownload sibling that should NOT be ingested
    _make_tgz(watch_dir / "junos-arm-32-22.2R3-S5.tgz", comment="arm-32")
    (watch_dir / "junos-arm-32-22.2R3-S5.tgz.crdownload").write_bytes(b"partial")

    opened: list[str] = []
    monkeypatch.setattr("junos_upgrader.firmware_fetcher._open_portal_browser", opened.append)

    ingested = interactive_portal_session(
        [item],
        fw_dir,
        rel,
        policies,
        watch_dir=watch_dir,
        timeout_seconds=10,
        poll_interval=0.0,
    )
    assert len(opened) == 1
    assert len(ingested) == 1
    assert ingested[0]["version"] == "23.4R2-S8"


def test_scan_and_ingest_skips_nested_firmware_dir(tmp_path: Path) -> None:
    rel = tmp_path / "approved-releases.yml"
    rel.write_text(RELEASES_YML.read_text(encoding="utf-8"), encoding="utf-8")
    _, policies, _ = load_release_catalog(rel)

    downloads = tmp_path / "Downloads"
    fw_dir = downloads / "repo" / "firmware"
    existing_fw = fw_dir / "juniper" / "ex3400" / "23.4R2-S8" / "junos-arm-32-23.4R2-S8.tgz"
    _make_tgz(existing_fw, comment="arm-32")

    # Scanning Downloads MUST skip files already inside nested fw_dir
    results_parent = scan_and_ingest_directory(
        downloads, fw_dir, rel, policies, update_manifest=False
    )
    assert results_parent == []

    # Scanning fw_dir directly still inspects it
    results_direct = scan_and_ingest_directory(
        fw_dir, fw_dir, rel, policies, update_manifest=False
    )
    assert len(results_direct) == 1
    assert results_direct[0]["status"] == "ingested"
