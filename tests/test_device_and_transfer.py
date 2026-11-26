# SPDX-License-Identifier: AGPL-3.0-or-later
"""Comprehensive mocked unit & integration tests for checks, transfer, junos_client, drivers, and orchestrator."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import random
import tarfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from conftest import TEST_ORIGIN, FakeJunosTransport, create_valid_tgz

from junos_upgrader.checks import (
    _extract_lacp_up_members,
    _extract_lldp_pairs,
    _extract_mac_count,
    auto_cleanup_storage,
    check_config_landmines,
    evaluate_hardware_and_fs_triage,
    parse_junos_storage,
    run_postchecks,
    run_prechecks,
    safe_subpath,
    sanitize_path_segment,
)
from junos_upgrader.drivers.junos import JunosSwitchDriver
from junos_upgrader.junos_client import (
    CredentialSet,
    NetmikoJunosTransport,
    detect_outbound_ip,
    load_credentials,
)
from junos_upgrader.models import (
    HopSpec,
    NeighborExpectation,
    PlatformPolicy,
    SwitchRecord,
    SwitchState,
    TriageVerdict,
)
from junos_upgrader.orchestrator import (
    UpgradeOptions,
    _wait_for_reboot,
    run_upgrade_batches,
    upgrade_single_switch,
)
from junos_upgrader.planner import load_release_catalog, match_platform_policy
from junos_upgrader.topology import build_topology_graph
from junos_upgrader.transfer import (
    TransferOutcome,
    UnifiedFirmwareServer,
    _is_usable_external_url,
    resolve_local_firmware_file,
    stage_or_stream_package,
    validate_package_filename,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASES_YML = REPO_ROOT / "manifests" / "approved-releases.yml"
CREDS_EXAMPLE = REPO_ROOT / "credentials.example.json"


def _sw(
    hostname: str,
    model: str = "ex3400-48p",
    version: str = "23.2R2-S3",
    ip: str = "192.0.2.10",
    role: str = "Access",
    neighbors: list[NeighborExpectation] | None = None,
) -> SwitchRecord:
    return SwitchRecord(
        site="SITE",
        hostname=hostname,
        management_ip=ip,
        model=model,
        serial_number=f"SN_{hostname}",
        current_version=version,
        role=role,
        management_method="SSH",
        state=SwitchState.READY,
        expected_neighbors=neighbors or [],
    )


def _fast_opts(
    base_url: str,
    tmp_path: Path,
    fw_dir: Path,
    require_release_notes: bool = False,
    **kwargs: object,
) -> UpgradeOptions:
    return UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=fw_dir,
        evidence_root=tmp_path / "ev",
        config_root=tmp_path / "cfg",
        manifest_path=tmp_path / "manifest.json",
        change_number="CHG_TEST",
        operator="netops",
        require_release_notes=require_release_notes,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
        **kwargs,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# checks.py tests
# ---------------------------------------------------------------------------


def test_optics_off_is_eligible_and_active_alarms_quarantine(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    # Default FakeJunosTransport includes realistic ': Off' lines -> must be ELIGIBLE!
    sw_ok = _sw("OPTICS_OK")
    tr_ok = FakeJunosTransport(
        sw_ok.hostname, sw_ok.model, sw_ok.serial_number, sw_ok.current_version
    )
    verdict, checks = evaluate_hardware_and_fs_triage(
        tr_ok, sw_ok, pol, tmp_path / "ev_ok", tmp_path / "cfg_ok"
    )
    assert verdict == TriageVerdict.ELIGIBLE
    assert any(c.name == "uplink_optics_health" and c.passed for c in checks)

    # Every active ': On' alarm variant (including Junos EX 'Laser output power low alarm : On') triggers REPLACE
    for idx, alarm_line in enumerate(
        (
            "Laser rx power low alarm : On",
            "Laser output power low alarm : ON",
            "Laser tx power low alarm : On",
            "Laser bias current high alarm : On",
        )
    ):
        sw_bad = _sw(f"OPTICS_BAD_{idx}")
        tr_bad = FakeJunosTransport(
            sw_bad.hostname,
            sw_bad.model,
            sw_bad.serial_number,
            sw_bad.current_version,
            optics_output=f"Physical interface: xe-0/2/0\n    {alarm_line}\n",
        )
        v_bad, _ = evaluate_hardware_and_fs_triage(
            tr_bad, sw_bad, pol, tmp_path / f"ev_{idx}", tmp_path / f"cfg_{idx}"
        )
        assert v_bad == TriageVerdict.REPLACE_RECOMMENDED


def test_storage_parsing_handles_zero_bytes_wrapped_df_and_single_dict_json() -> None:
    # 0B full /var/tmp must parse as 0 MB (not None / dropped!)
    zero_json = json.dumps(
        {
            "system-storage-information": [
                {
                    "filesystem": [
                        {
                            "mounted-on": [{"data": "/var/tmp"}],
                            "available-blocks": [
                                {"data": "0", "attributes": {"junos:format": "0B"}}
                            ],
                        },
                        {
                            "mounted-on": [{"data": "/"}],
                            "available-blocks": [
                                {"data": "2048000", "attributes": {"junos:format": "1000M"}}
                            ],
                        },
                    ]
                }
            ]
        }
    )
    free_mb, mounts = parse_junos_storage(zero_json)
    assert free_mb == 0
    assert mounts["/var/tmp"] == 0

    # Single dict filesystem (not list) + fallback to blocks when junos:format is unparseable
    single_dict_json = json.dumps(
        {
            "system-storage-information": [
                {
                    "filesystem": {
                        "mounted-on": [{"data": "/.mount"}],
                        "available-blocks": [
                            {"data": str(512 * 2048), "attributes": {"junos:format": "bad"}}
                        ],
                    }
                }
            ]
        }
    )
    free_single, _ = parse_junos_storage(single_dict_json)
    assert free_single == 512

    # Wrapped 2-line df text output (long device path followed by 5-column continuation)
    wrapped_df = (
        "Filesystem              Size       Used      Avail  Capacity   Mounted on\n"
        "/dev/gpt/junos-var-long-partition\n"
        "                        2.0G       1.5G       512M       75%   /var\n"
    )
    free_wrapped, mounts_w = parse_junos_storage(wrapped_df)
    assert free_wrapped == 512
    assert mounts_w["/var"] == 512


def test_ro_mount_and_flash_log_and_safe_var_tmp_cleanup(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    # Benign nullfs/devfs/cd9660 RO mounts do NOT trigger REPLACE; UFS RO '/' DOES!
    sw_ok = _sw("MOUNT_OK")
    tr_ok = FakeJunosTransport(
        sw_ok.hostname,
        sw_ok.model,
        sw_ok.serial_number,
        sw_ok.current_version,
        mount_output=(
            "/dev/md0.uzip on / (cd9660, local, read-only)\n"
            "/packages/mnt/jweb on /var/jails/rest-api (nullfs, local, read-only)\n"
            "devfs on /var/jail/dev (devfs, local, read-only)\n"
            "/dev/gpt/junos on /.mount (ufs, local, soft-updates)\n"
        ),
        # Non-storage sshd Input/output error must NOT quarantine healthy switch
        flash_log_output="Nov 24 12:00:00 sw sshd[123]: Input/output error on tty",
    )
    v_ok, _ = evaluate_hardware_and_fs_triage(
        tr_ok, sw_ok, pol, tmp_path / "ev1", tmp_path / "cfg1"
    )
    assert v_ok == TriageVerdict.ELIGIBLE

    # UFS root '/' mounted read-only triggers REPLACE_RECOMMENDED
    sw_ro = _sw("MOUNT_RO_ROOT")
    tr_ro = FakeJunosTransport(
        sw_ro.hostname,
        sw_ro.model,
        sw_ro.serial_number,
        sw_ro.current_version,
        mount_output="/dev/da0s1a on / (ufs, local, read-only)\n",
    )
    v_ro, _ = evaluate_hardware_and_fs_triage(
        tr_ro, sw_ro, pol, tmp_path / "ev2", tmp_path / "cfg2"
    )
    assert v_ro == TriageVerdict.REPLACE_RECOMMENDED

    # Permission denied on `start shell command "mount"` fails closed (hard_stop, NEEDS_REMEDIATION)
    sw_perm = _sw("MOUNT_PERM")
    tr_perm = FakeJunosTransport(
        sw_perm.hostname,
        sw_perm.model,
        sw_perm.serial_number,
        sw_perm.current_version,
        mount_output="error: permission denied\n",
    )
    v_perm, checks_perm = evaluate_hardware_and_fs_triage(
        tr_perm, sw_perm, pol, tmp_path / "ev3", tmp_path / "cfg3"
    )
    assert v_perm == TriageVerdict.NEEDS_REMEDIATION
    assert any(c.name == "fs_read_write" and not c.passed and c.hard_stop for c in checks_perm)

    # mmc1 error triggers REPLACE_RECOMMENDED
    sw_mmc = _sw("MMC1_BAD")
    tr_mmc = FakeJunosTransport(
        sw_mmc.hostname,
        sw_mmc.model,
        sw_mmc.serial_number,
        sw_mmc.current_version,
        flash_log_output="kernel: mmc1: CMD error status 0x20",
    )
    v_mmc, _ = evaluate_hardware_and_fs_triage(
        tr_mmc, sw_mmc, pol, tmp_path / "ev4", tmp_path / "cfg4"
    )
    assert v_mmc == TriageVerdict.REPLACE_RECOMMENDED

    # auto_cleanup_storage must NEVER follow symlinks outside /var/tmp or run injected filenames
    tr_clean = FakeJunosTransport(
        "CLEAN_SW",
        "ex3400-48p",
        "SN_C",
        "23.2R2-S3",
        var_tmp_output=(
            "total 100\n"
            "lrwxr-xr-x 1 root wheel 24 Nov 20 12:00 evil-link.tgz -> /cf/packages/system.tgz\n"
            "-rw-r--r-- 1 root wheel 100 Nov 20 12:00 stale-old.tgz\n"
            "-rw-r--r-- 1 root wheel 100 Nov 20 12:00 bad;reboot.tgz\n"
            "-rw-r--r-- 1 root wheel 100 Nov 20 12:00 ../escape.tgz\n"
        ),
    )
    auto_cleanup_storage(tr_clean, tmp_path / "ev_clean", execute_cleanup=True)
    del_cmds = [c for c in tr_clean.commands_executed if c.startswith("file delete ")]
    assert del_cmds == ["file delete /var/tmp/stale-old.tgz"]


def test_exact_version_model_commit_vc_landmines_and_postchecks(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    # Exact model check: manifest 'ex4300-48' must NOT match live 'ex4300-48mp'
    sw_sub = _sw("SUBSTR_MODEL", model="ex4300-48", version="23.4R2-S1")
    tr_sub = FakeJunosTransport("SUBSTR_MODEL", "ex4300-48mp", sw_sub.serial_number, "23.4R2-S10")
    checks_sub = run_prechecks(
        tr_sub,
        sw_sub,
        pol,
        pol.hops[-1],
        tmp_path / "ev_sub",
        tmp_path / "cfg_sub",
        require_release_notes=False,
    )
    assert any(
        c.name == "identity_and_version" and not c.passed and c.hard_stop for c in checks_sub
    )

    # Exact version check in postchecks: '23.4R2-S1' must NOT match '23.4R2-S10'
    pre_base = {
        "show version": "Model: ex3400-48p\nJunos: 23.2R2-S3\n",
        "show system alarms": "No alarms currently active",
        "show chassis alarms": "No alarms currently active",
        "show interfaces terse": "ge-0/0/0 up up\n",
        "show lldp neighbors": "mge-0/0/1 - 00:00:5e:00:53:01 xe-0/0/1 CORE_A\n",
        "show spanning-tree bridge": "  Root ID                           : 32768.00:00:5e:00:53:01\n",
        "show lacp interfaces": "  mge-0/0/1 Current Fast periodic Collecting Distributing\n",
        "show ethernet-switching table": (
            "  default 00:00:5e:00:53:01 D - ge-0/0/1.0\n"
            "  default 00:00:5e:00:53:02 D - ge-0/0/2.0\n"
        ),
    }
    post_base = {
        "show version": "Model: ex3400-48p\nJunos: 23.4R2-S10\n",
        "show system alarms": "1 alarms currently active\nMinor RE 0 /var partition usage is high",
        "show chassis alarms": "No alarms currently active",
        "show interfaces terse": "",  # Empty terse output must NOT silently pass!
        "show lldp neighbors": "mge-0/0/1 - 00:00:5e:00:53:99 xe-0/0/1 ROGUE_B\n",
        "show spanning-tree bridge": "  Root ID                           : 4096.00:00:5e:00:53:99\n",
        "show lacp interfaces": "  mge-0/0/1 Defaulted Fast periodic Collecting distributing\n",
        "show ethernet-switching table": (
            "  default 00:00:5e:00:53:ff S - irb.0\n  default 00:00:5e:00:53:fe L - Router\n"
        ),
    }
    post_res = {
        c.name: c for c in run_postchecks(pre_base, post_base, expected_version="23.4R2-S1")
    }
    assert not post_res["target_version_active"].passed
    assert not post_res["rstp_root_preserved"].passed
    assert not post_res["lldp_neighbors_preserved"].passed
    assert not post_res["interfaces_up_preserved"].passed
    assert not post_res["lacp_bundles_preserved"].passed
    assert not post_res["mac_table_repopulated"].passed  # Static/Local MACs ignored -> 0 dynamic!
    # Minor /var system alarm with clean chassis alarms is non-blocking warning with details
    assert not post_res["post_no_active_alarms"].passed
    assert not post_res["post_no_active_alarms"].hard_stop
    assert "/var partition usage is high" in post_res["post_no_active_alarms"].message

    # LLDP & LACP mge- and 5-column parsers directly
    assert _extract_lldp_pairs("mge-0/0/1 ae0 00:00:5e:00:53:01 ge-0/0/1 CORE") == {
        ("mge-0/0/1", "00:00:5e:00:53:01/CORE")
    }
    assert _extract_lacp_up_members("mge-0/0/1 Current Fast periodic Collecting Distributing") == {
        "mge-0/0/1"
    }
    assert (
        _extract_mac_count(
            "default 00:00:5e:00:53:01 S - irb.0\ndefault 00:00:5e:00:53:02 D - ge-0/0/1.0"
        )
        == 1
    )

    # Landmines: collects ALL weak SSH lines and respects deactivate telnet
    cfg = (
        "set system services ssh ciphers aes128-cbc\n"
        "set system services ssh protocol-version v1\n"
        "set system services telnet\n"
        "deactivate system services telnet\n"
    )
    lm = check_config_landmines(cfg)
    assert len(lm) == 2
    assert all("telnet" not in r.message.lower() for r in lm)

    # Commit comment containing 'error:' must NOT false-positive; Inactive VC member IS caught
    class CustomCommitVcTransport(FakeJunosTransport):
        def run_command(self, command: str, read_timeout: int = 60) -> str:
            if command.strip() == "show system commit":
                return "0 2026-11-21 10:00:00 UTC by netops via cli\n    comment: fix error: vlan\n"
            if command.strip() == "show virtual-chassis status":
                return "Virtual Chassis ID: 0000.5e00.5301\n0 (FPC 0) Prsnt Master*\n1 (FPC 1) Inactive Linecard\n"
            return super().run_command(command, read_timeout=read_timeout)

    sw_vc = _sw("VC_INACTIVE")
    tr_vc = CustomCommitVcTransport(
        sw_vc.hostname, sw_vc.model, sw_vc.serial_number, sw_vc.current_version
    )
    c_map = {
        c.name: c
        for c in run_prechecks(
            tr_vc,
            sw_vc,
            pol,
            pol.hops[-1],
            tmp_path / "ev_vc",
            tmp_path / "cfg_vc",
            require_release_notes=False,
        )
    }
    assert c_map["clean_commit_state"].passed
    assert not c_map["no_virtual_chassis"].passed

    # Path sanitization neutralizes traversal and slashes
    assert sanitize_path_segment("../../etc/passwd") == "etc_passwd"
    assert sanitize_path_segment("CHG/2026/01") == "CHG_2026_01"
    p = safe_subpath(tmp_path, "../../evil", "CHG/1", "sw")
    assert tmp_path.resolve() in p.resolve().parents


# ---------------------------------------------------------------------------
# transfer.py tests
# ---------------------------------------------------------------------------


def test_unified_firmware_server_security_token_head_traversal_and_ui_acl(tmp_path: Path) -> None:
    fw_dir = tmp_path / "firmware"
    good_tgz = fw_dir / "juniper" / "ex3400" / "23.4R2-S8" / "junos-arm-32-23.4R2-S8.tgz"
    create_valid_tgz(good_tgz, comment="arm-32")
    (fw_dir / "secret.txt").write_text("not a firmware package", encoding="utf-8")

    # External file linked via symlink inside firmware_dir must be rejected
    outside = tmp_path / "outside.tgz"
    outside.write_bytes(b"\x1f\x8b" + b"outside")
    symlink_pkg = fw_dir / "escape.tgz"
    os.symlink(outside, symlink_pkg)

    with UnifiedFirmwareServer(
        firmware_dir=fw_dir,
        topology_provider=lambda: {"nodes": [{"id": "SW1"}], "edges": []},
        port=0,
        bind_host="127.0.0.1",
        allow_remote_ui=False,
        allowed_clients={"127.0.0.1"},
    ) as srv:
        # Double start() returns same port without leaking a second server
        assert srv.start() == srv.port

        # Loopback UI access succeeds for GET and HEAD
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/") as r:
            assert r.status == 200
            assert b"junos-switch-upgrader" in r.read()
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/api/topology") as r:
            assert r.status == 200
            assert b'"SW1"' in r.read()

        # Valid tokenized firmware GET & HEAD succeed
        url = srv.build_http_url("127.0.0.1", "juniper/ex3400/23.4R2-S8/junos-arm-32-23.4R2-S8.tgz")
        assert f"/firmware/{srv.token}/" in url
        with urllib.request.urlopen(url) as r:
            assert r.status == 200
            assert r.read() == good_tgz.read_bytes()

        conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
        try:
            conn.request(
                "HEAD", f"/firmware/{srv.token}/juniper/ex3400/23.4R2-S8/junos-arm-32-23.4R2-S8.tgz"
            )
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 200
            assert int(resp.getheader("Content-Length") or 0) == good_tgz.stat().st_size

            # HEAD on directories must return 404 (never 200/301 dir listing!)
            for bad_path in (
                "/firmware/",
                f"/firmware/{srv.token}/",
                f"/firmware/{srv.token}/juniper/",
                f"/firmware/{srv.token}/juniper",
                "/firmware/wrong-token/juniper/ex3400/23.4R2-S8/junos-arm-32-23.4R2-S8.tgz",
                f"/firmware/{srv.token}/secret.txt",
                f"/firmware/{srv.token}/escape.tgz",
                f"/firmware/{srv.token}/%2e%2e/outside.tgz",
                f"/firmware/{srv.token}/test%00.tgz",
            ):
                for method in ("GET", "HEAD"):
                    conn.request(method, bad_path)
                    r_bad = conn.getresponse()
                    r_bad.read()
                    assert r_bad.status == 404, (
                        f"Expected 404 for {method} {bad_path}, got {r_bad.status}"
                    )
        finally:
            conn.close()

        # Token must be redacted in transfer_log
        assert srv.transfer_log
        assert all(srv.token not in entry["request"] for entry in srv.transfer_log)

        # Remote switch rejected when server bound to loopback 127.0.0.1
        with pytest.raises(RuntimeError, match="loopback"):
            srv.build_http_url("192.0.2.50", "juniper/ex3400/23.4R2-S8/junos-arm-32-23.4R2-S8.tgz")

    # Test allowed_clients rejecting 127.0.0.1 with 403
    with UnifiedFirmwareServer(
        firmware_dir=fw_dir,
        port=0,
        bind_host="127.0.0.1",
        allowed_clients={"192.0.2.99"},
    ) as srv_acl:
        url_acl = srv_acl.build_http_url(
            "127.0.0.1", "juniper/ex3400/23.4R2-S8/junos-arm-32-23.4R2-S8.tgz"
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(url_acl)
        assert exc_info.value.code == 403


def test_transfer_validation_scp_fallback_and_cleanup(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    # Filename validation blocks traversal, wildcards, and CLI metacharacters
    for bad_name in ("../evil.tgz", "pkg*.tgz", "a;reboot.tgz", "pkg.img", "sub/pkg.tgz"):
        with pytest.raises(ValueError):
            validate_package_filename(bad_name)

    # Symlink outside firmware_dir is ignored by resolve_local_firmware_file
    fw_dir = tmp_path / "fw"
    fw_dir.mkdir()
    outside = tmp_path / hop.package_filename
    create_valid_tgz(outside)
    os.symlink(outside, fw_dir / hop.package_filename)
    assert resolve_local_firmware_file(fw_dir, pol, hop) is None
    (fw_dir / hop.package_filename).unlink()

    # Valid local file
    local_pkg = fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    create_valid_tgz(local_pkg)
    assert resolve_local_firmware_file(fw_dir, pol, hop) == local_pkg

    # External URL validation
    assert not _is_usable_external_url("http://")
    assert not _is_usable_external_url("http://firmware-cache.example.internal")
    assert not _is_usable_external_url("https://repo.corp.net;reboot")
    assert _is_usable_external_url("https://firmware.corp.invalid.net") is True

    # Invalid transfer_mode raises ValueError
    sw = _sw("XFER_SW", ip="127.0.0.1")
    tr = FakeJunosTransport(sw.hostname, sw.model, sw.serial_number, sw.current_version)
    with pytest.raises(ValueError, match="Unsupported transfer_mode"):
        stage_or_stream_package(tr, sw, pol, hop, fw_dir, None, "", transfer_mode="tftp")

    # Timeout/exception during HTTP file copy cleans up partial file and falls back to SCP!
    class TimeoutHttpCopyTransport(FakeJunosTransport):
        def run_command(self, command: str, read_timeout: int = 60) -> str:
            if command.startswith("file copy "):
                self.commands_executed.append(command)
                raise TimeoutError("HTTP port firewalled")
            return super().run_command(command, read_timeout=read_timeout)

    tr_to = TimeoutHttpCopyTransport(sw.hostname, sw.model, sw.serial_number, sw.current_version)
    with UnifiedFirmwareServer(firmware_dir=fw_dir, port=0, bind_host="127.0.0.1") as srv:
        outcome = stage_or_stream_package(
            tr_to, sw, pol, hop, fw_dir, srv, "", transfer_mode="auto"
        )
    assert outcome.mode_used == "scp"
    assert len(tr_to.scp_uploads) == 1
    assert f"file delete /var/tmp/{hop.package_filename}" in tr_to.commands_executed

    # Silent HTTP copy failure ('No space left on device' without 'error:') triggers SCP fallback too!
    class NoSpaceHttpTransport(FakeJunosTransport):
        def run_command(self, command: str, read_timeout: int = 60) -> str:
            if command.startswith("file copy "):
                self.commands_executed.append(command)
                return "No space left on device"
            return super().run_command(command, read_timeout=read_timeout)

    tr_ns = NoSpaceHttpTransport(sw.hostname, sw.model, sw.serial_number, sw.current_version)
    with UnifiedFirmwareServer(firmware_dir=fw_dir, port=0, bind_host="127.0.0.1") as srv:
        outcome_ns = stage_or_stream_package(
            tr_ns, sw, pol, hop, fw_dir, srv, "", transfer_mode="auto"
        )
    assert outcome_ns.mode_used == "scp"


# ---------------------------------------------------------------------------
# junos_client.py tests
# ---------------------------------------------------------------------------


def test_load_credentials_and_repr_redaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("JUNOS_USER", raising=False)
    monkeypatch.delenv("JUNOS_PASSWORD", raising=False)
    monkeypatch.delenv("JUNOS_KEY_FILE", raising=False)

    # No credentials configured -> raises ValueError
    with pytest.raises(ValueError, match="No SSH credentials"):
        load_credentials()

    # Only CHANGE_ME placeholders -> raises ValueError
    only_placeholder = tmp_path / "creds_bad.json"
    only_placeholder.write_text(
        json.dumps([{"username": "netops", "password": "CHANGE_ME"}]), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="CHANGE_ME"):
        load_credentials(credentials_file=only_placeholder)

    # credentials.example.json skips CHANGE_ME entry and keeps SSH key entry
    example_creds = load_credentials(credentials_file=CREDS_EXAMPLE)
    assert len(example_creds) == 1
    assert example_creds[0].name == "Juniper-SSH-Key"
    assert example_creds[0].key_file == "~/.ssh/id_ed25519"

    # Does NOT inject cli_key into JSON password-only entries, AND honors explicit --username (no password)
    pw_file = tmp_path / "creds_pw.json"
    pw_file.write_text(
        json.dumps([{"username": "ops", "password": "s3cr3t-value", "vendor": "juniper"}]),
        encoding="utf-8",
    )
    loaded = load_credentials(
        credentials_file=pw_file, username="agent-user", key_file="/tmp/my_key"
    )
    assert loaded[0].username == "agent-user"
    assert loaded[0].key_file == "/tmp/my_key"
    assert loaded[1].username == "ops"
    assert loaded[1].key_file is None

    # repr() NEVER leaks plaintext passwords!
    tr = NetmikoJunosTransport(host="192.0.2.10", credentials=loaded)
    assert "s3cr3t-value" not in repr(loaded[1])
    assert "s3cr3t-value" not in repr(tr)


def test_netmiko_connect_lifecycle_no_timeout_doubling_and_cleanup() -> None:
    from netmiko import NetmikoTimeoutException
    from paramiko import SSHException

    c1 = CredentialSet(username="keyuser", password="", key_file="/tmp/bad_key")
    c2 = CredentialSet(username="pwuser", password="valid-password")

    # 1. NetmikoTimeoutException MUST NOT trigger legacy SSHException retry (no double timeout!)
    tr_to = NetmikoJunosTransport(host="192.0.2.10", credentials=[c2])
    with patch(
        "netmiko.ConnectHandler", side_effect=NetmikoTimeoutException("timed out")
    ) as mock_ch:
        with pytest.raises(NetmikoTimeoutException):
            tr_to.connect()
        assert mock_ch.call_count == 1

    # 2. Bad key SSHException falls through to password credential #2; screen setup runs cleanly
    fake_conn = MagicMock()
    tr_fb = NetmikoJunosTransport(host="192.0.2.10", credentials=[c1, c2])
    with patch(
        "netmiko.ConnectHandler",
        side_effect=[SSHException("bad key"), SSHException("bad key legacy"), fake_conn],
    ) as mock_ch:
        tr_fb.connect()
        assert tr_fb.connected_username == "pwuser"
        assert mock_ch.call_count == 3

    # 3. Failure in `set cli screen-length 0` disconnects `_conn` (no connection leak!)
    broken_cli_conn = MagicMock()
    broken_cli_conn.send_command.side_effect = RuntimeError("cli hang")
    tr_leak = NetmikoJunosTransport(host="192.0.2.10", credentials=[c2])
    with patch("netmiko.ConnectHandler", return_value=broken_cli_conn):
        with pytest.raises(RuntimeError, match="cli hang"):
            tr_leak.connect()
    broken_cli_conn.disconnect.assert_called_once()
    assert tr_leak._conn is None

    # 4. run_interactive_yes raises if disconnect happens BEFORE confirmation prompt
    tr_int = NetmikoJunosTransport(host="192.0.2.10", credentials=[c2])
    pre_drop_conn = MagicMock()
    pre_drop_conn.send_command.side_effect = EOFError("dropped before prompt")
    tr_int._conn = pre_drop_conn
    with pytest.raises(EOFError):
        tr_int.run_interactive_yes("request system reboot", allow_disconnect=True)

    # 5. detect_outbound_ip raises when allow_loopback_fallback=False on unresolvable host
    with pytest.raises(RuntimeError):
        detect_outbound_ip("nonexistent.invalid", allow_loopback_fallback=False)

    # 6. IncompatiblePeer tries legacy fallback once, then stops without looping over credentials
    import logging

    from paramiko.ssh_exception import IncompatiblePeer

    logging.getLogger("paramiko.transport").setLevel(logging.NOTSET)
    tr_inc = NetmikoJunosTransport(host="192.0.2.10", credentials=[c1, c2])
    with patch(
        "netmiko.ConnectHandler",
        side_effect=[
            IncompatiblePeer("no acceptable host key"),
            IncompatiblePeer("no acceptable kex algorithm"),
        ],
    ) as mock_ch:
        with pytest.raises(IncompatiblePeer):
            tr_inc.connect()
        assert mock_ch.call_count == 2
    assert logging.getLogger("paramiko.transport").level == logging.CRITICAL


# ---------------------------------------------------------------------------
# drivers/junos.py tests
# ---------------------------------------------------------------------------


def test_junos_driver_checksum_install_and_snapshot_hardening() -> None:
    drv = JunosSwitchDriver()
    tr = FakeJunosTransport("DRV_SW", "ex3400-48p", "SN1", "23.2R2-S3", checksum_override="a" * 64)

    # Placeholder & empty rejected by default
    ok, msg = drv.verify_staged_checksum(
        tr, "/var/tmp/junos-arm-32-23.4R2-S8.tgz", "md5", "REPLACE_WITH_JUNIPER_MD5"
    )
    assert not ok and "Refusing unverified" in msg
    ok_e, _ = drv.verify_staged_checksum(tr, "/var/tmp/junos-arm-32-23.4R2-S8.tgz", "md5", "")
    assert not ok_e

    # sha256 maps to Junos CLI 'sha-256' and verifies exact 64-hex digest
    ok_sha, _ = drv.verify_staged_checksum(
        tr, "/var/tmp/junos-arm-32-23.4R2-S8.tgz", "sha256", "a" * 64
    )
    assert ok_sha
    assert "file checksum sha-256 /var/tmp/junos-arm-32-23.4R2-S8.tgz" in tr.commands_executed

    # Substring match rejected
    ok_sub, _ = drv.verify_staged_checksum(
        tr, "/var/tmp/junos-arm-32-23.4R2-S8.tgz", "sha256", "aaaa"
    )
    assert not ok_sub

    # Unsupported checksum_type and path traversal rejected before running CLI
    ok_algo, _ = drv.verify_staged_checksum(
        tr, "/var/tmp/junos-arm-32-23.4R2-S8.tgz", "md5;reboot", "a" * 32
    )
    assert not ok_algo
    ok_path, _ = drv.verify_staged_checksum(tr, "/etc/passwd", "md5", "a" * 32)
    assert not ok_path

    # Disallowed install_options (e.g. 'reboot' or CLI injection) rejected
    bad_hop = HopSpec(
        "23.4",
        "23.4R2-S8",
        "junos-arm-32-23.4R2-S8.tgz",
        "md5",
        "a" * 32,
        install_options=["reboot"],
    )
    ok_opt, msg_opt = drv.install_and_reboot(
        tr, bad_hop, TransferOutcome("scp", "/var/tmp/junos-arm-32-23.4R2-S8.tgz", False)
    )
    assert not ok_opt and "Disallowed Junos install option" in msg_opt

    # CLI injection in software_add_target rejected
    good_hop = HopSpec("23.4", "23.4R2-S8", "junos-arm-32-23.4R2-S8.tgz", "md5", "a" * 32)
    ok_inj, _ = drv.install_and_reboot(
        tr, good_hop, TransferOutcome("scp", "/var/tmp/a.tgz | save /tmp/x", False)
    )
    assert not ok_inj

    # Reboot command error is detected!
    tr_reb = FakeJunosTransport("DRV_SW", "ex3400-48p", "SN1", "23.2R2-S3", fail_reboot_cmd=True)
    ok_reb, msg_reb = drv.install_and_reboot(
        tr_reb, good_hop, TransferOutcome("scp", "/var/tmp/junos-arm-32-23.4R2-S8.tgz", False)
    )
    assert not ok_reb and "Reboot command failed" in msg_reb

    # PowerPC EX4300 dispatches `request system snapshot slice alternate`
    ppc_pol = PlatformPolicy(
        "ex4300*", "juniper", "access", "21.4R3-S12", "jinstall-ex-4300", "powerpc", 600, 600
    )
    ok_ppc, _ = drv.refresh_recovery_snapshot(tr, ppc_pol)
    assert ok_ppc
    assert "request system snapshot slice alternate" in tr.commands_executed

    vm_pol = PlatformPolicy(
        "qfx5120*", "juniper", "core", "23.4R2-S8", "jinstall-host-qfx-5e", "qfx-5e", 1500, 720
    )
    ok_vm, _ = drv.refresh_recovery_snapshot(tr, vm_pol)
    assert ok_vm
    assert "request vmhost snapshot" in tr.commands_executed


# ---------------------------------------------------------------------------
# orchestrator.py tests
# ---------------------------------------------------------------------------


def test_orchestrator_replans_when_live_switch_is_older_than_manifest(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    fw_dir = tmp_path / "fw"
    checksums: dict[str, str] = {}
    for hop in pol.hops:
        _, md5_hex, _ = create_valid_tgz(
            fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
        )
        hop.checksum = md5_hex
        checksums[hop.package_filename] = md5_hex

    # Manifest mistakenly thinks switch is on 23.2R2-S3 (1 hop away),
    # but live switch is actually on 21.2R3-S8 (3 hops away: 22.2 -> 23.2 -> 23.4)!
    sw = _sw("STALE_OLDER_SW", version="23.2R2-S3")
    tr = FakeJunosTransport(
        sw.hostname,
        sw.model,
        sw.serial_number,
        running_version="21.2R3-S8",
        fail_http_copy=True,
        checksums_by_filename=checksums,
    )
    opts = _fast_opts(base_url, tmp_path, fw_dir)
    res = upgrade_single_switch(sw, pol, exclusions, policies, tr, opts)
    assert res.state == SwitchState.COMPLETED
    assert res.current_version == "23.4R2-S8"
    # Must NOT have jumped directly from 21.2 to 23.4! Must have executed 22.2 -> 23.2 -> 23.4!
    assert [h["hop"] for h in res.hop_history] == ["22.2R3-S5", "23.2R2-S3", "23.4R2-S8"]


def test_stage_only_http_stream_preserves_phase2_cleanup_on_ex2300(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex2300-c-12p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    _, md5_hex, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex2300" / hop.train / hop.package_filename
    )
    hop.checksum = md5_hex

    sw = _sw("EX2300_STAGE", model="ex2300-c-12p", version="23.4R2.13", ip="127.0.0.1")
    tr = FakeJunosTransport(
        sw.hostname, sw.model, sw.serial_number, "23.4R2.13", free_storage_mb=306
    )

    # Phase 1: stage_only on EX2300 (prefer_http_stream=True)
    stage_opts = _fast_opts(base_url, tmp_path, fw_dir, stage_only=True)
    staged = upgrade_single_switch(sw, pol, exclusions, policies, tr, stage_opts)
    assert staged.state == SwitchState.STAGED
    assert staged.staged_package.startswith("http-stream:")

    # Phase 2: upgrade MUST still run `request system storage cleanup no-confirm`!
    tr.commands_executed.clear()
    up_opts = _fast_opts(base_url, tmp_path, fw_dir, auto_cleanup=True)
    with UnifiedFirmwareServer(firmware_dir=fw_dir, port=0, bind_host="127.0.0.1") as srv:
        final = upgrade_single_switch(staged, pol, exclusions, policies, tr, up_opts, server=srv)
    assert final.state == SwitchState.COMPLETED
    assert "request system storage cleanup no-confirm" in tr.commands_executed


def test_wait_for_reboot_fails_if_switch_never_goes_offline() -> None:
    tr = FakeJunosTransport("STAY_UP", "ex3400-48p", "SN1", "23.2R2-S3", go_down_polls=0)
    # Switch stays reachable for entire wait_down_seconds -> must return False!
    assert (
        _wait_for_reboot(tr, timeout_seconds=1, poll_interval=0.0, wait_down_seconds=0.02) is False
    )


def test_snapshot_exception_does_not_flip_completed_to_failed_and_dry_run_is_isolated(
    tmp_path: Path,
) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    _, md5_hex, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    )
    hop.checksum = md5_hex

    # 1. Snapshot exception leaves COMPLETED switch COMPLETED with a warning
    sw_snap = _sw("SNAP_WARN_SW")
    tr_snap = FakeJunosTransport(
        sw_snap.hostname,
        sw_snap.model,
        sw_snap.serial_number,
        "23.2R2-S3",
        fail_http_copy=True,
        raise_on_snapshot=True,
        checksums_by_filename={hop.package_filename: md5_hex},
    )
    res_snap = upgrade_single_switch(
        sw_snap,
        pol,
        exclusions,
        policies,
        tr_snap,
        _fast_opts(base_url, tmp_path, fw_dir, refresh_snapshot=True),
    )
    assert res_snap.state == SwitchState.COMPLETED
    assert "Snapshot refresh warning" in res_snap.last_error

    # 2. Dry-run precheck failure does NOT mutate live SwitchRecord, manifest.json, or ancestor holds!
    transit = _sw(
        "DRY_TRANSIT",
        ip="192.0.2.50",
        neighbors=[NeighborExpectation("ge-0/0/1", "DRY_LEAF", "ge-0/2/0")],
    )
    leaf = _sw(
        "DRY_LEAF",
        ip="192.0.2.51",
        neighbors=[NeighborExpectation("ge-0/2/0", "DRY_TRANSIT", "ge-0/0/1", is_upstream=True)],
    )
    all_sw = [transit, leaf]
    graph = build_topology_graph(all_sw, origin=TEST_ORIGIN)

    def fail_vc_factory(s: SwitchRecord) -> FakeJunosTransport:
        return FakeJunosTransport(
            s.hostname, s.model, s.serial_number, s.current_version, virtual_chassis=True
        )

    dry_manifest = tmp_path / "dry_manifest.json"
    opts_dry = UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=fw_dir,
        evidence_root=tmp_path / "ev_dry",
        config_root=tmp_path / "cfg_dry",
        manifest_path=dry_manifest,
        change_number="CHG_DRY",
        operator="netops",
        require_release_notes=False,
        dry_run=True,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
    )
    processed, wave_ok = run_upgrade_batches(
        all_sw, all_sw, policies, exclusions, fail_vc_factory, opts_dry, graph=graph
    )
    assert not wave_ok
    assert processed[0].state == SwitchState.FAILED
    # Originals remain untouched and manifest was NOT written!
    assert leaf.state == SwitchState.READY
    assert transit.state == SwitchState.READY
    assert not dry_manifest.exists()

    # 3. Direct upgrade_single_switch on already-current switch transitions cleanly to COMPLETED
    sw_done = _sw("ALREADY_CURRENT", version="23.4R2-S8")
    tr_unused = FakeJunosTransport(
        sw_done.hostname, sw_done.model, sw_done.serial_number, "23.4R2-S8"
    )
    res_done = upgrade_single_switch(
        sw_done, pol, exclusions, policies, tr_unused, _fast_opts(base_url, tmp_path, fw_dir)
    )
    assert res_done.state == SwitchState.COMPLETED


def test_run_upgrade_batches_concurrency_lock_and_factory_failure(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    _, md5_hex, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    )
    hop.checksum = md5_hex

    core = _sw(
        "CORE_CONC",
        ip="192.0.2.60",
        role="Core",
        neighbors=[
            NeighborExpectation("xe-0/0/1", "LEAF_A", "xe-0/2/0"),
            NeighborExpectation("xe-0/0/2", "LEAF_B", "xe-0/2/0"),
        ],
    )
    leaf_a = _sw(
        "LEAF_A",
        ip="192.0.2.61",
        neighbors=[NeighborExpectation("xe-0/2/0", "CORE_CONC", "xe-0/0/1", is_upstream=True)],
    )
    leaf_b = _sw(
        "LEAF_B",
        ip="192.0.2.62",
        neighbors=[NeighborExpectation("xe-0/2/0", "CORE_CONC", "xe-0/0/2", is_upstream=True)],
    )
    all_sw = [core, leaf_a, leaf_b]
    graph = build_topology_graph(all_sw, origin=TEST_ORIGIN)

    lock = threading.Lock()
    opts = _fast_opts(base_url, tmp_path, fw_dir, batch_size=2, state_lock=lock)

    def ok_factory(s: SwitchRecord) -> FakeJunosTransport:
        return FakeJunosTransport(
            s.hostname,
            s.model,
            s.serial_number,
            s.current_version,
            fail_http_copy=True,
            checksums_by_filename={hop.package_filename: md5_hex},
        )

    processed, ok = run_upgrade_batches(
        all_sw, all_sw, policies, exclusions, ok_factory, opts, graph=graph
    )
    assert ok
    assert {s.hostname for s in processed} == {"LEAF_A", "LEAF_B"}
    assert leaf_a.state == SwitchState.COMPLETED
    assert leaf_b.state == SwitchState.COMPLETED

    # Factory exception marks switch FAILED and places ancestor on ANCESTOR_HOLD cleanly
    transit2 = _sw(
        "TR_FAC", ip="192.0.2.70", neighbors=[NeighborExpectation("ge-0/0/1", "LF_FAC", "ge-0/2/0")]
    )
    leaf2 = _sw(
        "LF_FAC",
        ip="192.0.2.71",
        neighbors=[NeighborExpectation("ge-0/2/0", "TR_FAC", "ge-0/0/1", is_upstream=True)],
    )
    sws2 = [transit2, leaf2]
    g2 = build_topology_graph(sws2, origin=TEST_ORIGIN)

    def exploding_factory(_: SwitchRecord) -> FakeJunosTransport:
        raise RuntimeError("vault unavailable")

    proc2, ok2 = run_upgrade_batches(
        sws2, sws2, policies, exclusions, exploding_factory, opts, graph=g2
    )
    assert not ok2
    assert len(proc2) == 1
    assert leaf2.state == SwitchState.FAILED
    assert "vault unavailable" in leaf2.last_error
    assert transit2.state == SwitchState.ANCESTOR_HOLD


def test_verifier_regressions_proceed_no_space_stale_hop_replan_and_ip_normalization(
    tmp_path: Path,
) -> None:
    from junos_upgrader.transfer import _normalize_ip, _UnifiedHandler

    # 1. junos_client.run_interactive_yes handles "Proceed?" without space before '?'
    tr_int = NetmikoJunosTransport(
        host="192.0.2.10", credentials=[CredentialSet(username="netops", password="pw")]
    )
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = ["Proceed?", "\nDone\nroot@sw>"]
    tr_int._conn = mock_conn
    out = tr_int.run_interactive_yes("request system snapshot recovery", allow_disconnect=False)
    assert "Proceed?" in out
    assert mock_conn.send_command.call_count == 2
    assert mock_conn.send_command.call_args_list[1].args[0] == "yes"

    # 2. orchestrator re-plans when stale hop fails hop-specific release_notes_reviewed
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    fw_dir = tmp_path / "fw_stale_rn"
    # Case A: Switch is ALREADY on final target 23.4R2-S8, manifest had stale 22.2R3-S5,
    # and require_release_notes=True (stale hop 23.2R2-S3 has release_notes_reviewed=False!).
    sw_done = _sw("STALE_ALREADY_DONE", version="22.2R3-S5")
    tr_done = FakeJunosTransport(
        sw_done.hostname, sw_done.model, sw_done.serial_number, running_version="23.4R2-S8"
    )
    opts_rn = _fast_opts(base_url, tmp_path, fw_dir, require_release_notes=True)
    res_done = upgrade_single_switch(sw_done, pol, exclusions, policies, tr_done, opts_rn)
    assert res_done.state == SwitchState.COMPLETED
    assert res_done.current_version == "23.4R2-S8"

    # Case B: Live switch is OLDER (21.2R3-S8) than manifest (23.2R2-S3); stale hop 23.4R2-S8 has
    # release_notes_reviewed=False, while true next hop 22.2R3-S5 IS reviewed & valid -> executes 22.2!
    hop_22_2 = next(h for h in pol.hops if h.target_version == "22.2R3-S5")
    hop_23_4 = pol.hops[-1]
    hop_22_2.release_notes_reviewed = True
    hop_23_4.release_notes_reviewed = False
    _, md5_22, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex3400" / hop_22_2.train / hop_22_2.package_filename
    )
    hop_22_2.checksum = md5_22

    sw_older = _sw("STALE_OLDER_RN", version="23.2R2-S3")
    tr_older = FakeJunosTransport(
        sw_older.hostname,
        sw_older.model,
        sw_older.serial_number,
        running_version="21.2R3-S8",
        fail_http_copy=True,
        checksums_by_filename={hop_22_2.package_filename: md5_22},
    )
    opts_one_hop = _fast_opts(base_url, tmp_path, fw_dir, require_release_notes=True, max_hops=1)
    res_older = upgrade_single_switch(sw_older, pol, exclusions, policies, tr_older, opts_one_hop)
    assert res_older.state == SwitchState.VALIDATED
    assert res_older.current_version == "22.2R3-S5"
    assert [h["hop"] for h in res_older.hop_history] == ["22.2R3-S5"]

    # Case C: Stale version + device-level hard-stop (VC) MUST still fail and NOT re-plan!
    sw_vc = _sw("STALE_VC_FAIL", version="22.2R3-S5")
    tr_vc = FakeJunosTransport(
        sw_vc.hostname,
        sw_vc.model,
        sw_vc.serial_number,
        running_version="23.4R2-S8",
        virtual_chassis=True,
    )
    res_vc = upgrade_single_switch(sw_vc, pol, exclusions, policies, tr_vc, opts_rn)
    assert res_vc.state == SwitchState.FAILED
    assert "Virtual Chassis" in res_vc.last_error

    # 3. transfer.py IPv4/IPv6 ACL normalization (non-canonical IPv6 & ::ffff: IPv4-mapped)
    assert _normalize_ip("2001:0db8:0000::0001") == "2001:db8::1"
    assert _normalize_ip("::ffff:192.0.2.10") == "192.0.2.10"
    assert _normalize_ip("::ffff:c000:020a") == "192.0.2.10"
    assert _normalize_ip("0:0:0:0:0:0:0:1") == "::1"

    srv = UnifiedFirmwareServer(
        firmware_dir=fw_dir,
        allowed_clients={"2001:0db8::0001", "::ffff:192.0.2.10"},
    )
    assert srv.allowed_clients == {"2001:db8::1", "192.0.2.10"}

    dummy_handler = object.__new__(_UnifiedHandler)
    dummy_handler._allowed_clients = srv.allowed_clients
    dummy_handler.client_address = ("2001:db8::1", 54321)
    assert dummy_handler._is_allowed_firmware_client() is True
    dummy_handler.client_address = ("::ffff:c000:020a", 54321)
    assert dummy_handler._is_allowed_firmware_client() is True
    dummy_handler.client_address = ("0:0:0:0:0:0:0:1", 54321)
    assert dummy_handler._is_loopback_client() is True


def _create_large_valid_tgz(dest: Path, payload_bytes: int, comment: str = "arm-32") -> tuple[Path, str]:
    """Create a valid gzipped tar archive >= payload_bytes using incompressible random bytes."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    comment_file = dest.parent / f".comment_{dest.stem}.tmp"
    blob_file = dest.parent / f".payload_{dest.stem}.bin"
    comment_file.write_text(comment, encoding="utf-8")
    blob_file.write_bytes(random.Random(0).randbytes(payload_bytes))
    try:
        with tarfile.open(dest, "w:gz") as tf:
            tf.add(comment_file, arcname="+COMMENT")
            tf.add(blob_file, arcname="payload.bin")
    finally:
        comment_file.unlink(missing_ok=True)
        blob_file.unlink(missing_ok=True)
    return dest, hashlib.md5(dest.read_bytes(), usedforsecurity=False).hexdigest()


class _TimeoutHttpCopyTransport(FakeJunosTransport):
    def run_command(self, command: str, read_timeout: int = 60) -> str:
        if command.strip().startswith("file copy "):
            self.commands_executed.append(command)
            raise TimeoutError("HTTP copy timed out")
        return super().run_command(command, read_timeout=read_timeout)


class _CustomSoftwareAddTransport(FakeJunosTransport):
    software_add_output: str = ""

    def run_command(self, command: str, read_timeout: int = 60) -> str:
        if command.strip().startswith("request system software add "):
            self.commands_executed.append(command)
            return self.software_add_output
        return super().run_command(command, read_timeout=read_timeout)


def test_tmpfs_http_to_scp_fallback_and_partial_cleanup(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    local_pkg, md5_hex, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    )
    hop.checksum = md5_hex

    sw = _sw("TMPFS_FALLBACK_SW", ip="127.0.0.1")
    sw.free_storage_mb = 437
    sw.tmpfs_free_mb = 908

    with UnifiedFirmwareServer(firmware_dir=fw_dir, port=0, bind_host="127.0.0.1") as srv:
        tr_fail = FakeJunosTransport(
            sw.hostname,
            sw.model,
            sw.serial_number,
            sw.current_version,
            free_storage_mb=437,
            tmpfs_free_mb=908,
            fail_http_copy=True,
        )
        out_fail = stage_or_stream_package(
            tr_fail, sw, pol, hop, fw_dir, srv, external_base_url="", transfer_mode="auto"
        )
        assert out_fail.mode_used == "scp-tmpfs"
        assert out_fail.uses_no_copy is True
        assert out_fail.remote_staged_path == f"/tmp/{hop.package_filename}"
        assert out_fail.software_add_target == f"/tmp/{hop.package_filename}"
        assert f"file delete /tmp/{hop.package_filename}" in tr_fail.commands_executed
        assert tr_fail.scp_uploads == [(local_pkg, f"/tmp/{hop.package_filename}")]

        tr_timeout = _TimeoutHttpCopyTransport(
            sw.hostname,
            sw.model,
            sw.serial_number,
            sw.current_version,
            free_storage_mb=437,
            tmpfs_free_mb=908,
        )
        out_timeout = stage_or_stream_package(
            tr_timeout, sw, pol, hop, fw_dir, srv, external_base_url="", transfer_mode="auto"
        )
        assert out_timeout.mode_used == "scp-tmpfs"
        assert out_timeout.uses_no_copy is True
        assert out_timeout.remote_staged_path == f"/tmp/{hop.package_filename}"
        assert f"file delete /tmp/{hop.package_filename}" in tr_timeout.commands_executed
        assert tr_timeout.scp_uploads == [(local_pkg, f"/tmp/{hop.package_filename}")]


def test_two_phase_stage_idempotent_and_upgrade_reuses_tmpfs_no_copy(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    fw_dir = tmp_path / "fw"

    # Case A: EX3400 (prefer_http_stream=False) two-phase stage -> idempotent stage -> upgrade
    pol34 = match_platform_policy("ex3400-48p", policies)
    assert pol34 is not None
    hop34 = pol34.hops[-1]
    _, md5_34, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex3400" / hop34.train / hop34.package_filename
    )
    hop34.checksum = md5_34

    sw34 = _sw("EX3400_TMPFS", model="ex3400-48p", version="23.2R2-S3", ip="127.0.0.1")
    tr34 = FakeJunosTransport(
        sw34.hostname,
        sw34.model,
        sw34.serial_number,
        "23.2R2-S3",
        free_storage_mb=437,
        tmpfs_free_mb=908,
        checksums_by_filename={hop34.package_filename: md5_34},
    )

    with UnifiedFirmwareServer(firmware_dir=fw_dir, port=0, bind_host="127.0.0.1") as srv:
        stage_opts = _fast_opts(base_url, tmp_path, fw_dir, stage_only=True)
        staged1 = upgrade_single_switch(sw34, pol34, exclusions, policies, tr34, stage_opts, server=srv)
        assert staged1.state == SwitchState.STAGED
        assert staged1.staged_package == f"/tmp/{hop34.package_filename}"
        assert any(
            c.startswith("file copy ") and c.endswith(f"/tmp/{hop34.package_filename}")
            for c in tr34.commands_executed
        )
        assert "request system reboot" not in tr34.commands_executed

        # Idempotent second stage_only=True even if tmpfs_free_mb dropped below threshold
        tr34.commands_executed.clear()
        tr34.scp_uploads.clear()
        tr34.tmpfs_free_mb = 20
        staged2 = upgrade_single_switch(
            staged1, pol34, exclusions, policies, tr34, stage_opts, server=srv
        )
        assert staged2.state == SwitchState.STAGED
        assert staged2.staged_package == f"/tmp/{hop34.package_filename}"
        assert f"file checksum md5 /tmp/{hop34.package_filename}" in tr34.commands_executed
        assert not any(c.startswith("file copy ") for c in tr34.commands_executed)
        assert tr34.scp_uploads == []

        # Phase 2 upgrade reuses /tmp/<pkg>.tgz with `no-copy unlink`
        tr34.commands_executed.clear()
        tr34.scp_uploads.clear()
        up_opts = _fast_opts(base_url, tmp_path, fw_dir, auto_cleanup=True)
        final34 = upgrade_single_switch(staged2, pol34, exclusions, policies, tr34, up_opts, server=srv)
        assert final34.state == SwitchState.COMPLETED
        assert final34.hop_history[0]["transfer_mode"] == "pre-staged"
        assert not any(c.startswith("file copy ") for c in tr34.commands_executed)
        assert tr34.scp_uploads == []
        assert (
            f"request system software add /tmp/{hop34.package_filename} no-copy unlink"
            in tr34.commands_executed
        )
        assert "request system reboot" in tr34.commands_executed

    # Case B: EX2300 (prefer_http_stream=True) idempotent second stage_only=True when tmpfs drops
    pol23 = match_platform_policy("ex2300-c-12p", policies)
    assert pol23 is not None
    hop23 = pol23.hops[-1]
    _, md5_23, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex2300" / hop23.train / hop23.package_filename
    )
    hop23.checksum = md5_23

    sw23 = _sw("EX2300_TMPFS", model="ex2300-c-12p", version="23.4R2.13", ip="127.0.0.1")
    tr23 = FakeJunosTransport(
        sw23.hostname,
        sw23.model,
        sw23.serial_number,
        "23.4R2.13",
        free_storage_mb=306,
        tmpfs_free_mb=908,
        checksums_by_filename={hop23.package_filename: md5_23},
    )
    with UnifiedFirmwareServer(firmware_dir=fw_dir, port=0, bind_host="127.0.0.1") as srv:
        stage_opts = _fast_opts(base_url, tmp_path, fw_dir, stage_only=True)
        staged23_1 = upgrade_single_switch(
            sw23, pol23, exclusions, policies, tr23, stage_opts, server=srv
        )
        assert staged23_1.state == SwitchState.STAGED
        assert staged23_1.staged_package == f"/tmp/{hop23.package_filename}"

        tr23.commands_executed.clear()
        tr23.tmpfs_free_mb = 20
        staged23_2 = upgrade_single_switch(
            staged23_1, pol23, exclusions, policies, tr23, stage_opts, server=srv
        )
        assert staged23_2.state == SwitchState.STAGED
        assert staged23_2.staged_package == f"/tmp/{hop23.package_filename}"
        assert f"file checksum md5 /tmp/{hop23.package_filename}" in tr23.commands_executed
        assert not any(c.startswith("file copy ") for c in tr23.commands_executed)


@pytest.mark.parametrize("large_pkg", [False, True])
def test_insufficient_tmpfs_boundary_falls_back_to_http_stream_or_var_tmp(
    tmp_path: Path, large_pkg: bool
) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    fw_dir = tmp_path / "fw"

    pol23 = match_platform_policy("ex2300-c-12p", policies)
    assert pol23 is not None
    hop23 = pol23.hops[-1]
    pkg23_path = fw_dir / "juniper" / "ex2300" / hop23.train / hop23.package_filename
    if large_pkg:
        _, md5_23 = _create_large_valid_tgz(pkg23_path, 2 * 1024 * 1024 + 65536)
    else:
        _, md5_23, _ = create_valid_tgz(pkg23_path)
    hop23.checksum = md5_23
    pkg23_mb_int = int(pkg23_path.stat().st_size / (1024 * 1024))
    assert pkg23_mb_int == (2 if large_pkg else 0)

    pol34 = match_platform_policy("ex3400-48p", policies)
    assert pol34 is not None
    hop34 = pol34.hops[-1]
    pkg34_path = fw_dir / "juniper" / "ex3400" / hop34.train / hop34.package_filename
    if large_pkg:
        _, md5_34 = _create_large_valid_tgz(pkg34_path, 2 * 1024 * 1024 + 65536)
    else:
        _, md5_34, _ = create_valid_tgz(pkg34_path)
    hop34.checksum = md5_34
    pkg34_mb_int = int(pkg34_path.stat().st_size / (1024 * 1024))

    with UnifiedFirmwareServer(firmware_dir=fw_dir, port=0, bind_host="127.0.0.1") as srv:
        # EX2300 (prefer_http_stream=True): +63 -> http-stream; +64 -> http-tmpfs
        sw23 = _sw("EX2300_BOUND", model="ex2300-c-12p", version="23.4R2.13", ip="127.0.0.1")
        sw23.free_storage_mb = 306
        sw23.tmpfs_free_mb = pkg23_mb_int + 63
        tr23 = FakeJunosTransport(sw23.hostname, sw23.model, sw23.serial_number, "23.4R2.13")
        out23_low = stage_or_stream_package(
            tr23, sw23, pol23, hop23, fw_dir, srv, external_base_url="", transfer_mode="auto"
        )
        assert out23_low.mode_used == "http-stream"
        assert out23_low.uses_no_copy is True
        assert out23_low.software_add_target.startswith("http://")
        assert out23_low.remote_staged_path == ""

        sw23.tmpfs_free_mb = pkg23_mb_int + 64
        out23_ok = stage_or_stream_package(
            tr23, sw23, pol23, hop23, fw_dir, srv, external_base_url="", transfer_mode="auto"
        )
        assert out23_ok.mode_used == "http-tmpfs"
        assert out23_ok.uses_no_copy is True
        assert out23_ok.remote_staged_path == f"/tmp/{hop23.package_filename}"

        # EX3400 (prefer_http_stream=False): +63 -> /var/tmp/; +64 -> /tmp/
        sw34 = _sw("EX3400_BOUND", model="ex3400-48p", version="23.2R2-S3", ip="127.0.0.1")
        sw34.free_storage_mb = 437
        sw34.tmpfs_free_mb = pkg34_mb_int + 63
        tr34 = FakeJunosTransport(sw34.hostname, sw34.model, sw34.serial_number, "23.2R2-S3")
        out34_low = stage_or_stream_package(
            tr34, sw34, pol34, hop34, fw_dir, srv, external_base_url="", transfer_mode="auto"
        )
        assert out34_low.mode_used == "http-copy"
        assert out34_low.uses_no_copy is False
        assert out34_low.remote_staged_path == f"/var/tmp/{hop34.package_filename}"

        sw34.tmpfs_free_mb = pkg34_mb_int + 64
        out34_ok = stage_or_stream_package(
            tr34, sw34, pol34, hop34, fw_dir, srv, external_base_url="", transfer_mode="auto"
        )
        assert out34_ok.mode_used == "http-tmpfs"
        assert out34_ok.uses_no_copy is True
        assert out34_ok.remote_staged_path == f"/tmp/{hop34.package_filename}"


@pytest.mark.parametrize(
    "fail_out",
    ["ERROR: Installation failed", "not enough space on /tmp", ""],
)
@pytest.mark.parametrize("staged_dir", ["/tmp", "/var/tmp"])
def test_install_failure_cleans_up_tmp_and_var_tmp(
    fail_out: str, staged_dir: str
) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]
    staged_path = f"{staged_dir}/{hop.package_filename}"

    tr = _CustomSoftwareAddTransport("EX3400_FAIL", "ex3400-48p", "SN_FAIL", "23.2R2-S3")
    tr.software_add_output = fail_out
    outcome = TransferOutcome(
        mode_used="http-tmpfs" if staged_dir == "/tmp" else "http-copy",
        software_add_target=staged_path,
        uses_no_copy=(staged_dir == "/tmp"),
        remote_staged_path=staged_path,
    )
    ok, msg = JunosSwitchDriver().install_and_reboot(tr, hop, outcome)
    assert ok is False
    assert msg
    assert f"file delete {staged_path}" in tr.commands_executed
    assert "request system reboot" not in tr.commands_executed


def test_http_stream_install_failure_skips_file_delete_and_checksum_failure_cleans_up(
    tmp_path: Path,
) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    # 1. http-stream install failure must NOT issue file delete
    tr_stream = _CustomSoftwareAddTransport("STREAM_FAIL", "ex2300-c-12p", "SN_SF", "23.4R2.13")
    tr_stream.software_add_output = "ERROR: fetch failed"
    stream_outcome = TransferOutcome(
        mode_used="http-stream",
        software_add_target=f"http://192.0.2.5:8080/{hop.package_filename}",
        uses_no_copy=True,
        remote_staged_path="",
    )
    ok_stream, _ = JunosSwitchDriver().install_and_reboot(tr_stream, hop, stream_outcome)
    assert ok_stream is False
    assert not any(c.startswith("file delete ") for c in tr_stream.commands_executed)

    # 2. Orchestrator checksum failure cleans up newly staged /tmp and /var/tmp in both stage_only modes
    fw_dir = tmp_path / "fw"
    _, md5_hex, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    )
    hop.checksum = md5_hex

    for stage_only in (True, False):
        for use_tmpfs in (True, False):
            sw = _sw(f"CHK_FAIL_{stage_only}_{use_tmpfs}", version="23.2R2-S3", ip="127.0.0.1")
            tr = FakeJunosTransport(
                sw.hostname,
                sw.model,
                sw.serial_number,
                "23.2R2-S3",
                free_storage_mb=437 if use_tmpfs else 1200,
                tmpfs_free_mb=908 if use_tmpfs else None,
                fail_http_copy=True,
                checksum_override="f" * 32,
            )
            opts = _fast_opts(base_url, tmp_path / f"run_{stage_only}_{use_tmpfs}", fw_dir, stage_only=stage_only)
            res = upgrade_single_switch(sw, pol, exclusions, policies, tr, opts)
            expected_path = (
                f"/tmp/{hop.package_filename}" if use_tmpfs else f"/var/tmp/{hop.package_filename}"
            )
            assert res.state == SwitchState.FAILED
            assert res.staged_package == ""
            assert res.staged_checksum == ""
            assert f"file delete {expected_path}" in tr.commands_executed

    # 3. Pre-staged corrupt file is cleaned up on verify_staged_checksum failure before re-staging
    sw_pre = _sw("PRESET_CORRUPT", version="23.2R2-S3", ip="127.0.0.1")
    sw_pre.staged_package = f"/tmp/{hop.package_filename}"
    sw_pre.staged_checksum = "a" * 32
    tr_pre = FakeJunosTransport(
        sw_pre.hostname,
        sw_pre.model,
        sw_pre.serial_number,
        "23.2R2-S3",
        free_storage_mb=1200,
        tmpfs_free_mb=None,
        fail_http_copy=True,
        checksum_override="f" * 32,
    )
    opts_pre = _fast_opts(base_url, tmp_path / "run_pre", fw_dir, stage_only=False)
    res_pre = upgrade_single_switch(sw_pre, pol, exclusions, policies, tr_pre, opts_pre)
    assert res_pre.state == SwitchState.FAILED
    assert f"file delete /tmp/{hop.package_filename}" in tr_pre.commands_executed
    assert f"file delete /var/tmp/{hop.package_filename}" in tr_pre.commands_executed


def test_veriexec_auth_error_with_pending_notice_succeeds() -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]
    staged_path = f"/tmp/{hop.package_filename}"
    outcome = TransferOutcome(
        mode_used="http-tmpfs",
        software_add_target=staged_path,
        uses_no_copy=True,
        remote_staged_path=staged_path,
    )

    # Variant A: colon Authentication error + pending notice
    tr_a = _CustomSoftwareAddTransport("VERI_A", "ex3400-48p", "SN_VA", "23.2R2-S3")
    tr_a.software_add_output = (
        "veriexec: /packages/sets/pending/boot/loader.efi: Authentication error\n"
        "NOTICE: 'pending' set will be activated at next reboot.\n"
    )
    ok_a, _ = JunosSwitchDriver().install_and_reboot(tr_a, hop, outcome)
    assert ok_a is True
    assert "request system reboot" in tr_a.commands_executed
    assert f"file delete {staged_path}" not in tr_a.commands_executed

    # Variant B: `cannot open` + `error:` inside veriexec line + pending notice
    tr_b = _CustomSoftwareAddTransport("VERI_B", "ex3400-48p", "SN_VB", "23.2R2-S3")
    tr_b.software_add_output = (
        "veriexec: cannot open /packages/sets/pending/boot/loader.efi: error: Authentication error\n"
        "NOTICE: 'pending' set will be activated at next reboot.\n"
    )
    ok_b, _ = JunosSwitchDriver().install_and_reboot(tr_b, hop, outcome)
    assert ok_b is True
    assert "request system reboot" in tr_b.commands_executed

    # Negative control 1: pending notice absent -> veriexec error fails closed
    tr_neg1 = _CustomSoftwareAddTransport("VERI_NEG1", "ex3400-48p", "SN_VN1", "23.2R2-S3")
    tr_neg1.software_add_output = (
        "veriexec: /packages/sets/pending/boot/loader.efi: error: Authentication error\n"
    )
    ok_neg1, _ = JunosSwitchDriver().install_and_reboot(tr_neg1, hop, outcome)
    assert ok_neg1 is False
    assert "request system reboot" not in tr_neg1.commands_executed
    assert f"file delete {staged_path}" in tr_neg1.commands_executed

    # Negative control 2: pending notice present alongside real ERROR: -> fails closed
    tr_neg2 = _CustomSoftwareAddTransport("VERI_NEG2", "ex3400-48p", "SN_VN2", "23.2R2-S3")
    tr_neg2.software_add_output = (
        "veriexec: /packages/sets/pending/boot/loader.efi: Authentication error\n"
        "NOTICE: 'pending' set will be activated at next reboot.\n"
        "ERROR: Installation failed\n"
    )
    ok_neg2, _ = JunosSwitchDriver().install_and_reboot(tr_neg2, hop, outcome)
    assert ok_neg2 is False
    assert "request system reboot" not in tr_neg2.commands_executed
    assert f"file delete {staged_path}" in tr_neg2.commands_executed

    # Negative control 3: Variant A exact Authentication error line WITHOUT NOTICE -> fails closed
    tr_neg3 = _CustomSoftwareAddTransport("VERI_NEG3", "ex3400-48p", "SN_VN3", "23.2R2-S3")
    tr_neg3.software_add_output = (
        "veriexec: /packages/sets/pending/boot/loader.efi: Authentication error\n"
    )
    ok_neg3, _ = JunosSwitchDriver().install_and_reboot(tr_neg3, hop, outcome)
    assert ok_neg3 is False
    assert "request system reboot" not in tr_neg3.commands_executed
    assert f"file delete {staged_path}" in tr_neg3.commands_executed


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "/tmp/../etc/passwd",
        "/tmp/pkg.tgz;reboot",
        "/var/tmp/",
        "/tmp/",
        "/tmp/sub/junos-arm-32-23.4R2-S8.tgz",
        "/tmp/./junos-arm-32-23.4R2-S8.tgz",
        "/tmp/not_a_package.txt",
    ],
)
def test_unsafe_remote_staged_path_skips_file_delete(unsafe_path: str) -> None:
    from junos_upgrader.orchestrator import _cleanup_remote_staged

    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    tr = _CustomSoftwareAddTransport("UNSAFE_DEL", "ex3400-48p", "SN_UD", "23.2R2-S3")
    tr.software_add_output = "ERROR: Installation failed"
    bad_outcome = TransferOutcome(
        mode_used="http-tmpfs",
        software_add_target=f"/tmp/{hop.package_filename}",
        uses_no_copy=True,
        remote_staged_path=unsafe_path,
    )
    ok, _ = JunosSwitchDriver().install_and_reboot(tr, hop, bad_outcome)
    assert ok is False
    assert "request system reboot" not in tr.commands_executed
    assert not any(c.startswith("file delete ") for c in tr.commands_executed)

    tr_clean = FakeJunosTransport("UNSAFE_ORCH", "ex3400-48p", "SN_UO", "23.2R2-S3")
    _cleanup_remote_staged(tr_clean, unsafe_path)
    assert tr_clean.commands_executed == []
