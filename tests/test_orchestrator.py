# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for multi-hop upgrade execution, HTTP streaming, SCP fallback, and failure paths."""

from __future__ import annotations

import urllib.request
from pathlib import Path

from conftest import FakeJunosTransport, create_valid_tgz

from junos_upgrader.models import SwitchRecord, SwitchState
from junos_upgrader.orchestrator import UpgradeOptions, upgrade_single_switch
from junos_upgrader.planner import load_release_catalog, match_platform_policy
from junos_upgrader.transfer import UnifiedFirmwareServer

RELEASES_YML = Path(__file__).resolve().parents[1] / "manifests" / "approved-releases.yml"


def _make_switch(
    hostname: str,
    model: str,
    version: str,
    ip: str = "127.0.0.1",
) -> SwitchRecord:
    return SwitchRecord(
        site="LAB",
        hostname=hostname,
        management_ip=ip,
        model=model,
        serial_number="SN123456",
        current_version=version,
        role="Access",
        management_method="SSH",
        state=SwitchState.READY,
    )


def _fast_opts(
    base_url: str,
    tmp_path: Path,
    fw_dir: Path,
    change_number: str = "CHG001",
    **extra: object,
) -> UpgradeOptions:
    return UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=fw_dir,
        evidence_root=tmp_path / "evidence",
        config_root=tmp_path / "configs",
        manifest_path=tmp_path / "manifest.json",
        change_number=change_number,
        operator="netops",
        require_release_notes=False,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
        **extra,  # type: ignore[arg-type]
    )


def test_ex3400_full_multihop_with_scp_fallback(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    fw_dir = tmp_path / "firmware"
    checksums: dict[str, str] = {}
    for hop in pol.hops:
        pkg_path = fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
        _, md5_hex, _ = create_valid_tgz(pkg_path, comment="arm-32")
        hop.checksum = md5_hex
        checksums[hop.package_filename] = md5_hex

    sw = _make_switch("CAMPUS_IDF_A_SW_01", "ex3400-48p", "18.1R3-S4.2")
    transport = FakeJunosTransport(
        hostname=sw.hostname,
        model=sw.model,
        serial_number=sw.serial_number,
        running_version=sw.current_version,
        fail_http_copy=True,  # Forces automatic SCP fallback from same firmware_dir
        checksums_by_filename=checksums,
    )
    opts = _fast_opts(base_url, tmp_path, fw_dir, change_number="CHG001")

    result = upgrade_single_switch(sw, pol, exclusions, policies, transport, opts)
    assert result.state == SwitchState.COMPLETED
    assert result.current_version == "23.4R2-S8"
    assert len(result.hop_history) == 7
    assert len(transport.scp_uploads) == 7
    assert all(h["transfer_mode"] == "scp" for h in result.hop_history)


def test_ex2300_low_flash_uses_http_stream_no_copy_and_serves_real_tgz(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex2300-c-12p", policies)
    assert pol is not None

    fw_dir = tmp_path / "firmware"
    hop = pol.hops[-1]
    pkg_path = fw_dir / "juniper" / "ex2300" / hop.train / hop.package_filename
    _, md5_hex, _ = create_valid_tgz(pkg_path, comment="arm-32")
    hop.checksum = md5_hex

    sw = _make_switch("lab-ex2300c-01", "ex2300-c-12p", "23.4R2.13")
    transport = FakeJunosTransport(
        hostname=sw.hostname,
        model=sw.model,
        serial_number=sw.serial_number,
        running_version="23.4R2.13",
        free_storage_mb=306,  # Matches real /.mount on lab EX2300-C-12P
        checksums_by_filename={hop.package_filename: md5_hex},
    )
    opts = _fast_opts(base_url, tmp_path, fw_dir, change_number="CHG002")

    with UnifiedFirmwareServer(firmware_dir=fw_dir, port=0) as srv:
        result = upgrade_single_switch(sw, pol, exclusions, policies, transport, opts, server=srv)
        add_cmds = [
            c for c in transport.commands_executed if c.startswith("request system software add ")
        ]
        assert len(add_cmds) == 1
        stream_url = add_cmds[0].split()[4]
        assert f":{srv.port}/firmware/{srv.token}/" in stream_url
        assert "no-copy" in add_cmds[0] and "unlink" in add_cmds[0]

        # End-to-end check: actually fetch the generated HTTP stream URL from the live server!
        with urllib.request.urlopen(stream_url) as resp:
            assert resp.status == 200
            body = resp.read()
            assert body[:2] == b"\x1f\x8b"
            assert body == pkg_path.read_bytes()

    assert result.state == SwitchState.COMPLETED
    assert result.current_version == "23.4R2-S8"
    assert result.hop_history[0]["transfer_mode"] == "http-stream"


def test_placeholder_checksum_rejected_by_default_and_allowed_when_opted_in(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    fw_dir = tmp_path / "firmware"
    hop = pol.hops[-1]
    assert "REPLACE" in hop.checksum
    create_valid_tgz(fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename)

    sw = _make_switch("PLACEHOLDER_SW", "ex3400-48p", "23.2R2-S3", ip="192.0.2.20")
    tr = FakeJunosTransport(sw.hostname, sw.model, sw.serial_number, "23.2R2-S3")
    opts_strict = _fast_opts(base_url, tmp_path, fw_dir, change_number="CHG_STRICT")
    res_blocked = upgrade_single_switch(sw, pol, exclusions, policies, tr, opts_strict)
    assert res_blocked.state == SwitchState.FAILED
    assert "request system reboot" not in tr.commands_executed

    # Explicitly opting in with allow_unverified_checksums=True permits placeholder checksums
    sw_opt = _make_switch("PLACEHOLDER_OPT", "ex3400-48p", "23.2R2-S3", ip="192.0.2.21")
    tr_opt = FakeJunosTransport(
        sw_opt.hostname, sw_opt.model, sw_opt.serial_number, "23.2R2-S3", fail_http_copy=True
    )
    opts_allow = _fast_opts(
        base_url, tmp_path, fw_dir, change_number="CHG_ALLOW", allow_unverified_checksums=True
    )
    res_ok = upgrade_single_switch(sw_opt, pol, exclusions, policies, tr_opt, opts_allow)
    assert res_ok.state == SwitchState.COMPLETED


def test_dry_run_never_installs_reboots_or_mutates_switch(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex2300-c-12p", policies)
    assert pol is not None

    sw = _make_switch("lab-ex2300c-01", "ex2300-c-12p", "23.4R2.13")
    transport = FakeJunosTransport(
        hostname=sw.hostname,
        model=sw.model,
        serial_number=sw.serial_number,
        running_version="23.4R2.13",
        free_storage_mb=306,
    )
    opts = _fast_opts(base_url, tmp_path, tmp_path / "firmware", change_number="DRY1", dry_run=True)

    result = upgrade_single_switch(sw, pol, exclusions, policies, transport, opts)
    assert result.state == SwitchState.READY
    assert result.current_version == "23.4R2.13"
    assert not any(c.startswith("request system software add") for c in transport.commands_executed)
    assert "request system reboot" not in transport.commands_executed
    assert any(c == "request system storage cleanup dry-run" for c in transport.commands_executed)


def test_arch_mismatch_and_vc_hard_stops(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("qfx5200-32c", policies)
    assert pol is not None

    # 1. Evolved switch vs classical policy hard-stop
    sw = _make_switch("QFX_EVO", "qfx5200-32c", "21.4R3-S1", ip="192.0.2.30")
    transport = FakeJunosTransport(
        hostname=sw.hostname,
        model=sw.model,
        serial_number=sw.serial_number,
        running_version="21.4R3-S1",
        free_storage_mb=2000,
        pkg_arch_tag="junos-evo-install-qfx-x86-64",
    )
    opts = _fast_opts(base_url, tmp_path, tmp_path / "firmware", change_number="CHG_EVO")
    result = upgrade_single_switch(sw, pol, exclusions, policies, transport, opts)
    assert result.state == SwitchState.FAILED
    assert "Junos OS Evolved" in result.last_error

    # 2. Multi-member Virtual Chassis hard-stop
    pol_ex = match_platform_policy("ex3400-48p", policies)
    assert pol_ex is not None
    sw_vc = _make_switch("IDF_VC_01", "ex3400-48p", "23.2R2-S3", ip="192.0.2.31")
    tr_vc = FakeJunosTransport(
        hostname=sw_vc.hostname,
        model=sw_vc.model,
        serial_number=sw_vc.serial_number,
        running_version="23.2R2-S3",
        virtual_chassis=True,
    )
    res_vc = upgrade_single_switch(sw_vc, pol_ex, exclusions, policies, tr_vc, opts)
    assert res_vc.state == SwitchState.FAILED
    assert "Virtual Chassis" in res_vc.last_error


def test_failure_hooks_uncommitted_checksum_install_reboot_and_postcheck(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    fw_dir = tmp_path / "firmware"
    hop = pol.hops[-1]
    _, md5_hex, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    )
    hop.checksum = md5_hex
    opts = _fast_opts(base_url, tmp_path, fw_dir, change_number="CHG_FAILS")

    # 1. Pending commit confirmed / uncommitted state hard-stop
    sw1 = _make_switch("SW_UNCOMMIT", "ex3400-48p", "23.2R2-S3", ip="192.0.2.40")
    tr1 = FakeJunosTransport(
        sw1.hostname, sw1.model, sw1.serial_number, "23.2R2-S3", uncommitted_changes=True
    )
    res1 = upgrade_single_switch(sw1, pol, exclusions, policies, tr1, opts)
    assert res1.state == SwitchState.FAILED
    assert "Commit state" in res1.last_error

    # 2. Checksum mismatch on switch aborts before software add
    sw2 = _make_switch("SW_BADCHK", "ex3400-48p", "23.2R2-S3", ip="192.0.2.41")
    tr2 = FakeJunosTransport(
        sw2.hostname,
        sw2.model,
        sw2.serial_number,
        "23.2R2-S3",
        fail_http_copy=True,
        checksum_override="a" * 32,
    )
    res2 = upgrade_single_switch(sw2, pol, exclusions, policies, tr2, opts)
    assert res2.state == SwitchState.FAILED
    assert "Checksum mismatch" in res2.last_error
    assert not any(c.startswith("request system software add") for c in tr2.commands_executed)

    # 3. Install failure aborts without rebooting
    sw3 = _make_switch("SW_BADINST", "ex3400-48p", "23.2R2-S3", ip="192.0.2.42")
    tr3 = FakeJunosTransport(
        sw3.hostname,
        sw3.model,
        sw3.serial_number,
        "23.2R2-S3",
        fail_http_copy=True,
        fail_install=True,
        checksums_by_filename={hop.package_filename: md5_hex},
    )
    res3 = upgrade_single_switch(sw3, pol, exclusions, policies, tr3, opts)
    assert res3.state == SwitchState.FAILED
    assert "Software add failed" in res3.last_error
    assert "request system reboot" not in tr3.commands_executed

    # 4. Reboot timer expiry marks switch FAILED
    pol_short = match_platform_policy("ex3400-48p", policies)
    assert pol_short is not None
    pol_short.boot_timeout_seconds = 0
    sw4 = _make_switch("SW_NORETURN", "ex3400-48p", "23.2R2-S3", ip="192.0.2.43")
    tr4 = FakeJunosTransport(
        sw4.hostname,
        sw4.model,
        sw4.serial_number,
        "23.2R2-S3",
        fail_http_copy=True,
        fail_reboot=True,
        checksums_by_filename={hop.package_filename: md5_hex},
    )
    res4 = upgrade_single_switch(sw4, pol_short, exclusions, policies, tr4, opts)
    assert res4.state == SwitchState.FAILED
    assert "Reboot timer" in res4.last_error

    # 5. Full upgrade_single_switch postcheck failure (PoE/MAC/LACP drop) MUST NOT overwrite rescue config!
    sw5 = _make_switch("SW_BADPOST", "ex3400-48p", "23.2R2-S3", ip="192.0.2.44")
    tr5 = FakeJunosTransport(
        sw5.hostname,
        sw5.model,
        sw5.serial_number,
        "23.2R2-S3",
        fail_http_copy=True,
        checksums_by_filename={hop.package_filename: md5_hex},
        poe_watts_pre=45.0,
        poe_watts_post=0.0,
        mac_count_pre=6,
        mac_count_post=0,
        lacp_up_pre=["xe-0/2/0"],
        lacp_up_post=[],
    )
    res5 = upgrade_single_switch(sw5, pol, exclusions, policies, tr5, opts)
    assert res5.state == SwitchState.FAILED
    assert "PoE power delivery dropped" in res5.last_error
    assert "MAC table is empty" in res5.last_error
    assert "LACP member(s) failed" in res5.last_error
    # Rescue save was called once PRE-hop, and MUST NOT be called a second time after failed postcheck!
    assert tr5.commands_executed.count("request system configuration rescue save") == 1
