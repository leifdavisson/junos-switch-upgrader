# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for v0.3.0 engineering upgrades: staging, fast deltas, PoE/MAC/LACP, recovery.txt, landmines, and train-pinned scan."""

from __future__ import annotations

from pathlib import Path

from conftest import FakeJunosTransport, create_valid_tgz

from junos_upgrader.checks import (
    BASELINE_COMMANDS,
    FAST_DELTA_COMMANDS,
    check_config_landmines,
    generate_recovery_sheet,
    run_postchecks,
    run_prechecks,
)
from junos_upgrader.drivers import get_driver
from junos_upgrader.firmware_fetcher import scan_and_ingest_directory
from junos_upgrader.models import SwitchRecord, SwitchState
from junos_upgrader.orchestrator import UpgradeOptions, upgrade_single_switch
from junos_upgrader.planner import load_release_catalog, match_platform_policy

RELEASES_YML = Path(__file__).resolve().parents[1] / "manifests" / "approved-releases.yml"


def _make_sw(hostname: str, model: str, version: str, role: str = "Access") -> SwitchRecord:
    return SwitchRecord(
        site="SITE",
        hostname=hostname,
        management_ip="192.0.2.10",
        model=model,
        serial_number="SN10001",
        current_version=version,
        role=role,
        management_method="SSH",
        state=SwitchState.READY,
    )


def test_two_phase_stage_then_upgrade_reuses_staged_package(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    # Put switch 1 hop away from final target to test stage -> upgrade reuse cleanly
    sw = _make_sw("IDF_STAGE_01", "ex3400-48p", "23.2R2-S3")
    fw_dir = tmp_path / "firmware"
    hop = pol.hops[-1]
    pkg_path = fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    _, md5_hex, _ = create_valid_tgz(pkg_path, comment="arm-32")
    hop.checksum = md5_hex

    transport = FakeJunosTransport(
        hostname=sw.hostname,
        model=sw.model,
        serial_number=sw.serial_number,
        running_version="23.2R2-S3",
        fail_http_copy=True,  # SCP copies during stage phase
        go_down_polls=2,
        checksums_by_filename={hop.package_filename: md5_hex},
    )

    stage_opts = UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=fw_dir,
        evidence_root=tmp_path / "evidence",
        config_root=tmp_path / "configs",
        manifest_path=tmp_path / "manifest.json",
        change_number="STAGE1",
        operator="netops",
        stage_only=True,
        require_release_notes=False,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
    )
    staged = upgrade_single_switch(sw, pol, exclusions, policies, transport, stage_opts)
    assert staged.state == SwitchState.STAGED
    assert staged.staged_package == f"/var/tmp/{hop.package_filename}"
    assert len(transport.scp_uploads) == 1
    assert "request system reboot" not in transport.commands_executed

    # Also verify recovery.txt was written in stage phase
    rec_file = tmp_path / "configs" / "SITE" / "IDF_STAGE_01" / "recovery.txt"
    assert rec_file.exists()
    rec_text = rec_file.read_text(encoding="utf-8")
    assert "192.0.2.10" in rec_text
    assert "255.255.255.0" in rec_text
    assert "192.0.2.1" in rec_text

    # Phase 2: upgrade reuses /var/tmp package without re-uploading via SCP!
    transport.scp_uploads.clear()
    up_opts = UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=fw_dir,
        evidence_root=tmp_path / "evidence",
        config_root=tmp_path / "configs",
        manifest_path=tmp_path / "manifest.json",
        change_number="MAINT1",
        operator="netops",
        require_release_notes=False,
        refresh_snapshot=True,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=1.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
    )
    final = upgrade_single_switch(staged, pol, exclusions, policies, transport, up_opts)
    assert final.state == SwitchState.COMPLETED
    assert final.current_version == "23.4R2-S8"
    assert final.recovery_snapshot == "23.4R2-S8"
    assert len(transport.scp_uploads) == 0
    assert final.hop_history[0]["transfer_mode"] == "pre-staged"
    assert "request system snapshot recovery" in transport.commands_executed
    # Post-upgrade recovery.txt reflects the updated current_version
    assert "Version at Backup: 23.4R2-S8" in rec_file.read_text(encoding="utf-8")


def test_fast_intermediate_delta_vs_full_hop_baseline(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    # 2 hops: 22.2R3-S5 -> 23.2R2-S3 -> 23.4R2-S8
    sw = _make_sw("IDF_FAST_01", "ex3400-48p", "22.2R3-S5")
    fw_dir = tmp_path / "firmware"
    checksums: dict[str, str] = {}
    for hop in pol.hops[-2:]:
        pkg_path = fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
        _, md5_hex, _ = create_valid_tgz(pkg_path, comment="arm-32")
        hop.checksum = md5_hex
        checksums[hop.package_filename] = md5_hex

    transport = FakeJunosTransport(
        hostname=sw.hostname,
        model=sw.model,
        serial_number=sw.serial_number,
        running_version="22.2R3-S5",
        fail_http_copy=True,
        checksums_by_filename=checksums,
    )
    opts = UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=fw_dir,
        evidence_root=tmp_path / "evidence",
        config_root=tmp_path / "configs",
        manifest_path=tmp_path / "manifest.json",
        change_number="FAST1",
        operator="netops",
        fast_intermediate_hops=True,
        require_release_notes=False,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
    )
    res = upgrade_single_switch(sw, pol, exclusions, policies, transport, opts)
    assert res.state == SwitchState.COMPLETED

    hop1_pre = tmp_path / "evidence" / "SITE" / "FAST1" / "IDF_FAST_01" / "hop_1_23.2R2-S3" / "pre"
    hop1_post = (
        tmp_path / "evidence" / "SITE" / "FAST1" / "IDF_FAST_01" / "hop_1_23.2R2-S3" / "post"
    )
    hop2_post = (
        tmp_path / "evidence" / "SITE" / "FAST1" / "IDF_FAST_01" / "hop_2_23.4R2-S8" / "post"
    )
    cfg_hop1_post = tmp_path / "configs" / "SITE" / "IDF_FAST_01" / "post" / "hop_1_23.2R2-S3"
    cfg_hop2_post = tmp_path / "configs" / "SITE" / "IDF_FAST_01" / "post" / "hop_2_23.4R2-S8"

    # Hop 1 Pre & Final Post get full baseline (includes show_interfaces_extensive.txt); intermediate Hop 1 Post gets fast delta!
    assert (hop1_pre / "show_interfaces_extensive.txt").exists()
    assert not (hop1_post / "show_interfaces_extensive.txt").exists()
    assert (hop1_post / "show_poe_controller.txt").exists()
    assert (hop2_post / "show_interfaces_extensive.txt").exists()
    assert len(FAST_DELTA_COMMANDS) < len(BASELINE_COMMANDS)
    # Fast intermediate hop must NOT write an empty 0-byte config.hierarchical.txt
    assert not (cfg_hop1_post / "config.hierarchical.txt").exists()
    assert (cfg_hop2_post / "config.hierarchical.txt").stat().st_size > 0


def test_poe_mac_lacp_postchecks_and_core_console_gate(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    # Postcheck catches PoE collapse, empty MAC table, and LACP member loss
    pre_tr = FakeJunosTransport(
        "SW1",
        "ex3400-48p",
        "SN1",
        "23.2R2-S3",
        poe_watts_pre=45.0,
        mac_count_pre=5,
        lacp_up_pre=["xe-0/2/0"],
    )
    post_tr = FakeJunosTransport(
        "SW1",
        "ex3400-48p",
        "SN1",
        "23.4R2-S8",
        poe_watts_pre=0.0,
        mac_count_pre=0,
        lacp_up_pre=[],
    )

    drv = get_driver("juniper")
    pre_base = drv.collect_baseline(pre_tr, tmp_path / "pre", fast_delta=True)
    post_base = drv.collect_baseline(post_tr, tmp_path / "post", fast_delta=True)
    results = run_postchecks(pre_base, post_base, expected_version="23.4R2-S8")
    failed_names = {r.name for r in results if not r.passed and r.hard_stop}
    assert {
        "poe_delivery_preserved",
        "mac_table_repopulated",
        "lacp_bundles_preserved",
    } <= failed_names

    # Core console_port gate blocks when empty unless allow_no_console=True
    core_sw = _make_sw("MDF_CORE_01", "ex4600-40f", "20.4R3-S10", role="Core")
    core_pol = match_platform_policy("ex4600-40f", policies)
    assert core_pol is not None
    core_tr = FakeJunosTransport(
        "MDF_CORE_01",
        "ex4600-40f",
        "SN10001",
        "20.4R3-S10",
        pkg_arch_tag="jinstall-host-qfx-5",
        free_storage_mb=2000,
        config_set_extra="set system services ssh ciphers aes128-cbc\nset system services telnet",
    )
    checks_blocked = run_prechecks(
        core_tr,
        core_sw,
        core_pol,
        core_pol.hops[-1],
        tmp_path / "ev_core",
        tmp_path / "cfg_core",
        require_release_notes=False,
        allow_no_console=False,
    )
    assert any(c.name == "console_access" and not c.passed and c.hard_stop for c in checks_blocked)
    assert any(
        c.name == "config_landmines" and not c.passed and not c.hard_stop for c in checks_blocked
    )

    checks_allowed = run_prechecks(
        core_tr,
        core_sw,
        core_pol,
        core_pol.hops[-1],
        tmp_path / "ev_core2",
        tmp_path / "cfg_core2",
        require_release_notes=False,
        allow_no_console=True,
    )
    assert not any(c.name == "console_access" and c.hard_stop for c in checks_allowed)

    # Config landmines standalone helper + recovery sheet for VMHost platform
    warns = check_config_landmines("set ethernet-switching-options storm-control interface all")
    assert any(w.severity == "warn" and "ethernet-switching-options" in w.message for w in warns)
    rec = generate_recovery_sheet(core_sw, core_pol, pre_base, tmp_path / "core_recovery.txt")
    assert "VMHost" in rec.read_text(encoding="utf-8")


def test_train_pinned_scan_updates_all_matching_arm32_policies(tmp_path: Path) -> None:
    rel_copy = tmp_path / "approved-releases.yml"
    rel_copy.write_text(RELEASES_YML.read_text(encoding="utf-8"), encoding="utf-8")
    _, policies, _ = load_release_catalog(rel_copy)

    scan_dir = tmp_path / "downloads"
    fw_dir = tmp_path / "firmware"
    scan_dir.mkdir()

    # Newer service release 23.4R2-S9 should train-match ex2300-*mp*, ex2300*, and ex3400*!
    create_valid_tgz(scan_dir / "junos-arm-32-23.4R2-S9.tgz", comment="arm-32")

    res = scan_and_ingest_directory(scan_dir, fw_dir, rel_copy, policies, update_manifest=True)
    assert res[0]["status"] == "ingested"
    assert int(res[0]["platforms_updated"]) == 3

    _, updated_policies, _ = load_release_catalog(rel_copy)
    for model in ("ex2300-c-12p", "ex2300-24mp", "ex3400-48p"):
        p = match_platform_policy(model, updated_policies)
        assert p is not None
        assert p.final_target == "23.4R2-S9"
        assert p.hops[-1].package_filename == "junos-arm-32-23.4R2-S9.tgz"


def test_create_latest_bleeding_edge_manifest_and_bumper(tmp_path: Path) -> None:
    from junos_upgrader.firmware_fetcher import generate_bleeding_edge_manifest

    dl = tmp_path / "downloads"
    fw = tmp_path / "firmware"
    out_yml = tmp_path / "bleeding-edge.yml"
    dl.mkdir()

    # Create 24.4R2.23 and 25.2R2.12 .tgz archives
    for fname in ("junos-arm-32-24.4R2.23.tgz", "junos-arm-32-25.2R2.12.tgz"):
        create_valid_tgz(dl / fname, comment="arm-32")

    summary = generate_bleeding_edge_manifest([dl], RELEASES_YML, fw, out_yml)
    assert out_yml.exists()
    assert len(summary["added_hops"]) == 6  # 2 hops x 3 arm-32 policies
    assert not summary["gap_warnings"]  # 23.4 -> 24.4 (4q) -> 25.2 (2q) is within max_train_gap=4

    base_url, b_policies, b_excl = load_release_catalog(out_yml)
    pol2300 = match_platform_policy("ex2300-c-12p", b_policies)
    assert pol2300 is not None
    assert pol2300.bleeding_edge is True
    assert pol2300.jtac_baseline == "23.4R2-S8"
    assert pol2300.final_target == "25.2R2.12"

    # Bumper: live upgrade without accept_bleeding_edge=True must hard-stop!
    sw = _make_sw("LAB_EX2300", "ex2300-c-12p", "23.4R2.13")
    tr = FakeJunosTransport(
        "LAB_EX2300", "ex2300-c-12p", "SN10001", "23.4R2.13", free_storage_mb=306
    )
    opts_blocked = UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=fw,
        evidence_root=tmp_path / "ev",
        config_root=tmp_path / "cfg",
        manifest_path=tmp_path / "manifest.json",
        change_number="BLEED1",
        operator="netops",
        require_release_notes=False,
        accept_bleeding_edge=False,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
    )
    res = upgrade_single_switch(sw, pol2300, b_excl, b_policies, tr, opts_blocked)
    assert res.state == SwitchState.FAILED
    assert "--accept-bleeding-edge" in res.last_error
