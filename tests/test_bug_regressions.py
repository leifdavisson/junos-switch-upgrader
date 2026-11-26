# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression tests for bug-hunter and Phase 2 audit fixes."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import TEST_ORIGIN, FakeJunosTransport, create_valid_tgz

from junos_upgrader.checks import evaluate_hardware_and_fs_triage
from junos_upgrader.cli import _filter_switches
from junos_upgrader.models import (
    NeighborExpectation,
    SwitchRecord,
    SwitchState,
    TriageVerdict,
)
from junos_upgrader.orchestrator import (
    UpgradeOptions,
    run_upgrade_batches,
    upgrade_single_switch,
)
from junos_upgrader.packages import validate_package_match
from junos_upgrader.planner import (
    compute_remaining_hops,
    load_release_catalog,
    match_platform_policy,
)
from junos_upgrader.topology import RunnerOrigin, build_topology_graph, redact_topology_graph
from junos_upgrader.transfer import stage_or_stream_package
from junos_upgrader.web_ui import render_topology_html

RELEASES_YML = Path(__file__).resolve().parents[1] / "manifests" / "approved-releases.yml"


def _make_sw(
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


def test_phase2_upgrade_preserves_prestaged_tgz_and_cleans_stale(tmp_path: Path) -> None:
    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    hop = pol.hops[-1]
    fw_dir = tmp_path / "firmware"
    pkg_path = fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    _, md5_hex, _ = create_valid_tgz(pkg_path, comment="arm-32")
    hop.checksum = md5_hex

    sw = _make_sw("IDF_STAGE_KEEP", "ex3400-48p", "23.2R2-S3")
    sw.state = SwitchState.STAGED
    sw.staged_package = f"/var/tmp/{hop.package_filename}"

    transport = FakeJunosTransport(
        hostname=sw.hostname,
        model=sw.model,
        serial_number=sw.serial_number,
        running_version="23.2R2-S3",
        checksums_by_filename={hop.package_filename: md5_hex},
        var_tmp_output=(
            f"-rw-r--r-- 1 root wheel 250000000 Nov 24 12:00 {hop.package_filename}\n"
            "-rw-r--r-- 1 root wheel 200000000 Nov 01 12:00 old-stale-image.tgz\n"
        ),
    )
    opts = UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=fw_dir,
        evidence_root=tmp_path / "ev",
        config_root=tmp_path / "cfg",
        manifest_path=tmp_path / "manifest.json",
        change_number="CHG_KEEP",
        operator="netops",
        auto_cleanup=True,
        require_release_notes=False,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
    )

    res = upgrade_single_switch(sw, pol, exclusions, policies, transport, opts)
    assert res.state == SwitchState.COMPLETED
    assert res.hop_history[0]["transfer_mode"] == "pre-staged"
    assert f"file delete /var/tmp/{hop.package_filename}" not in transport.commands_executed
    assert "request system storage cleanup no-confirm" not in transport.commands_executed
    assert "file delete /var/tmp/old-stale-image.tgz" in transport.commands_executed


def test_ssh_connect_failure_marks_failed_and_holds_ancestors(tmp_path: Path) -> None:
    _, policies, exclusions = load_release_catalog(RELEASES_YML)
    transit = _make_sw(
        "TRANSIT_1",
        ip="192.0.2.2",
        neighbors=[NeighborExpectation("ge-0/0/10", "LEAF_1", "ge-0/2/0")],
    )
    leaf = _make_sw(
        "LEAF_1",
        ip="192.0.2.3",
        neighbors=[NeighborExpectation("ge-0/2/0", "TRANSIT_1", "ge-0/0/10", is_upstream=True)],
    )
    all_sw = [transit, leaf]
    graph = build_topology_graph(all_sw, origin=TEST_ORIGIN)

    class BrokenConnectTransport(FakeJunosTransport):
        def connect(self) -> None:
            raise TimeoutError("TCP connect timed out")

    def factory(sw: SwitchRecord) -> FakeJunosTransport:
        return BrokenConnectTransport(
            hostname=sw.hostname,
            model=sw.model,
            serial_number=sw.serial_number,
            running_version=sw.current_version,
        )

    manifest_path = tmp_path / "manifest.json"
    opts = UpgradeOptions(
        firmware_base_url="http://firmware-cache.example.internal",
        firmware_dir=tmp_path / "fw",
        evidence_root=tmp_path / "ev",
        config_root=tmp_path / "cfg",
        manifest_path=manifest_path,
        change_number="CHG_CONN",
        operator="netops",
        require_release_notes=False,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
    )

    processed, wave_ok = run_upgrade_batches(
        all_sw, all_sw, policies, exclusions, factory, opts, graph=graph
    )
    assert not wave_ok
    assert len(processed) == 1
    assert leaf.state == SwitchState.FAILED
    assert "TCP connect timed out" in leaf.last_error
    assert transit.state == SwitchState.ANCESTOR_HOLD
    assert manifest_path.exists()


def test_absent_psu_slot_without_hw_alarms_is_not_replace_recommended(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    sw = _make_sw("SINGLE_PSU_SW")
    tr_ok = FakeJunosTransport(
        hostname=sw.hostname,
        model=sw.model,
        serial_number=sw.serial_number,
        running_version=sw.current_version,
        chassis_env=(
            "Power FPC 0 Power Supply 0 OK\n"
            "Power FPC 0 Power Supply 1 Absent\n"
            "Temp FPC 0 CPU Sensor OK 42 degrees C\n"
        ),
        sys_alarms="No alarms currently active",
        chas_alarms="No alarms currently active",
    )
    verdict, checks = evaluate_hardware_and_fs_triage(
        tr_ok, sw, pol, tmp_path / "ev_ok", tmp_path / "cfg_ok"
    )
    assert verdict == TriageVerdict.ELIGIBLE
    assert sw.state == SwitchState.READY
    assert all(c.passed for c in checks if c.hard_stop)

    # Absent PSU slot + minor /var usage system alarm (with CLEAN chassis alarms) -> NEEDS_REMEDIATION (not hard stop)
    sw_var = _make_sw("SINGLE_PSU_VAR_ALARM_SW")
    tr_var = FakeJunosTransport(
        hostname=sw_var.hostname,
        model=sw_var.model,
        serial_number=sw_var.serial_number,
        running_version=sw_var.current_version,
        chassis_env="Power FPC 0 Power Supply 0 OK\nPower FPC 0 Power Supply 1 Absent\n",
        sys_alarms="1 alarms currently active\nMinor RE 0 /var partition usage is high",
        chas_alarms="No alarms currently active",
    )
    verdict_var, checks_var = evaluate_hardware_and_fs_triage(
        tr_var, sw_var, pol, tmp_path / "ev_var", tmp_path / "cfg_var"
    )
    assert verdict_var == TriageVerdict.NEEDS_REMEDIATION
    assert sw_var.state == SwitchState.READY
    assert all(c.passed for c in checks_var if c.hard_stop)

    # Absent PSU + unrelated chassis alarm (Management Ethernet Link Down) -> NEEDS_REMEDIATION, NOT REPLACE_RECOMMENDED
    sw_mgmt = _make_sw("SINGLE_PSU_MGMT_ALARM_SW")
    tr_mgmt = FakeJunosTransport(
        hostname=sw_mgmt.hostname,
        model=sw_mgmt.model,
        serial_number=sw_mgmt.serial_number,
        running_version=sw_mgmt.current_version,
        chassis_env="Power FPC 0 Power Supply 0 OK\nPower FPC 0 Power Supply 1 Absent\n",
        sys_alarms="No alarms currently active",
        chas_alarms="1 alarms currently active\nMinor Management Ethernet Link Down",
    )
    verdict_mgmt, checks_mgmt = evaluate_hardware_and_fs_triage(
        tr_mgmt, sw_mgmt, pol, tmp_path / "ev_mgmt", tmp_path / "cfg_mgmt"
    )
    assert verdict_mgmt == TriageVerdict.NEEDS_REMEDIATION
    assert sw_mgmt.state == SwitchState.READY
    assert any(c.name == "chassis_health" and not c.passed and c.hard_stop for c in checks_mgmt)

    # Absent + active hardware PSU chassis alarm must still trigger REPLACE_RECOMMENDED
    sw_alarm = _make_sw("ALARM_PSU_SW")
    tr_alarm = FakeJunosTransport(
        hostname=sw_alarm.hostname,
        model=sw_alarm.model,
        serial_number=sw_alarm.serial_number,
        running_version=sw_alarm.current_version,
        chassis_env="Power FPC 0 Power Supply 1 Absent\n",
        sys_alarms="No alarms currently active",
        chas_alarms="1 alarms currently active\nMajor FPC 0 PSU 1 failure",
    )
    verdict_bad, _ = evaluate_hardware_and_fs_triage(
        tr_alarm, sw_alarm, pol, tmp_path / "ev_bad", tmp_path / "cfg_bad"
    )
    assert verdict_bad == TriageVerdict.REPLACE_RECOMMENDED

    # Benign Minor "Rescue configuration is not set" system alarm must warn, NOT fail/quarantine
    sw_rescue = _make_sw("RESCUE_UNSET_SW")
    tr_rescue = FakeJunosTransport(
        hostname=sw_rescue.hostname,
        model=sw_rescue.model,
        serial_number=sw_rescue.serial_number,
        running_version=sw_rescue.current_version,
        sys_alarms=(
            "1 alarms currently active\n"
            "Alarm time               Class  Description\n"
            "2026-07-31 03:48:14 PDT  Minor  Rescue configuration is not set"
        ),
        chas_alarms="No alarms currently active",
    )
    verdict_rescue, checks_rescue = evaluate_hardware_and_fs_triage(
        tr_rescue, sw_rescue, pol, tmp_path / "ev_rescue", tmp_path / "cfg_rescue"
    )
    assert verdict_rescue in (TriageVerdict.ELIGIBLE, TriageVerdict.NEEDS_REMEDIATION)
    assert sw_rescue.state == SwitchState.READY
    assert any(
        c.name == "chassis_health" and c.passed and not c.hard_stop and c.severity == "warn"
        for c in checks_rescue
    )


def test_missing_local_tgz_warns_in_validation_and_rejects_example_url(tmp_path: Path) -> None:
    base_url, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex2300-c-12p", policies)
    assert pol is not None

    sw = _make_sw("EX2300_MISS", "ex2300-c-12p", "23.4R2.13")
    sw.kernel_arch = "arm-32"
    sw.free_storage_mb = 306
    hop = pol.hops[-1]

    checks = validate_package_match(sw, pol, hop, local_file=None)
    assert any(
        c.name == "local_tgz_present" and not c.passed and c.severity == "warn" for c in checks
    )

    tr = FakeJunosTransport(sw.hostname, sw.model, sw.serial_number, sw.current_version)
    with pytest.raises(FileNotFoundError, match="not found"):
        stage_or_stream_package(
            transport=tr,
            switch=sw,
            policy=pol,
            hop=hop,
            firmware_dir=tmp_path / "empty_fw",
            server=None,
            external_base_url=base_url,  # http://firmware-cache.example.internal
            transfer_mode="auto",
        )


def test_compute_remaining_hops_never_downgrades_newer_intratrain() -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    assert pol.final_target == "23.4R2-S8"

    # Switch already on 23.4R2-S9 (> 23.4R2-S8) must return 0 hops, not downgrade!
    assert compute_remaining_hops("23.4R2-S9", pol) == []


def test_cli_comma_hosts_redaction_order_and_svg_escaping() -> None:
    sw1 = _make_sw("SW_A", ip="192.0.2.1")
    sw2 = _make_sw("SW_B", ip="192.0.2.2")
    sw3 = _make_sw("SW_C", ip="192.0.2.3")
    filtered = _filter_switches([sw1, sw2, sw3], site=None, model=None, hosts=("SW_A,192.0.2.3",))
    assert [s.hostname for s in filtered] == ["SW_A", "SW_C"]

    # Reverse order so child appears before parent in graph.nodes
    child = _make_sw(
        "LEAF_X",
        ip="192.0.2.20",
        neighbors=[NeighborExpectation("ge-0/2/0", "PARENT_Y", "ge-0/0/1", is_upstream=True)],
    )
    parent = _make_sw(
        "PARENT_Y",
        ip="192.0.2.10",
        role="Core",
        neighbors=[NeighborExpectation("ge-0/0/1", "LEAF_X", "ge-0/2/0")],
    )
    graph = build_topology_graph([child, parent], origin=TEST_ORIGIN)
    redacted = redact_topology_graph(graph)
    leaf_node = next(n for n in redacted.nodes.values() if n["depth"] == 2)
    parent_node = next(n for n in redacted.nodes.values() if n["depth"] == 1)
    assert leaf_node["upstream"] == parent_node["id"]

    html = render_topology_html()
    assert "function esc(" in html
    assert "esc(n.label)" in html


def test_interactive_yes_reboot_and_non_error_install_failures(tmp_path: Path) -> None:
    from junos_upgrader.drivers.junos import JunosSwitchDriver
    from junos_upgrader.junos_client import NetmikoJunosTransport
    from junos_upgrader.models import HopSpec
    from junos_upgrader.transfer import TransferOutcome

    class FakeNetmikoConn:
        def __init__(self) -> None:
            self.sent: list[tuple[str, dict[str, object]]] = []

        def send_command(self, cmd: str, **kwargs: object) -> str:
            self.sent.append((cmd, kwargs))
            if cmd == "request system reboot":
                return "Reboot the system ? [yes,no] (no)"
            if cmd == "yes":
                raise EOFError("Socket closed during reboot")
            return ""

    tr = NetmikoJunosTransport(host="192.0.2.10", credentials=[])
    fake_conn = FakeNetmikoConn()
    tr._conn = fake_conn
    out = tr.run_interactive_yes("request system reboot", allow_disconnect=True)
    assert "Reboot the system" in out
    assert [c for c, _ in fake_conn.sent] == ["request system reboot", "yes"]
    assert "expect_string" in fake_conn.sent[0][1]
    assert "expect_string" in fake_conn.sent[1][1]

    # Non-"error:" software add failures must NOT trigger reboot
    class FailSoftwareAddTransport(FakeJunosTransport):
        def run_command(self, command: str, read_timeout: int = 60) -> str:
            self.commands_executed.append(command)
            if command.startswith("request system software add "):
                return "Validation failed: package incompatible"
            return super().run_command(command, read_timeout=read_timeout)

    drv = JunosSwitchDriver()
    fail_tr = FailSoftwareAddTransport("SW1", "ex3400-48p", "SN1", "23.2R2-S3")
    hop = HopSpec("23.4R2-S8", "23.4R2-S8", "junos-arm-32-23.4R2-S8.tgz", "md5", "a" * 32)
    ok, msg = drv.install_and_reboot(
        fail_tr,
        hop,
        TransferOutcome("http-stream", "http://192.0.2.1:8080/firmware/tok/pkg.tgz", True),
    )
    assert not ok
    assert "Validation failed" in msg
    assert "request system reboot" not in fail_tr.commands_executed


def test_lldp_multi_re_json_and_var_storage_and_live_version_refresh(tmp_path: Path) -> None:
    import json

    from junos_upgrader import __version__
    from junos_upgrader.checks import parse_junos_storage, run_prechecks
    from junos_upgrader.inventory import _parse_lldp_json

    lldp_multi_re = json.dumps(
        {
            "multi-routing-engine-results": [
                {
                    "multi-routing-engine-item": [
                        {
                            "lldp-neighbors-information": [
                                {
                                    "lldp-neighbor-information": {
                                        "lldp-local-port-id": [{"data": "xe-0/2/0.0"}],
                                        "lldp-remote-system-name": [{"data": "CORE_SW"}],
                                        "lldp-remote-port-id": [{"data": "xe-0/0/1"}],
                                        "lldp-remote-chassis-id": [{"data": "00:00:5e:00:53:01"}],
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    )
    stp_multi_re = json.dumps(
        {
            "multi-routing-engine-results": [
                {
                    "multi-routing-engine-item": [
                        {
                            "stp-interface-information": [
                                {
                                    "stp-instance": {
                                        "stp-interfaces": [
                                            {
                                                "stp-interface-entry": {
                                                    "interface-name": [{"data": "xe-0/2/0.0"}],
                                                    "port-role": [{"data": "ROOT"}],
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    )
    nbrs = _parse_lldp_json(lldp_multi_re, stp_multi_re)
    assert len(nbrs) == 1
    assert nbrs[0].remote_device == "CORE_SW"
    assert nbrs[0].is_upstream is True

    # /var should be selected ahead of / when /var/tmp is not a separate mount
    storage_txt = (
        "Filesystem Size Used Avail Capacity Mounted on\n"
        "/dev/da0s1a 200M 180M 20M 90% /\n"
        "/dev/da0s2e 2.0G 500M 1.5G 25% /var\n"
    )
    free_mb, _ = parse_junos_storage(storage_txt)
    assert free_mb == 1536

    # Stale manifest version refreshes from live show version when model & serial match
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    sw = _make_sw("RESUME_SW", "ex3400-48p", "22.2R3-S5")
    tr = FakeJunosTransport("RESUME_SW", "ex3400-48p", sw.serial_number, "23.2R2-S3")
    checks = run_prechecks(
        tr,
        sw,
        pol,
        pol.hops[-1],
        tmp_path / "ev",
        tmp_path / "cfg",
        require_release_notes=False,
    )
    assert sw.current_version == "23.2R2-S3"
    assert all(c.passed for c in checks if c.hard_stop)

    # Origin caching avoids ip route calls and __version__ matches pyproject.toml
    origin = RunnerOrigin("cached-host", "192.0.2.5", "eth0", "192.0.2.1")
    g = build_topology_graph([sw], origin=origin)
    assert g.origin.hostname == "cached-host"
    assert __version__ == "0.3.0"

    # Orchestrator skips already-installed hop when manifest current_version was stale
    base_url, _, exclusions = load_release_catalog(RELEASES_YML)
    sw_stale = _make_sw("ORCH_RESUME_SW", "ex3400-48p", "22.2R3-S5")
    # Live switch is ALREADY at final target 23.4R2-S8!
    tr_done = FakeJunosTransport(
        "ORCH_RESUME_SW", "ex3400-48p", sw_stale.serial_number, "23.4R2-S8"
    )
    opts = UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=tmp_path / "fw",
        evidence_root=tmp_path / "ev_orch",
        config_root=tmp_path / "cfg_orch",
        manifest_path=tmp_path / "manifest.json",
        change_number="CHG_RESUME",
        operator="netops",
        require_release_notes=False,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
        reconnect_timeout_seconds=0.0,
    )
    res_done = upgrade_single_switch(sw_stale, pol, exclusions, policies, tr_done, opts)
    assert res_done.state == SwitchState.COMPLETED
    assert res_done.current_version == "23.4R2-S8"
    assert "request system reboot" not in tr_done.commands_executed


def test_norris_live_prep_fixes_poe_nomore_tmpfs_storage_and_cli(tmp_path: Path) -> None:
    from click.testing import CliRunner
    from conftest import create_valid_tgz

    from junos_upgrader.checks import _extract_poe_watts
    from junos_upgrader.cli import main
    from junos_upgrader.drivers.junos import JunosSwitchDriver
    from junos_upgrader.inventory import load_inventory, save_inventory
    from junos_upgrader.transfer import (
        TransferOutcome,
        UnifiedFirmwareServer,
        stage_or_stream_package,
    )

    # #11: _extract_poe_watts parses EX3400 controller rows with trailing asterisks ("0**")
    poe_out = (
        "Controller  Maximum   Power         Guard    Management   Status        Lldp\n"
        "index       power     consumption   band                                Priority\n"
        "   0**      740W      36.20W          0W     Class        AT_MODE       Disabled\n"
        "  **New PoE software upgrade available.\n"
    )
    assert _extract_poe_watts(poe_out) == pytest.approx(36.20)

    # #5 & #6: default boot_timeout_seconds >= 1200 and read-only precheck low storage != quarantine
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    assert pol.boot_timeout_seconds >= 1200

    sw_low = _make_sw("LOW_STORAGE_SW", "ex3400-48p", "18.1R3-S4.2")
    tr_low = FakeJunosTransport(
        sw_low.hostname,
        sw_low.model,
        sw_low.serial_number,
        sw_low.current_version,
        free_storage_mb=100,
    )
    verdict_ro, _ = evaluate_hardware_and_fs_triage(
        tr_low, sw_low, pol, tmp_path / "ev_ro", tmp_path / "cfg_ro", execute_cleanup=False
    )
    assert verdict_ro == TriageVerdict.NEEDS_REMEDIATION
    assert sw_low.state == SwitchState.READY
    # #12: flash_log_scan uses | no-more
    assert any("show log messages" in cmd and "| no-more" in cmd for cmd in tr_low.commands_executed)

    verdict_rw, _ = evaluate_hardware_and_fs_triage(
        tr_low, sw_low, pol, tmp_path / "ev_rw", tmp_path / "cfg_rw", execute_cleanup=True
    )
    assert verdict_rw == TriageVerdict.REPLACE_RECOMMENDED
    assert sw_low.state == SwitchState.REPLACE_RECOMMENDED

    # #10: /tmp (tmpfs) staging when /.mount is tight and tmpfs has headroom + failed install cleanup
    fw_dir = tmp_path / "fw"
    hop = pol.hops[-1]
    _, md5_hex, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    )
    hop.checksum = md5_hex

    sw_tmp = _make_sw("TMPFS_SW", "ex3400-48p", "23.2R2-S3", ip="127.0.0.1")
    sw_tmp.free_storage_mb = 437
    sw_tmp.tmpfs_free_mb = 904
    tr_tmp = FakeJunosTransport(
        sw_tmp.hostname,
        sw_tmp.model,
        sw_tmp.serial_number,
        sw_tmp.current_version,
        checksums_by_filename={hop.package_filename: md5_hex},
    )
    with UnifiedFirmwareServer(firmware_dir=fw_dir, port=0, bind_host="127.0.0.1") as srv:
        outcome = stage_or_stream_package(
            tr_tmp, sw_tmp, pol, hop, fw_dir, srv, "", transfer_mode="auto"
        )
    assert outcome.mode_used == "http-tmpfs"
    assert outcome.remote_staged_path == f"/tmp/{hop.package_filename}"
    assert outcome.uses_no_copy is True

    drv = JunosSwitchDriver()
    ok_chk, _ = drv.verify_staged_checksum(tr_tmp, outcome.remote_staged_path, "md5", md5_hex)
    assert ok_chk is True

    # Failed software add cleans up stranded /tmp/<pkg>.tgz
    tr_fail = FakeJunosTransport(
        sw_tmp.hostname,
        sw_tmp.model,
        sw_tmp.serial_number,
        sw_tmp.current_version,
        fail_install=True,
    )
    ok_inst, _ = drv.install_and_reboot(
        tr_fail,
        hop,
        TransferOutcome(
            mode_used="http-tmpfs",
            software_add_target=f"/tmp/{hop.package_filename}",
            uses_no_copy=True,
            remote_staged_path=f"/tmp/{hop.package_filename}",
        ),
    )
    assert ok_inst is False
    assert f"file delete /tmp/{hop.package_filename}" in tr_fail.commands_executed

    # #7 & #8: CLI --verbose/--log-file and reset-state
    manifest_path = tmp_path / "site-inventory.json"
    sw_q = _make_sw("QUAR_SW", "ex3400-48p", "23.2R2-S3")
    sw_q.state = SwitchState.REPLACE_RECOMMENDED
    sw_q.last_error = "Storage 428 MB below minimum 600 MB floor."
    save_inventory([sw_q], manifest_path)

    log_file = tmp_path / "run.log"
    runner = CliRunner()
    res_cli = runner.invoke(
        main,
        [
            "--verbose",
            "--log-file",
            str(log_file),
            "reset-state",
            "--manifest",
            str(manifest_path),
            "--releases",
            str(RELEASES_YML),
        ],
    )
    assert res_cli.exit_code == 0, res_cli.output
    assert log_file.exists()
    reloaded = load_inventory(manifest_path)
    assert reloaded[0].state == SwitchState.READY
    assert reloaded[0].last_error == ""


def test_check_local_ssh_fallback_unit_matrix() -> None:
    from junos_upgrader.checks import check_local_ssh_fallback

    blocked_configs = [
        # Single radius, template super-user without local auth, root-login deny
        (
            "set system authentication-order radius\n"
            'set system radius-server 198.51.100.20 secret "$9$testdummy"\n'
            "set system login user remote uid 2000\n"
            "set system login user remote class super-user\n"
            "set system services ssh root-login deny\n"
        ),
        # Multi-line authentication-order + read-only user with password (not super-user)
        (
            "set system authentication-order radius\n"
            "set system authentication-order password\n"
            "set system login user remote class super-user\n"
            "set system login user viewer class read-only\n"
            'set system login user viewer authentication encrypted-password "$6$test$DummyHash"\n'
        ),
        # Bracketed list without spaces + empty encrypted-password
        (
            "set system authentication-order [radius password]\n"
            "set system login user localadmin class super-user\n"
            'set system login user localadmin authentication encrypted-password ""\n'
        ),
        # tacplus only, no local users
        (
            "set system authentication-order tacplus\n"
            'set system tacplus-server 203.0.113.20 secret "$9$testdummy"\n'
        ),
        # Deactivated user authentication
        (
            "set system authentication-order [ tacplus password ]\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyHash"\n'
            "deactivate system login user localadmin authentication\n"
        ),
        # Deactivated user stanza / class / specific auth method / deleted auth
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyHash"\n'
            "deactivate system login user localadmin\n"
        ),
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyHash"\n'
            "deactivate system login user localadmin class\n"
        ),
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyHash"\n'
            "deactivate system login user localadmin authentication encrypted-password\n"
        ),
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyHash"\n'
            "delete system login user localadmin authentication encrypted-password\n"
        ),
        # root-login allow overridden or deactivated
        (
            "set system authentication-order radius\n"
            "set system services ssh root-login allow\n"
            "set system services ssh root-login deny-password\n"
        ),
        (
            "set system authentication-order radius\n"
            "set system services ssh root-login allow\n"
            "deactivate system services ssh root-login\n"
        ),
        (
            "set system authentication-order radius\n"
            "set system services ssh root-login allow\n"
            "deactivate system services ssh\n"
        ),
        (
            "set system authentication-order radius\n"
            "set system services ssh root-login allow\n"
            "delete system services ssh root-login allow\n"
        ),
    ]
    for cfg in blocked_configs:
        res = check_local_ssh_fallback(cfg, allow_aaa_only_ssh=False)
        assert res.name == "local_ssh_fallback"
        assert res.passed is False, cfg
        assert res.hard_stop is True, cfg
        assert res.severity == "fail", cfg
        assert res.details["aaa_methods"], cfg

    # Override turns hard_stop into non-blocking warning
    overridden = check_local_ssh_fallback(blocked_configs[0], allow_aaa_only_ssh=True)
    assert overridden.name == "local_ssh_fallback"
    assert overridden.passed is False
    assert overridden.hard_stop is False
    assert overridden.severity == "warn"

    passing_aaa_configs = [
        # Bracketed list + unquoted super-user with encrypted-password
        (
            "set system authentication-order [ radius password ]\n"
            "set system login user remote class super-user\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyHash"\n'
        ),
        # Quoted super-user with ssh-ed25519
        (
            "set system authentication-order radius\n"
            'set system login user "net ops" class super-user\n'
            'set system login user "net ops" authentication ssh-ed25519 '
            '"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestPublicKeyMaterialOnly '
            'netops@example.invalid"\n'
        ),
        # tacplus + ssh-rsa
        (
            "set system authentication-order tacplus\n"
            "set system login user localadmin class super-user\n"
            'set system login user localadmin authentication ssh-rsa '
            '"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQFakeTestPublicKeyMaterialOnly '
            'netops@example.invalid"\n'
        ),
        # [ tacplus password ] + ssh-ecdsa
        (
            "set system authentication-order [ tacplus password ]\n"
            "set system login user localadmin class super-user\n"
            'set system login user localadmin authentication ssh-ecdsa '
            '"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIFakeTestKeyMaterialOnly '
            'netops@example.invalid"\n'
        ),
        # Deactivated password but active ssh-ed25519 still provides fallback
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyHash"\n'
            "deactivate system login user localadmin authentication encrypted-password\n"
            'set system login user localadmin authentication ssh-ed25519 '
            '"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestPublicKeyMaterialOnly"\n'
        ),
        # root-login allow
        (
            "set system authentication-order radius\n"
            "set system login user remote class super-user\n"
            "set system services ssh root-login allow\n"
        ),
    ]
    for cfg in passing_aaa_configs:
        res = check_local_ssh_fallback(cfg, allow_aaa_only_ssh=False)
        assert res.name == "local_ssh_fallback"
        assert res.passed is True, cfg
        assert res.hard_stop is False, cfg
        assert res.severity == "info", cfg

    non_aaa_configs = [
        "",
        "set system authentication-order password\n",
        (
            "set system authentication-order [ radius password ]\n"
            "deactivate system authentication-order\n"
        ),
        "set system authentication-order radius\ndeactivate system authentication-order radius\n",
        "set system authentication-order radius\ndelete system authentication-order\n",
    ]
    for cfg in non_aaa_configs:
        res = check_local_ssh_fallback(cfg, allow_aaa_only_ssh=False)
        assert res.name == "local_ssh_fallback"
        assert res.passed is True, cfg
        assert res.hard_stop is False, cfg
        assert res.severity == "info", cfg
        assert res.details["aaa_methods"] == [], cfg


def test_aaa_only_ssh_gate_run_prechecks_and_orchestrator(tmp_path: Path) -> None:
    from junos_upgrader.checks import run_prechecks

    base_url, policies, exclusions = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    pkg_path = fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    _, md5_hex, _ = create_valid_tgz(pkg_path, comment="arm-32")
    hop.checksum = md5_hex

    aaa_only_cfg = (
        "set system authentication-order [ radius password ]\n"
        "set system login user remote class super-user\n"
        "set system services ssh root-login deny\n"
    )

    # A. Direct run_prechecks
    sw_pre = _make_sw("AAA_PRE_SW", "ex3400-48p", "23.2R2-S3")
    tr_pre = FakeJunosTransport(
        sw_pre.hostname,
        sw_pre.model,
        sw_pre.serial_number,
        sw_pre.current_version,
        config_set_extra=aaa_only_cfg,
    )
    checks_blocked = run_prechecks(
        tr_pre,
        sw_pre,
        pol,
        hop,
        tmp_path / "ev_blk",
        tmp_path / "cfg_blk",
        local_pkg_file=pkg_path,
        require_release_notes=False,
        allow_aaa_only_ssh=False,
    )
    gate_blk = [c for c in checks_blocked if c.name == "local_ssh_fallback"]
    assert len(gate_blk) == 1
    assert gate_blk[0].passed is False
    assert gate_blk[0].hard_stop is True
    assert gate_blk[0].severity == "fail"

    checks_warn = run_prechecks(
        tr_pre,
        sw_pre,
        pol,
        hop,
        tmp_path / "ev_warn",
        tmp_path / "cfg_warn",
        local_pkg_file=pkg_path,
        require_release_notes=False,
        allow_aaa_only_ssh=True,
    )
    gate_warn = [c for c in checks_warn if c.name == "local_ssh_fallback"]
    assert len(gate_warn) == 1
    assert gate_warn[0].passed is False
    assert gate_warn[0].hard_stop is False
    assert gate_warn[0].severity == "warn"

    def _opts(*, stage_only: bool, allow_aaa: bool) -> UpgradeOptions:
        return UpgradeOptions(
            firmware_base_url=base_url,
            firmware_dir=fw_dir,
            evidence_root=tmp_path / f"ev_{stage_only}_{allow_aaa}",
            config_root=tmp_path / f"cfg_{stage_only}_{allow_aaa}",
            manifest_path=tmp_path / "manifest.json",
            change_number="CHG_AAA",
            operator="netops",
            transfer_mode="scp",
            require_release_notes=False,
            stage_only=stage_only,
            allow_aaa_only_ssh=allow_aaa,
            reboot_poll_interval=0.0,
            reboot_wait_down_seconds=0.0,
            post_settle_seconds=0.0,
            reconnect_timeout_seconds=0.0,
        )

    # B. Orchestrator stage_only=True
    sw_stg_blk = _make_sw("AAA_STAGE_BLK", "ex3400-48p", "23.2R2-S3")
    tr_stg_blk = FakeJunosTransport(
        sw_stg_blk.hostname,
        sw_stg_blk.model,
        sw_stg_blk.serial_number,
        sw_stg_blk.current_version,
        config_set_extra=aaa_only_cfg,
        checksums_by_filename={hop.package_filename: md5_hex},
    )
    res_stg_blk = upgrade_single_switch(
        sw_stg_blk, pol, exclusions, policies, tr_stg_blk, _opts(stage_only=True, allow_aaa=False)
    )
    assert res_stg_blk.state == SwitchState.FAILED
    assert "aaa" in res_stg_blk.last_error.lower() or "ssh" in res_stg_blk.last_error.lower()
    assert tr_stg_blk.scp_uploads == []
    assert not any(
        c.startswith("request system software add ") for c in tr_stg_blk.commands_executed
    )

    sw_stg_ok = _make_sw("AAA_STAGE_OK", "ex3400-48p", "23.2R2-S3")
    tr_stg_ok = FakeJunosTransport(
        sw_stg_ok.hostname,
        sw_stg_ok.model,
        sw_stg_ok.serial_number,
        sw_stg_ok.current_version,
        config_set_extra=aaa_only_cfg,
        checksums_by_filename={hop.package_filename: md5_hex},
    )
    res_stg_ok = upgrade_single_switch(
        sw_stg_ok, pol, exclusions, policies, tr_stg_ok, _opts(stage_only=True, allow_aaa=True)
    )
    assert res_stg_ok.state == SwitchState.STAGED
    assert res_stg_ok.staged_package == f"/var/tmp/{hop.package_filename}"
    assert res_stg_ok.last_error == ""

    # C. Orchestrator stage_only=False
    sw_upg_blk = _make_sw("AAA_UPG_BLK", "ex3400-48p", "23.2R2-S3")
    tr_upg_blk = FakeJunosTransport(
        sw_upg_blk.hostname,
        sw_upg_blk.model,
        sw_upg_blk.serial_number,
        sw_upg_blk.current_version,
        config_set_extra=aaa_only_cfg,
        checksums_by_filename={hop.package_filename: md5_hex},
    )
    res_upg_blk = upgrade_single_switch(
        sw_upg_blk, pol, exclusions, policies, tr_upg_blk, _opts(stage_only=False, allow_aaa=False)
    )
    assert res_upg_blk.state == SwitchState.FAILED
    assert not any(
        c.startswith("request system software add ") for c in tr_upg_blk.commands_executed
    )
    assert "request system reboot" not in tr_upg_blk.commands_executed

    sw_upg_ok = _make_sw("AAA_UPG_OK", "ex3400-48p", "23.2R2-S3")
    tr_upg_ok = FakeJunosTransport(
        sw_upg_ok.hostname,
        sw_upg_ok.model,
        sw_upg_ok.serial_number,
        sw_upg_ok.current_version,
        config_set_extra=aaa_only_cfg,
        checksums_by_filename={hop.package_filename: md5_hex},
    )
    res_upg_ok = upgrade_single_switch(
        sw_upg_ok, pol, exclusions, policies, tr_upg_ok, _opts(stage_only=False, allow_aaa=True)
    )
    assert res_upg_ok.state == SwitchState.COMPLETED
    assert res_upg_ok.current_version == "23.4R2-S8"
    assert "request system reboot" in tr_upg_ok.commands_executed


def test_cli_allow_aaa_only_ssh_on_precheck_stage_and_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from click.testing import CliRunner

    import junos_upgrader.cli as cli_mod
    from junos_upgrader.inventory import load_inventory, save_inventory

    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    pkg_path = fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    _, md5_hex, _ = create_valid_tgz(pkg_path, comment="arm-32")

    aaa_only_cfg = (
        "set system authentication-order [ radius password ]\n"
        "set system login user remote class super-user\n"
        "set system services ssh root-login deny\n"
    )

    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or TEST_ORIGIN),
    )
    monkeypatch.setattr(
        cli_mod,
        "_make_transport_factory",
        lambda creds: (
            lambda sw: FakeJunosTransport(
                sw.hostname,
                sw.model,
                sw.serial_number,
                sw.current_version,
                config_set_extra=aaa_only_cfg,
                checksums_by_filename={hop.package_filename: md5_hex},
            )
        ),
    )

    manifest = tmp_path / "inv.json"
    ev_dir = tmp_path / "ev"
    cfg_dir = tmp_path / "cfg"
    runner = CliRunner()

    def _reset_manifest() -> SwitchRecord:
        sw = _make_sw("AAA_CLI_SW", "ex3400-48p", "23.2R2-S3")
        save_inventory([sw], manifest)
        return sw

    # 1. precheck
    _reset_manifest()
    pre_args = [
        "precheck",
        "--manifest",
        str(manifest),
        "--releases",
        str(RELEASES_YML),
        "--firmware-dir",
        str(fw_dir),
        "--evidence-dir",
        str(ev_dir),
        "--config-dir",
        str(cfg_dir),
        "--skip-release-notes-gate",
        "--allow-unverified-checksums",
    ]
    res_pre_blk = runner.invoke(cli_mod.main, pre_args)
    assert res_pre_blk.exit_code != 0
    assert "aaa" in load_inventory(manifest)[0].last_error.lower()

    res_pre_ok = runner.invoke(cli_mod.main, [*pre_args, "--allow-aaa-only-ssh"])
    assert res_pre_ok.exit_code == 0, res_pre_ok.output
    assert "WARN" in res_pre_ok.output
    assert load_inventory(manifest)[0].state == SwitchState.READY
    assert load_inventory(manifest)[0].last_error == ""

    # 2. stage
    _reset_manifest()
    stage_args = [
        "stage",
        "--manifest",
        str(manifest),
        "--releases",
        str(RELEASES_YML),
        "--firmware-dir",
        str(fw_dir),
        "--evidence-dir",
        str(ev_dir),
        "--config-dir",
        str(cfg_dir),
        "--transfer-mode",
        "scp",
        "--change-number",
        "CHG_AAA",
        "--operator",
        "netops",
        "--skip-release-notes-gate",
        "--allow-unverified-checksums",
    ]
    res_stg_blk = runner.invoke(cli_mod.main, stage_args)
    assert res_stg_blk.exit_code != 0
    assert load_inventory(manifest)[0].state == SwitchState.FAILED

    _reset_manifest()
    res_stg_ok = runner.invoke(cli_mod.main, [*stage_args, "--allow-aaa-only-ssh"])
    assert res_stg_ok.exit_code == 0, res_stg_ok.output
    assert load_inventory(manifest)[0].state == SwitchState.STAGED

    # 3. upgrade --dry-run (end-to-end gate check)
    _reset_manifest()
    upg_dry_args = [
        "upgrade",
        "--manifest",
        str(manifest),
        "--releases",
        str(RELEASES_YML),
        "--firmware-dir",
        str(fw_dir),
        "--evidence-dir",
        str(ev_dir),
        "--config-dir",
        str(cfg_dir),
        "--transfer-mode",
        "scp",
        "--change-number",
        "CHG_AAA",
        "--operator",
        "netops",
        "--skip-release-notes-gate",
        "--allow-unverified-checksums",
        "--dry-run",
    ]
    res_upg_blk = runner.invoke(cli_mod.main, upg_dry_args)
    assert res_upg_blk.exit_code != 0

    _reset_manifest()
    res_upg_ok = runner.invoke(cli_mod.main, [*upg_dry_args, "--allow-aaa-only-ssh"])
    assert res_upg_ok.exit_code == 0, res_upg_ok.output

    # 4. upgrade non-dry-run UpgradeOptions.allow_aaa_only_ssh wiring
    captured_opts: list[UpgradeOptions] = []

    def _fake_batches(
        all_switches,
        targets,
        policies_arg,
        exclusions_arg,
        factory_arg,
        opts,
        **kwargs,
    ):
        captured_opts.append(opts)
        return list(targets), True

    monkeypatch.setattr(cli_mod, "run_upgrade_batches", _fake_batches)
    _reset_manifest()
    upg_args = [
        "upgrade",
        "--manifest",
        str(manifest),
        "--releases",
        str(RELEASES_YML),
        "--firmware-dir",
        str(fw_dir),
        "--evidence-dir",
        str(ev_dir),
        "--config-dir",
        str(cfg_dir),
        "--transfer-mode",
        "scp",
        "--change-number",
        "CHG_AAA",
        "--operator",
        "netops",
        "--skip-release-notes-gate",
        "--allow-unverified-checksums",
    ]
    res_wire_default = runner.invoke(cli_mod.main, upg_args)
    assert res_wire_default.exit_code == 0, res_wire_default.output
    res_wire_flag = runner.invoke(cli_mod.main, [*upg_args, "--allow-aaa-only-ssh"])
    assert res_wire_flag.exit_code == 0, res_wire_flag.output
    assert len(captured_opts) == 2
    assert captured_opts[0].allow_aaa_only_ssh is False
    assert captured_opts[1].allow_aaa_only_ssh is True


def test_check_local_ssh_fallback_deactivate_delete_multikey_and_malformed_quotes() -> None:
    from junos_upgrader.checks import check_local_ssh_fallback

    # 1. deactivate -> delete -> set on system / authentication-order / authentication-order <m>
    # Must NOT retain stale deactivation state (would silently bypass the AAA lockout gate).
    aaa_reconfigured_after_delete = [
        (
            "set system authentication-order radius\n"
            "deactivate system\n"
            "delete system\n"
            "set system authentication-order radius\n"
        ),
        (
            "set system authentication-order radius\n"
            "deactivate system authentication-order\n"
            "delete system authentication-order\n"
            "set system authentication-order radius\n"
        ),
        (
            "set system authentication-order radius\n"
            "deactivate system authentication-order radius\n"
            "delete system authentication-order radius\n"
            "set system authentication-order radius\n"
        ),
    ]
    for cfg in aaa_reconfigured_after_delete:
        res = check_local_ssh_fallback(cfg, allow_aaa_only_ssh=False)
        assert res.passed is False, cfg
        assert res.hard_stop is True, cfg
        assert res.severity == "fail", cfg
        assert res.details["aaa_methods"] == ["radius"], cfg

    # 2. deactivate -> delete -> set on fallback user, class, authentication, and root-login allow
    # Must NOT retain stale deactivation state (would cause false-positive upgrade blocks).
    fallback_reconfigured_after_delete = [
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyOldHash"\n'
            "deactivate system login\n"
            "delete system login\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyNewHash"\n'
        ),
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyOldHash"\n'
            "deactivate system login user localadmin\n"
            "delete system login user localadmin\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyNewHash"\n'
        ),
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyHash"\n'
            "deactivate system login user localadmin class\n"
            "delete system login user localadmin class\n"
            "set system login user localadmin class super-user\n"
        ),
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyOldHash"\n'
            "deactivate system login user localadmin authentication\n"
            "delete system login user localadmin authentication\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyNewHash"\n'
        ),
        (
            "set system authentication-order radius\n"
            "set system login user localadmin class super-user\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyOldHash"\n'
            "deactivate system login user localadmin authentication encrypted-password\n"
            "delete system login user localadmin authentication encrypted-password\n"
            "set system login user localadmin authentication "
            'encrypted-password "$6$test$DummyNewHash"\n'
        ),
        (
            "set system authentication-order radius\n"
            "set system services ssh root-login allow\n"
            "deactivate system services ssh root-login allow\n"
            "delete system services ssh root-login allow\n"
            "set system services ssh root-login allow\n"
        ),
        (
            "set system authentication-order radius\n"
            "set system services ssh root-login allow\n"
            "deactivate system services ssh\n"
            "delete system services ssh\n"
            "set system services ssh root-login allow\n"
        ),
        (
            "set system authentication-order radius\n"
            "set system services ssh root-login allow\n"
            "deactivate system services\n"
            "delete system services\n"
            "set system services ssh root-login allow\n"
        ),
    ]
    for cfg in fallback_reconfigured_after_delete:
        res = check_local_ssh_fallback(cfg, allow_aaa_only_ssh=False)
        assert res.passed is True, cfg
        assert res.hard_stop is False, cfg
        assert res.severity == "info", cfg

    # 3. Multiple SSH keys of the same auth_type (ssh-ed25519 KEY1 + KEY2)
    key1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestKeyOneOnly"
    key2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestKeyTwoOnly"
    two_keys_base = (
        "set system authentication-order radius\n"
        "set system login user localadmin class super-user\n"
        f'set system login user localadmin authentication ssh-ed25519 "{key1}"\n'
        f'set system login user localadmin authentication ssh-ed25519 "{key2}"\n'
    )

    # Deactivating or deleting KEY1 alone leaves KEY2 active -> passes
    for suffix in (
        f'deactivate system login user localadmin authentication ssh-ed25519 "{key1}"\n',
        f'delete system login user localadmin authentication ssh-ed25519 "{key1}"\n',
    ):
        res = check_local_ssh_fallback(two_keys_base + suffix, allow_aaa_only_ssh=False)
        assert res.passed is True, suffix
        assert res.details["fallback_users"] == ["localadmin"], suffix

    # Re-adding KEY1 after deactivate -> delete -> set also passes
    readded_key = (
        "set system authentication-order radius\n"
        "set system login user localadmin class super-user\n"
        f'set system login user localadmin authentication ssh-ed25519 "{key1}"\n'
        f'deactivate system login user localadmin authentication ssh-ed25519 "{key1}"\n'
        f'delete system login user localadmin authentication ssh-ed25519 "{key1}"\n'
        f'set system login user localadmin authentication ssh-ed25519 "{key1}"\n'
    )
    res_readded = check_local_ssh_fallback(readded_key, allow_aaa_only_ssh=False)
    assert res_readded.passed is True
    assert res_readded.details["fallback_users"] == ["localadmin"]

    # Deactivating/deleting both keys individually or the whole ssh-ed25519 stanza -> blocks
    for suffix in (
        (
            f'deactivate system login user localadmin authentication ssh-ed25519 "{key1}"\n'
            f'deactivate system login user localadmin authentication ssh-ed25519 "{key2}"\n'
        ),
        (
            f'delete system login user localadmin authentication ssh-ed25519 "{key1}"\n'
            f'delete system login user localadmin authentication ssh-ed25519 "{key2}"\n'
        ),
        "deactivate system login user localadmin authentication ssh-ed25519\n",
        "delete system login user localadmin authentication ssh-ed25519\n",
    ):
        res = check_local_ssh_fallback(two_keys_base + suffix, allow_aaa_only_ssh=False)
        assert res.passed is False, suffix
        assert res.hard_stop is True, suffix
        assert res.details["fallback_users"] == [], suffix

    # 4. Unbalanced lone quote in encrypted-password must not count as valid password or crash
    lone_quote_cfg = (
        "set system authentication-order radius\n"
        "set system login user localadmin class super-user\n"
        'set system login user localadmin authentication encrypted-password "\n'
    )
    res_quote = check_local_ssh_fallback(lone_quote_cfg, allow_aaa_only_ssh=False)
    assert res_quote.passed is False
    assert res_quote.hard_stop is True
    assert res_quote.details["fallback_users"] == []


class StatefulRemediationTransport(FakeJunosTransport):
    """Stateful FakeJunosTransport simulating rescue save, /var/tmp cleanup, and pkg purge."""

    def __init__(
        self,
        *args: object,
        cleanup_reclaim_mb: int = 0,
        pkg_purge_reclaim_mb: int = 0,
        fail_rescue_save: bool = False,
        fail_pkg_purge: bool = False,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.cleanup_reclaim_mb = cleanup_reclaim_mb
        self.pkg_purge_reclaim_mb = pkg_purge_reclaim_mb
        self.fail_rescue_save = fail_rescue_save
        self.fail_pkg_purge = fail_pkg_purge
        self._cleanup_done = False
        self._pkg_rm_done = False
        self._pkg_purge_done = False

    def run_command(self, command: str, read_timeout: int = 60) -> str:
        cmd = command.strip()
        if cmd == "request system configuration rescue save":
            self.commands_executed.append(command)
            if self.fail_rescue_save:
                return "error: rescue configuration save failed"
            if self.sys_alarms and "rescue configuration is not set" in self.sys_alarms.lower():
                self.sys_alarms = "No alarms currently active"
            return "Rescue configuration saved"
        if cmd.startswith("file delete "):
            self.commands_executed.append(command)
            target_path = cmd[len("file delete ") :].strip()
            target_name = Path(target_path).name
            kept_lines = [
                ln
                for ln in self.var_tmp_output.splitlines()
                if target_name not in ln.split() and target_path not in ln.split()
            ]
            self.var_tmp_output = "\n".join(kept_lines) + ("\n" if kept_lines else "")
            return f"deleted {target_path}"
        if cmd == "request system storage cleanup no-confirm":
            self.commands_executed.append(command)
            if not self._cleanup_done:
                self._cleanup_done = True
                self.free_storage_mb += self.cleanup_reclaim_mb
            return f"Freed {self.cleanup_reclaim_mb}MB"
        if cmd == 'start shell command "pkg setop rm previous"':
            self.commands_executed.append(command)
            if self.fail_pkg_purge:
                return "error: permission denied"
            self._pkg_rm_done = True
            return "Removed previous package set"
        if cmd == 'start shell command "pkg delete old"':
            self.commands_executed.append(command)
            if self.fail_pkg_purge:
                return "error: permission denied"
            if self._pkg_rm_done and not self._pkg_purge_done:
                self._pkg_purge_done = True
                self.free_storage_mb += self.pkg_purge_reclaim_mb
            return f"Deleted old packages, freed {self.pkg_purge_reclaim_mb}MB"
        return super().run_command(command, read_timeout=read_timeout)


_MUTATING_PRECHECK_PREFIXES = (
    "request system configuration rescue save",
    "file delete ",
    "request system storage cleanup no-confirm",
    'start shell command "pkg ',
)


def _mutating_commands(commands: list[str]) -> list[str]:
    return [c for c in commands if c.strip().startswith(_MUTATING_PRECHECK_PREFIXES)]


def test_precheck_default_readonly_and_purge_requires_fix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenarios (a) and (b): default precheck is read-only; --purge-previous-pkg requires --fix."""
    from click.testing import CliRunner

    import junos_upgrader.cli as cli_mod
    from junos_upgrader.inventory import load_inventory, save_inventory

    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    pkg_path = fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    create_valid_tgz(pkg_path, comment="arm-32")

    manifest = tmp_path / "inv.json"
    sw = _make_sw("PRE_RO_SW", "ex3400-48p", "23.2R2-S3")
    save_inventory([sw], manifest)

    transports: list[StatefulRemediationTransport] = []

    def _factory(rec: SwitchRecord) -> StatefulRemediationTransport:
        tr = StatefulRemediationTransport(
            rec.hostname,
            rec.model,
            rec.serial_number,
            rec.current_version,
            free_storage_mb=150,
            cleanup_reclaim_mb=200,
            sys_alarms=(
                "1 alarms currently active\n"
                "2026-07-31 03:48:14 PDT  Minor  Rescue configuration is not set"
            ),
            var_tmp_output="-rw-r--r-- 1 root wheel 200000000 Nov 01 12:00 old-stale.tgz\n",
        )
        transports.append(tr)
        return tr

    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or TEST_ORIGIN),
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda creds: _factory)

    runner = CliRunner()
    base_args = [
        "precheck",
        "--manifest",
        str(manifest),
        "--releases",
        str(RELEASES_YML),
        "--firmware-dir",
        str(fw_dir),
        "--evidence-dir",
        str(tmp_path / "ev"),
        "--config-dir",
        str(tmp_path / "cfg"),
        "--skip-release-notes-gate",
        "--allow-unverified-checksums",
    ]

    # (b) --purge-previous-pkg without --fix fails fast with zero SSH calls
    res_bad_flag = runner.invoke(cli_mod.main, [*base_args, "--purge-previous-pkg"])
    assert res_bad_flag.exit_code != 0
    assert "--purge-previous-pkg requires --fix" in res_bad_flag.output
    assert transports == []

    # (a) Default precheck remains strictly read-only
    res_ro = runner.invoke(cli_mod.main, base_args)
    assert res_ro.exit_code != 0  # storage_floor fails in read-only mode
    assert len(transports) == 1
    assert _mutating_commands(transports[0].commands_executed) == []
    reloaded = load_inventory(manifest)[0]
    assert reloaded.triage_verdict == TriageVerdict.NEEDS_REMEDIATION.value
    assert reloaded.state == SwitchState.READY


def test_precheck_fix_remediates_rescue_and_storage_and_preserves_staged_var_tmp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario (c): precheck --fix saves rescue, cleans /var/tmp, preserves /var/tmp/<pkg>.tgz."""
    from click.testing import CliRunner

    import junos_upgrader.cli as cli_mod
    from junos_upgrader.inventory import load_inventory, save_inventory

    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    pkg_path = fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    create_valid_tgz(pkg_path, comment="arm-32")

    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or TEST_ORIGIN),
    )

    runner = CliRunner()

    # Case 1: /tmp/<pkg>.tgz staged (or unstaged NOT_READY) -> runs storage cleanup no-confirm & cleans stale /var/tmp/*.tgz
    manifest_1 = tmp_path / "inv1.json"
    sw_1 = _make_sw("FIX_FULL_SW", "ex3400-48p", "23.2R2-S3")
    sw_1.state = SwitchState.NOT_READY
    sw_1.staged_package = f"/tmp/{hop.package_filename}"
    save_inventory([sw_1], manifest_1)

    tr_1 = StatefulRemediationTransport(
        sw_1.hostname,
        sw_1.model,
        sw_1.serial_number,
        sw_1.current_version,
        free_storage_mb=150,
        cleanup_reclaim_mb=250,
        tmpfs_free_mb=900,
        sys_alarms=(
            "1 alarms currently active\n"
            "2026-07-31 03:48:14 PDT  Minor  Rescue configuration is not set"
        ),
        var_tmp_output="-rw-r--r-- 1 root wheel 200000000 Nov 01 12:00 old-stale.tgz\n",
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda creds: (lambda _sw: tr_1))

    ev_1 = tmp_path / "ev1"
    res_1 = runner.invoke(
        cli_mod.main,
        [
            "precheck",
            "--manifest",
            str(manifest_1),
            "--releases",
            str(RELEASES_YML),
            "--firmware-dir",
            str(fw_dir),
            "--evidence-dir",
            str(ev_1),
            "--config-dir",
            str(tmp_path / "cfg1"),
            "--skip-release-notes-gate",
            "--allow-unverified-checksums",
            "--fix",
        ],
    )
    assert res_1.exit_code == 0, res_1.output
    assert "request system configuration rescue save" in tr_1.commands_executed
    assert "file delete /var/tmp/old-stale.tgz" in tr_1.commands_executed
    assert "request system storage cleanup no-confirm" in tr_1.commands_executed
    assert not any("pkg " in c for c in tr_1.commands_executed)
    updated_1 = load_inventory(manifest_1)[0]
    assert updated_1.triage_verdict == TriageVerdict.ELIGIBLE.value
    assert updated_1.triage_reasons == []
    assert updated_1.state == SwitchState.READY
    assert updated_1.free_storage_mb == 400
    assert (ev_1 / "SITE" / "precheck" / sw_1.hostname / "rescue_save_fix.txt").is_file()

    # Case 2: active staged /var/tmp/<hop.package_filename> -> preserved, storage cleanup skipped, stale /var/tmp deleted
    manifest_2 = tmp_path / "inv2.json"
    sw_2 = _make_sw("FIX_KEEP_SW", "ex3400-48p", "23.2R2-S3")
    sw_2.state = SwitchState.STAGED
    sw_2.staged_package = f"/var/tmp/{hop.package_filename}"
    save_inventory([sw_2], manifest_2)

    tr_2 = StatefulRemediationTransport(
        sw_2.hostname,
        sw_2.model,
        sw_2.serial_number,
        sw_2.current_version,
        free_storage_mb=950,
        sys_alarms=(
            "1 alarms currently active\n"
            "2026-07-31 03:48:14 PDT  Minor  Rescue configuration is not set"
        ),
        var_tmp_output=(
            f"-rw-r--r-- 1 root wheel 250000000 Nov 24 12:00 {hop.package_filename}\n"
            "-rw-r--r-- 1 root wheel 200000000 Nov 01 12:00 stray-old.tgz\n"
        ),
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda creds: (lambda _sw: tr_2))

    res_2 = runner.invoke(
        cli_mod.main,
        [
            "precheck",
            "--manifest",
            str(manifest_2),
            "--releases",
            str(RELEASES_YML),
            "--firmware-dir",
            str(fw_dir),
            "--evidence-dir",
            str(tmp_path / "ev2"),
            "--config-dir",
            str(tmp_path / "cfg2"),
            "--skip-release-notes-gate",
            "--allow-unverified-checksums",
            "--fix",
        ],
    )
    assert res_2.exit_code == 0, res_2.output
    assert "request system configuration rescue save" in tr_2.commands_executed
    assert "file delete /var/tmp/stray-old.tgz" in tr_2.commands_executed
    assert f"file delete /var/tmp/{hop.package_filename}" not in tr_2.commands_executed
    assert "request system storage cleanup no-confirm" not in tr_2.commands_executed
    updated_2 = load_inventory(manifest_2)[0]
    assert updated_2.triage_verdict == TriageVerdict.ELIGIBLE.value
    assert updated_2.triage_reasons == []
    assert updated_2.state == SwitchState.STAGED


def test_precheck_fix_skips_remediation_on_identity_failure_or_replace_recommended(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario (d): precheck --fix skips remediation on identity mismatch or REPLACE_RECOMMENDED."""
    from click.testing import CliRunner

    import junos_upgrader.cli as cli_mod
    from junos_upgrader.inventory import load_inventory, save_inventory

    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    create_valid_tgz(fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename, "arm-32")

    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or TEST_ORIGIN),
    )

    runner = CliRunner()

    # 1. Identity mismatch (live model differs from manifest)
    manifest_id = tmp_path / "inv_id.json"
    sw_id = _make_sw("ID_FAIL_SW", "ex3400-48p", "23.2R2-S3")
    save_inventory([sw_id], manifest_id)
    tr_id = StatefulRemediationTransport(
        sw_id.hostname,
        "ex2300-24p",  # wrong live model -> identity_and_version hard_stop
        sw_id.serial_number,
        sw_id.current_version,
        free_storage_mb=400,
        sys_alarms=(
            "1 alarms currently active\n"
            "2026-07-31 03:48:14 PDT  Minor  Rescue configuration is not set"
        ),
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda creds: (lambda _sw: tr_id))
    res_id = runner.invoke(
        cli_mod.main,
        [
            "precheck",
            "--manifest",
            str(manifest_id),
            "--releases",
            str(RELEASES_YML),
            "--firmware-dir",
            str(fw_dir),
            "--evidence-dir",
            str(tmp_path / "ev_id"),
            "--config-dir",
            str(tmp_path / "cfg_id"),
            "--skip-release-notes-gate",
            "--allow-unverified-checksums",
            "--fix",
        ],
    )
    assert res_id.exit_code != 0
    assert _mutating_commands(tr_id.commands_executed) == []

    # 2. Hardware/FS fault (RO mount -> REPLACE_RECOMMENDED during initial triage)
    manifest_ro = tmp_path / "inv_ro.json"
    sw_ro = _make_sw("RO_FAIL_SW", "ex3400-48p", "23.2R2-S3")
    save_inventory([sw_ro], manifest_ro)
    tr_ro = StatefulRemediationTransport(
        sw_ro.hostname,
        sw_ro.model,
        sw_ro.serial_number,
        sw_ro.current_version,
        mount_output="/dev/gpt/junos on /.mount (ufs, local, read-only)\n",
        free_storage_mb=400,
        sys_alarms=(
            "1 alarms currently active\n"
            "2026-07-31 03:48:14 PDT  Minor  Rescue configuration is not set"
        ),
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda creds: (lambda _sw: tr_ro))
    res_ro = runner.invoke(
        cli_mod.main,
        [
            "precheck",
            "--manifest",
            str(manifest_ro),
            "--releases",
            str(RELEASES_YML),
            "--firmware-dir",
            str(fw_dir),
            "--evidence-dir",
            str(tmp_path / "ev_ro"),
            "--config-dir",
            str(tmp_path / "cfg_ro"),
            "--skip-release-notes-gate",
            "--allow-unverified-checksums",
            "--fix",
        ],
    )
    assert res_ro.exit_code != 0
    assert _mutating_commands(tr_ro.commands_executed) == []
    assert load_inventory(manifest_ro)[0].state == SwitchState.REPLACE_RECOMMENDED


def test_precheck_fix_purge_previous_pkg_conditional_on_storage_and_platform(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario (e): --purge-previous-pkg runs only when EX2300/EX3400 remains below floor."""
    from click.testing import CliRunner

    import junos_upgrader.cli as cli_mod
    from junos_upgrader.inventory import load_inventory, save_inventory

    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol_ex3400 = match_platform_policy("ex3400-48p", policies)
    pol_ex4400 = match_platform_policy("ex4400-48p", policies)
    assert pol_ex3400 is not None
    assert pol_ex4400 is not None

    fw_dir = tmp_path / "fw"
    hop34 = pol_ex3400.hops[-1]
    hop44 = pol_ex4400.hops[-1]
    create_valid_tgz(fw_dir / "juniper" / "ex3400" / hop34.train / hop34.package_filename, "arm-32")
    create_valid_tgz(fw_dir / "juniper" / "ex4400" / hop44.train / hop44.package_filename, "x86-64")

    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or TEST_ORIGIN),
    )

    runner = CliRunner()

    # 1. EX3400: first run `--fix` alone leaves storage below floor -> stays READY / needs-remediation (NOT REPLACE_RECOMMENDED)
    manifest_1 = tmp_path / "inv_purge.json"
    sw_1 = _make_sw("PURGE_EX3400", "ex3400-48p", "23.2R2-S3")
    save_inventory([sw_1], manifest_1)
    tr_1 = StatefulRemediationTransport(
        sw_1.hostname,
        sw_1.model,
        sw_1.serial_number,
        sw_1.current_version,
        free_storage_mb=150,
        cleanup_reclaim_mb=50,  # 200 MB < 250 MB floor
        pkg_purge_reclaim_mb=200,  # 400 MB >= 250 MB floor
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda creds: (lambda _sw: tr_1))

    ev_1 = tmp_path / "ev_purge"
    base_args_1 = [
        "precheck",
        "--manifest",
        str(manifest_1),
        "--releases",
        str(RELEASES_YML),
        "--firmware-dir",
        str(fw_dir),
        "--evidence-dir",
        str(ev_1),
        "--config-dir",
        str(tmp_path / "cfg_purge"),
        "--skip-release-notes-gate",
        "--allow-unverified-checksums",
        "--fix",
    ]
    res_no_purge = runner.invoke(cli_mod.main, base_args_1)
    assert res_no_purge.exit_code != 0
    mid_sw = load_inventory(manifest_1)[0]
    assert mid_sw.state == SwitchState.READY  # NOT quarantined as REPLACE_RECOMMENDED
    assert mid_sw.triage_verdict == TriageVerdict.NEEDS_REMEDIATION.value
    assert not any("pkg " in c for c in tr_1.commands_executed)

    # Re-run with `--fix --purge-previous-pkg` without reset-state -> runs pkg purge and recovers to ELIGIBLE
    res_purge = runner.invoke(cli_mod.main, [*base_args_1, "--purge-previous-pkg"])
    assert res_purge.exit_code == 0, res_purge.output
    assert 'start shell command "pkg setop rm previous"' in tr_1.commands_executed
    assert 'start shell command "pkg delete old"' in tr_1.commands_executed
    assert (ev_1 / "SITE" / "precheck" / sw_1.hostname / "pkg_purge_previous.txt").is_file()
    final_sw = load_inventory(manifest_1)[0]
    assert final_sw.triage_verdict == TriageVerdict.ELIGIBLE.value
    assert final_sw.triage_reasons == []
    assert final_sw.state == SwitchState.READY
    assert final_sw.free_storage_mb == 400

    # 2. EX3400 where standard cleanup already reaches floor -> skips pkg purge commands
    manifest_2 = tmp_path / "inv_enough.json"
    sw_2 = _make_sw("ENOUGH_EX3400", "ex3400-48p", "23.2R2-S3")
    save_inventory([sw_2], manifest_2)
    tr_2 = StatefulRemediationTransport(
        sw_2.hostname,
        sw_2.model,
        sw_2.serial_number,
        sw_2.current_version,
        free_storage_mb=150,
        cleanup_reclaim_mb=200,  # 350 MB >= 250 MB floor already met
        pkg_purge_reclaim_mb=200,
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda creds: (lambda _sw: tr_2))
    res_enough = runner.invoke(
        cli_mod.main,
        [
            "precheck",
            "--manifest",
            str(manifest_2),
            "--releases",
            str(RELEASES_YML),
            "--firmware-dir",
            str(fw_dir),
            "--evidence-dir",
            str(tmp_path / "ev_enough"),
            "--config-dir",
            str(tmp_path / "cfg_enough"),
            "--skip-release-notes-gate",
            "--allow-unverified-checksums",
            "--fix",
            "--purge-previous-pkg",
        ],
    )
    assert res_enough.exit_code == 0, res_enough.output
    assert not any("pkg " in c for c in tr_2.commands_executed)

    # 3. Non-EX2300/EX3400 platform (EX4400) -> skips pkg purge commands even below floor
    manifest_3 = tmp_path / "inv_ex4400.json"
    sw_3 = _make_sw("SKIP_EX4400", "ex4400-48p", "22.4R3-S7")
    save_inventory([sw_3], manifest_3)
    tr_3 = StatefulRemediationTransport(
        sw_3.hostname,
        sw_3.model,
        sw_3.serial_number,
        sw_3.current_version,
        pkg_arch_tag="junos-ex-4400",
        free_storage_mb=400,
        cleanup_reclaim_mb=0,
        pkg_purge_reclaim_mb=500,
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda creds: (lambda _sw: tr_3))
    res_ex44 = runner.invoke(
        cli_mod.main,
        [
            "precheck",
            "--manifest",
            str(manifest_3),
            "--releases",
            str(RELEASES_YML),
            "--firmware-dir",
            str(fw_dir),
            "--evidence-dir",
            str(tmp_path / "ev_ex44"),
            "--config-dir",
            str(tmp_path / "cfg_ex44"),
            "--skip-release-notes-gate",
            "--allow-unverified-checksums",
            "--fix",
            "--purge-previous-pkg",
        ],
    )
    assert res_ex44.exit_code != 0
    assert not any("pkg " in c for c in tr_3.commands_executed)


def test_precheck_fix_with_aaa_only_ssh_gate_applies_safe_fixes_but_keeps_lockout_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario (f): precheck --fix still remediates triage while preserving local_ssh_fallback block."""
    from click.testing import CliRunner

    import junos_upgrader.cli as cli_mod
    from junos_upgrader.inventory import load_inventory, save_inventory

    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]

    fw_dir = tmp_path / "fw"
    create_valid_tgz(fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename, "arm-32")

    aaa_only_cfg = (
        "set system authentication-order [ radius password ]\n"
        "set system login user remote class super-user\n"
        "set system services ssh root-login deny\n"
    )
    manifest = tmp_path / "inv_aaa.json"
    sw = _make_sw("AAA_FIX_SW", "ex3400-48p", "23.2R2-S3")
    save_inventory([sw], manifest)

    tr = StatefulRemediationTransport(
        sw.hostname,
        sw.model,
        sw.serial_number,
        sw.current_version,
        free_storage_mb=150,
        cleanup_reclaim_mb=250,
        config_set_extra=aaa_only_cfg,
        sys_alarms=(
            "1 alarms currently active\n"
            "2026-07-31 03:48:14 PDT  Minor  Rescue configuration is not set"
        ),
    )

    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or TEST_ORIGIN),
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda creds: (lambda _sw: tr))

    runner = CliRunner()
    base_args = [
        "precheck",
        "--manifest",
        str(manifest),
        "--releases",
        str(RELEASES_YML),
        "--firmware-dir",
        str(fw_dir),
        "--evidence-dir",
        str(tmp_path / "ev"),
        "--config-dir",
        str(tmp_path / "cfg"),
        "--skip-release-notes-gate",
        "--allow-unverified-checksums",
        "--fix",
    ]

    # Without --allow-aaa-only-ssh: safe triage fixes run, but local_ssh_fallback hard-stop still fails
    res_blk = runner.invoke(cli_mod.main, base_args)
    assert res_blk.exit_code != 0
    assert "request system configuration rescue save" in tr.commands_executed
    assert "request system storage cleanup no-confirm" in tr.commands_executed
    reloaded = load_inventory(manifest)[0]
    assert reloaded.triage_verdict == TriageVerdict.ELIGIBLE.value
    assert reloaded.triage_reasons == []
    assert "aaa" in reloaded.last_error.lower() or "ssh" in reloaded.last_error.lower()

    # With --allow-aaa-only-ssh: passes with WARN
    res_ok = runner.invoke(cli_mod.main, [*base_args, "--allow-aaa-only-ssh"])
    assert res_ok.exit_code == 0, res_ok.output
    assert "WARN" in res_ok.output
    reloaded_ok = load_inventory(manifest)[0]
    assert reloaded_ok.state == SwitchState.READY
    assert reloaded_ok.last_error == ""


def test_precheck_fix_order_live_alarms_and_explicit_fallback_user_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner
    from conftest import create_valid_tgz

    import junos_upgrader.cli as cli_mod
    from junos_upgrader.inventory import load_inventory, save_inventory
    from junos_upgrader.junos_client import parse_ssh_public_key, validate_fallback_username

    # Username & SSH key validation
    assert validate_fallback_username("localadmin") == "localadmin"
    for bad in ("root", "ROOT", "bad;user", "../x", ""):
        with pytest.raises(ValueError):
            validate_fallback_username(bad)
    ktype, kclean = parse_ssh_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@host\n")
    assert ktype == "ssh-ed25519" and kclean == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"

    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None
    hop = pol.hops[-1]
    fw_dir = tmp_path / "fw"
    _, md5_hex, _ = create_valid_tgz(
        fw_dir / "juniper" / "ex3400" / hop.train / hop.package_filename
    )
    rel_copy = tmp_path / "approved-releases.yml"
    rel_text = RELEASES_YML.read_text(encoding="utf-8")
    rel_text = rel_text.replace("REPLACE_WITH_JUNIPER_MD5", md5_hex)
    rel_text = rel_text.replace("release_notes_reviewed: false", "release_notes_reviewed: true")
    rel_copy.write_text(rel_text, encoding="utf-8")

    sw = _make_sw("AAA_FIX_SW", "ex3400-48p", "23.2R2-S3")
    manifest = tmp_path / "site-inventory.json"
    save_inventory([sw], manifest)

    # Pre-seed a STALE show_system_alarms.txt saying "No alarms currently active"
    ev_dir = tmp_path / "ev"
    stale_ev = ev_dir / sw.site / "precheck" / sw.hostname
    stale_ev.mkdir(parents=True)
    (stale_ev / "show_system_alarms.txt").write_text("No alarms currently active\n", encoding="utf-8")

    pub_key_file = tmp_path / "fallback.pub"
    pub_key_file.write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey netops@host\n", encoding="utf-8"
    )

    tr = FakeJunosTransport(
        sw.hostname,
        sw.model,
        sw.serial_number,
        sw.current_version,
        free_storage_mb=450,
        sys_alarms=(
            "1 alarms currently active\n"
            "2026-07-31 03:48:14 PDT  Minor  Rescue configuration is not set"
        ),
        config_set_extra=(
            "set system authentication-order radius\n"
            "set system login user remote class super-user"
        ),
    )
    monkeypatch.setattr(cli_mod, "_make_transport_factory", lambda _creds: (lambda _sw: tr))

    runner = CliRunner()
    common = [
        "precheck",
        "--manifest",
        str(manifest),
        "--releases",
        str(rel_copy),
        "--firmware-dir",
        str(fw_dir),
        "--evidence-dir",
        str(ev_dir),
        "--config-dir",
        str(tmp_path / "cfg"),
        "--username",
        "netops",
        "--password",
        "valid-pw",
    ]

    # 1. --create-fallback-user requires --fix
    res_nofix = runner.invoke(
        cli_mod.main, [*common, "--create-fallback-user", "localadmin", "--fallback-ssh-key", str(pub_key_file)]
    )
    assert res_nofix.exit_code != 0
    assert "--create-fallback-user requires --fix" in res_nofix.output

    # 2. Declining interactive confirmation aborts cleanly without touching switch
    res_decline = runner.invoke(
        cli_mod.main,
        [*common, "--fix", "--create-fallback-user", "localadmin", "--fallback-ssh-key", str(pub_key_file)],
        input="n\n",
    )
    assert res_decline.exit_code != 0
    assert "not approved" in res_decline.output.lower()
    assert tr.commands_executed == []

    # 3. Approving interactively creates fallback user, cleans storage BEFORE rescue save,
    #    ignores stale show_system_alarms.txt, and transitions AAA-only switch to PASS!
    res_approve = runner.invoke(
        cli_mod.main,
        [*common, "--fix", "--create-fallback-user", "localadmin", "--fallback-ssh-key", str(pub_key_file)],
        input="y\n",
    )
    assert res_approve.exit_code == 0, res_approve.output
    assert "PASS" in res_approve.output
    assert "configure_local_fallback_user:localadmin" in tr.commands_executed
    cleanup_idx = tr.commands_executed.index("request system storage cleanup no-confirm")
    rescue_idx = tr.commands_executed.index("request system configuration rescue save")
    assert cleanup_idx < rescue_idx
    reloaded = load_inventory(manifest)[0]
    assert reloaded.state == SwitchState.READY
    assert reloaded.last_error == ""


