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
