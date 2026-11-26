# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for daisy-chain topology wave scheduling, hardware/FS triage, package scan, and HTTP UI."""

from __future__ import annotations

import ipaddress
import json
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from click.testing import CliRunner
from conftest import FakeJunosTransport

from junos_upgrader.checks import (
    _extract_poe_watts,
    evaluate_hardware_and_fs_triage,
    parse_junos_storage,
    run_postchecks,
)
from junos_upgrader.cli import main
from junos_upgrader.firmware_fetcher import scan_and_ingest_directory
from junos_upgrader.inventory import load_inventory, save_inventory
from junos_upgrader.models import NeighborExpectation, SwitchRecord, SwitchState, TriageVerdict
from junos_upgrader.orchestrator import UpgradeOptions, run_upgrade_batches
from junos_upgrader.packages import extract_switch_arch, inspect_local_tgz
from junos_upgrader.planner import load_release_catalog, match_platform_policy
from junos_upgrader.topology import (
    RunnerOrigin,
    build_topology_graph,
    compute_topology_waves,
    detect_local_runner_origin,
    mark_ancestor_holds,
    redact_topology_graph,
)
from junos_upgrader.transfer import UnifiedFirmwareServer
from junos_upgrader.web_ui import export_topology_markdown, render_topology_html

RELEASES_YML = Path(__file__).resolve().parents[1] / "manifests" / "approved-releases.yml"
TEST_ORIGIN = RunnerOrigin(
    hostname="TEST-RUNNER",
    outbound_ip="192.0.2.250",
    outbound_iface="eth0",
    gateway_ip="192.0.2.254",
)


def _sw(
    host: str,
    ip: str,
    role: str = "Access",
    neighbors: list[NeighborExpectation] | None = None,
    mac: str = "",
    state: SwitchState = SwitchState.READY,
) -> SwitchRecord:
    return SwitchRecord(
        site="SITE",
        hostname=host,
        management_ip=ip,
        model="ex3400-48p",
        serial_number=f"SN_{host}",
        current_version="23.2R2-S3",
        role=role,
        management_method="SSH",
        mac_address=mac,
        state=state,
        expected_neighbors=neighbors or [],
    )


def test_daisy_chain_leaf_first_and_ancestor_hold(tmp_path: Path) -> None:
    core = _sw(
        "CORE_1",
        "192.0.2.1",
        role="Core",
        neighbors=[NeighborExpectation("xe-0/0/1", "TRANSIT_1", "xe-0/2/0")],
    )
    transit = _sw(
        "TRANSIT_1",
        "192.0.2.2",
        neighbors=[
            NeighborExpectation("xe-0/2/0", "CORE_1", "xe-0/0/1", is_upstream=True),
            NeighborExpectation("ge-0/0/10", "LEAF_1", "ge-0/2/0"),
        ],
    )
    leaf1 = _sw(
        "LEAF_1",
        "192.0.2.3",
        neighbors=[
            NeighborExpectation("ge-0/2/0", "TRANSIT_1", "ge-0/0/10", is_upstream=True),
            NeighborExpectation("ge-0/0/11", "LEAF_2", "ge-0/2/0"),
        ],
    )
    leaf2 = _sw(
        "LEAF_2",
        "192.0.2.4",
        neighbors=[NeighborExpectation("ge-0/2/0", "LEAF_1", "ge-0/0/11", is_upstream=True)],
    )
    indep_leaf = _sw(
        "INDEP_LEAF",
        "192.0.2.5",
        neighbors=[NeighborExpectation("ge-0/2/0", "CORE_1", "xe-0/0/2", is_upstream=True)],
    )
    # Connect CORE_1 -> INDEP_LEAF
    core.expected_neighbors.append(NeighborExpectation("xe-0/0/2", "INDEP_LEAF", "ge-0/2/0"))

    all_sw = [core, transit, leaf1, leaf2, indep_leaf]
    graph = build_topology_graph(all_sw, origin=TEST_ORIGIN)

    assert core.topology_depth == 1
    assert transit.topology_depth == 2
    assert leaf1.topology_depth == 3
    assert leaf2.topology_depth == 4
    assert indep_leaf.topology_depth == 2

    waves = compute_topology_waves(all_sw, graph, batch_size=3, include_cores=False)
    # Core excluded; LEAF_2 (depth 4) and INDEP_LEAF (depth 2, independent branch) can pair,
    # whereas LEAF_1 / TRANSIT_1 are ancestors of LEAF_2 so cannot share Wave 1!
    wave1_names = {s.hostname for s in waves[0]}
    assert "LEAF_2" in wave1_names
    assert "INDEP_LEAF" in wave1_names
    assert "LEAF_1" not in wave1_names
    assert "TRANSIT_1" not in wave1_names
    assert "CORE_1" not in {s.hostname for w in waves for s in w}

    # If LEAF_2 fails (e.g. read-only flash -> REPLACE_RECOMMENDED), LEAF_1 & TRANSIT_1 must be held!
    _, policies, exclusions = load_release_catalog(RELEASES_YML)

    def factory(sw: SwitchRecord) -> FakeJunosTransport:
        return FakeJunosTransport(
            hostname=sw.hostname,
            model=sw.model,
            serial_number=sw.serial_number,
            running_version=sw.current_version,
            mount_output=(
                "/dev/gpt/junos on /.mount (ufs, local, read-only)\n"
                if sw.hostname == "LEAF_2"
                else "/dev/gpt/junos on /.mount (ufs, local)\n"
            ),
        )

    opts = UpgradeOptions(
        firmware_base_url="http://localhost",
        firmware_dir=tmp_path / "fw",
        evidence_root=tmp_path / "ev",
        config_root=tmp_path / "cfg",
        manifest_path=tmp_path / "manifest.json",
        change_number="CHG_TOPO",
        operator="netops",
        batch_size=1,
        require_release_notes=False,
        reboot_poll_interval=0.0,
        reboot_wait_down_seconds=0.0,
        post_settle_seconds=0.0,
    )
    _, wave_ok = run_upgrade_batches(
        all_sw, all_sw, policies, exclusions, factory, opts, graph=graph
    )
    assert not wave_ok
    assert leaf2.state == SwitchState.REPLACE_RECOMMENDED
    assert leaf1.state == SwitchState.ANCESTOR_HOLD
    assert transit.state == SwitchState.ANCESTOR_HOLD

    md_path = export_topology_markdown(graph, tmp_path / "topo.md")
    assert "LEAF_2" in md_path.read_text(encoding="utf-8")


def test_disconnected_component_preserves_depth_ancestors_and_leaf_first_waves() -> None:
    core = _sw("CORE_1", "192.0.2.10", role="Core")
    transit = _sw(
        "IDF_A_TRANSIT",
        "192.0.2.11",
        neighbors=[NeighborExpectation("ge-0/0/1", "IDF_B_LEAF", "ge-0/2/0")],
    )
    leaf = _sw(
        "IDF_B_LEAF",
        "192.0.2.12",
        neighbors=[NeighborExpectation("ge-0/2/0", "IDF_A_TRANSIT", "ge-0/0/1", is_upstream=True)],
    )
    deep_leaf = _sw(
        "IDF_C_DEEP",
        "192.0.2.13",
        neighbors=[NeighborExpectation("ge-0/2/0", "IDF_B_LEAF", "ge-0/0/2", is_upstream=True)],
    )
    leaf.expected_neighbors.append(NeighborExpectation("ge-0/0/2", "IDF_C_DEEP", "ge-0/2/0"))

    all_sw = [core, transit, leaf, deep_leaf]
    graph = build_topology_graph(all_sw, origin=TEST_ORIGIN)

    assert transit.topology_depth == 1
    assert leaf.topology_depth == 2
    assert deep_leaf.topology_depth == 3
    assert graph.ancestors["IDF_B_LEAF"] == {"IDF_A_TRANSIT"}
    assert graph.ancestors["IDF_C_DEEP"] == {"IDF_A_TRANSIT", "IDF_B_LEAF"}

    waves = compute_topology_waves(all_sw, graph, batch_size=3, include_cores=False)
    assert [[s.hostname for s in w] for w in waves] == [
        ["IDF_C_DEEP"],
        ["IDF_B_LEAF"],
        ["IDF_A_TRANSIT"],
    ]

    held = mark_ancestor_holds(deep_leaf, all_sw, graph)
    assert set(held) == {"IDF_A_TRANSIT", "IDF_B_LEAF"}
    assert transit.state == SwitchState.ANCESTOR_HOLD
    assert leaf.state == SwitchState.ANCESTOR_HOLD


def test_stp_explicit_upstream_respected_when_true_parent_already_queued() -> None:
    # Triangle: CORE -> SW_B, CORE -> SW_A (STP-blocked), SW_B -> SW_A (SW_A's STP root port)
    core = _sw(
        "CORE",
        "192.0.2.20",
        role="Core",
        neighbors=[
            NeighborExpectation("xe-0/0/1", "SW_B", "xe-0/2/0"),
            NeighborExpectation("xe-0/0/2", "SW_A", "xe-0/2/1"),
        ],
    )
    sw_b = _sw(
        "SW_B",
        "192.0.2.21",
        neighbors=[
            NeighborExpectation("xe-0/2/0", "CORE", "xe-0/0/1", is_upstream=True),
            NeighborExpectation("ge-0/0/1", "SW_A", "ge-0/2/0"),
        ],
    )
    sw_a = _sw(
        "SW_A",
        "192.0.2.22",
        neighbors=[
            NeighborExpectation("ge-0/2/0", "SW_B", "ge-0/0/1", is_upstream=True),
            NeighborExpectation("xe-0/2/1", "CORE", "xe-0/0/2", is_upstream=False),
        ],
    )
    graph = build_topology_graph([core, sw_b, sw_a], origin=TEST_ORIGIN)
    assert sw_b.topology_depth == 2
    assert sw_a.topology_depth == 3
    assert sw_a.upstream_switch == "SW_B"
    assert sw_a.upstream_local_port == "ge-0/2/0"
    assert graph.ancestors["SW_A"] == {"CORE", "SW_B"}


def test_explicit_upstream_cycle_terminates_and_places_all_nodes() -> None:
    core = _sw(
        "CORE",
        "192.0.2.30",
        role="Core",
        neighbors=[NeighborExpectation("xe-0/0/1", "SW_A", "xe-0/2/0")],
    )
    sw_a = _sw(
        "SW_A",
        "192.0.2.31",
        neighbors=[
            NeighborExpectation("xe-0/2/0", "CORE", "xe-0/0/1"),
            NeighborExpectation("ge-0/0/1", "SW_B", "ge-0/0/1", is_upstream=True),
        ],
    )
    sw_b = _sw(
        "SW_B",
        "192.0.2.32",
        neighbors=[NeighborExpectation("ge-0/0/1", "SW_A", "ge-0/0/1", is_upstream=True)],
    )
    graph = build_topology_graph([core, sw_a, sw_b], origin=TEST_ORIGIN)
    assert core.topology_depth == 1
    assert sw_a.topology_depth == 2
    assert sw_b.topology_depth == 3
    assert graph.ancestors["SW_B"] == {"CORE", "SW_A"}


def test_empty_gateway_ip_fqdn_mac_core_behind_core_and_duplicate_hostnames() -> None:
    # 1. Empty gateway_ip must NOT match unmanaged AP with remote_ip=""
    origin_no_gw = RunnerOrigin("TEST-RUNNER", "192.0.2.250", "eth0", "")
    core_gw = _sw(
        "CORE_1",
        "192.0.2.40",
        role="Core",
        mac="00:00:5e:00:53:40",
        neighbors=[
            NeighborExpectation("ge-0/0/5", "AP-LOBBY-01", "eth0", remote_ip="", is_upstream=False)
        ],
    )
    # 2. Core-behind-Core: CORE_2 points upstream to CORE_1 using FQDN + different case
    core_2 = _sw(
        "CORE_2",
        "192.0.2.41",
        role="Core",
        mac="00:00:5e:00:53:41",
        neighbors=[
            NeighborExpectation(
                "xe-0/2/0", "core_1.corp.example", "xe-0/0/1", remote_ip="", is_upstream=True
            )
        ],
    )
    # 3. Leaf links to CORE_2 by remote_mac only (remote_device is chassis MAC, no remote_ip)
    leaf_mac = _sw(
        "LEAF_MAC",
        "192.0.2.42",
        neighbors=[
            NeighborExpectation(
                "ge-0/2/0",
                "UNKNOWN_SYSNAME",
                "xe-0/0/2",
                remote_ip="",
                remote_mac="0000.5e00.5341",
                is_upstream=True,
            )
        ],
    )
    # 4. Duplicate hostname entry handled cleanly without duplicate edges
    dup_leaf = _sw("LEAF_MAC", "192.0.2.42")

    graph = build_topology_graph([core_gw, core_2, leaf_mac, dup_leaf], origin=origin_no_gw)
    assert core_gw.upstream_switch == "TEST-RUNNER"
    assert core_gw.upstream_local_port == ""
    assert core_2.topology_depth == 2
    assert core_2.upstream_switch == "CORE_1"
    assert leaf_mac.topology_depth == 3
    assert leaf_mac.upstream_switch == "CORE_2"
    assert dup_leaf.topology_depth == 3
    assert len(graph.edges) == 3  # __runner__->CORE_1, CORE_1->CORE_2, CORE_2->LEAF_MAC


def test_preexisting_failed_descendant_holds_ancestors_and_appends_errors() -> None:
    core = _sw("CORE_1", "192.0.2.60", role="Core")
    transit = _sw(
        "TRANSIT_1",
        "192.0.2.61",
        neighbors=[NeighborExpectation("xe-0/2/0", "CORE_1", "xe-0/0/1", is_upstream=True)],
    )
    leaf_bad = _sw(
        "LEAF_BAD",
        "192.0.2.62",
        state=SwitchState.REPLACE_RECOMMENDED,
        neighbors=[NeighborExpectation("ge-0/2/0", "TRANSIT_1", "ge-0/0/1", is_upstream=True)],
    )
    leaf_bad2 = _sw(
        "LEAF_BAD_2",
        "192.0.2.63",
        state=SwitchState.FAILED,
        neighbors=[NeighborExpectation("ge-0/2/0", "TRANSIT_1", "ge-0/0/2", is_upstream=True)],
    )
    leaf_ok = _sw(
        "LEAF_OK",
        "192.0.2.64",
        neighbors=[NeighborExpectation("ge-0/2/0", "CORE_1", "xe-0/0/2", is_upstream=True)],
    )
    all_sw = [core, transit, leaf_bad, leaf_bad2, leaf_ok]
    graph = build_topology_graph(all_sw, origin=TEST_ORIGIN)

    # Even when targets only includes TRANSIT_1 and LEAF_OK, TRANSIT_1 must be excluded!
    waves = compute_topology_waves([transit, leaf_ok], graph, batch_size=2, include_cores=False)
    assert [[s.hostname for s in w] for w in waves] == [["LEAF_OK"]]

    # mark_ancestor_holds appends (not overwrites) multiple downstream failures cleanly
    mark_ancestor_holds(leaf_bad, all_sw, graph)
    mark_ancestor_holds(leaf_bad2, all_sw, graph)
    mark_ancestor_holds(leaf_bad2, all_sw, graph)  # deduplicated repeat
    assert transit.state == SwitchState.ANCESTOR_HOLD
    assert "LEAF_BAD" in transit.last_error
    assert "LEAF_BAD_2" in transit.last_error
    assert transit.last_error.count("LEAF_BAD_2") == 1


def test_redact_topology_graph_redaction_map_and_large_fleet_ips() -> None:
    switches = [_sw(f"SITE_SW_{i:03d}", f"198.51.100.{(i % 250) + 1}") for i in range(1, 521)]
    graph = build_topology_graph(switches, origin=TEST_ORIGIN)
    redacted = redact_topology_graph(graph)

    assert len(redacted.redaction_map) == 520
    assert redacted.redaction_map["SITE_SW_001"] == "SW-01"
    assert redacted.redaction_map["SITE_SW_520"] == "SW-520"

    seen_ips: set[str] = set()
    for node_id, node in redacted.nodes.items():
        if node_id == "__runner__":
            continue
        ip_str = node["ip"]
        addr = ipaddress.IPv4Address(ip_str)
        last_octet = int(ip_str.rsplit(".", 1)[-1])
        assert 1 <= last_octet <= 254, f"Invalid host octet in {ip_str}"
        assert str(addr) not in seen_ips
        seen_ips.add(str(addr))


def test_detect_local_runner_origin_rejects_option_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called_cmds: list[list[str]] = []

    def fake_check_output(cmd: list[str], **_kwargs: object) -> str:
        called_cmds.append(cmd)
        return "default via 192.0.2.1 dev eth0\n"

    monkeypatch.setattr("junos_upgrader.topology.subprocess.check_output", fake_check_output)
    monkeypatch.setattr("junos_upgrader.topology.detect_outbound_ip", lambda _ip: "192.0.2.10")
    monkeypatch.setattr("junos_upgrader.topology.socket.gethostname", lambda: "TEST-HOST")

    origin = detect_local_runner_origin("-V")
    assert origin.hostname == "TEST-HOST"
    assert origin.gateway_ip == "192.0.2.1"
    # Must NOT have invoked `ip route get -V`
    assert all("get" not in cmd for cmd in called_cmds)


def test_hardware_fs_replace_triage_triggers(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    # 1. Flash I/O error + Fan Failure -> REPLACE_RECOMMENDED + quarantine backup written
    sw = _sw("BAD_FLASH_SW", "192.0.2.9")
    tr = FakeJunosTransport(
        hostname=sw.hostname,
        model=sw.model,
        serial_number=sw.serial_number,
        running_version=sw.current_version,
        flash_log_output="kernel: g_vfs_done():da0s1a[READ(offset=1024)]error = 5",
        chassis_env="Fan FPC 0 Fan Tray 0 Failed\n",
    )
    verdict, _ = evaluate_hardware_and_fs_triage(
        tr, sw, pol, tmp_path / "ev", tmp_path / "cfg", execute_cleanup=False
    )
    assert verdict == TriageVerdict.REPLACE_RECOMMENDED
    assert sw.state == SwitchState.REPLACE_RECOMMENDED
    assert (
        tmp_path / "cfg" / "SITE" / "BAD_FLASH_SW" / "quarantine_backup" / "config.set.txt"
    ).exists()

    # 2. Crash dump in /var/crash triggers REPLACE_RECOMMENDED unless ignore_old_cores=True
    sw2 = _sw("CRASH_SW", "192.0.2.10")
    tr2 = FakeJunosTransport(
        hostname=sw2.hostname,
        model=sw2.model,
        serial_number=sw2.serial_number,
        running_version=sw2.current_version,
        crash_files_output="-rw------- 1 root wheel 1234567 Nov 10 /var/crash/vmcore.0\n",
    )
    verdict2, _ = evaluate_hardware_and_fs_triage(
        tr2, sw2, pol, tmp_path / "ev2", tmp_path / "cfg2", ignore_old_cores=False
    )
    assert verdict2 == TriageVerdict.REPLACE_RECOMMENDED

    sw3 = _sw("OPTICS_SW", "192.0.2.11")
    tr3 = FakeJunosTransport(
        hostname=sw3.hostname,
        model=sw3.model,
        serial_number=sw3.serial_number,
        running_version=sw3.current_version,
        optics_output="Physical interface: xe-0/2/0\n    Laser rx power low alarm : ON\n",
    )
    verdict3, _ = evaluate_hardware_and_fs_triage(
        tr3, sw3, pol, tmp_path / "ev3", tmp_path / "cfg3"
    )
    assert verdict3 == TriageVerdict.REPLACE_RECOMMENDED

    # 3. Real EX2300 cd9660 root + rw /.mount + UI_CMDLINE echo + Minor /var usage alarm -> NEEDS_REMEDIATION (not REPLACE)
    sw4 = _sw("EX2300_LIVE_LIKE", "192.0.2.12")
    tr4 = FakeJunosTransport(
        hostname=sw4.hostname,
        model="ex2300-c-12p",
        serial_number=sw4.serial_number,
        running_version="23.4R2.13",
        free_storage_mb=306,
        mount_output=(
            "/dev/md0.uzip on / (cd9660, local, read-only)\n"
            "/dev/gpt/junos on /.mount (ufs, local, noatime, soft-updates)\n"
        ),
        flash_log_output=(
            "Nov 22 01:12:13 lab-ex2300c-01 mgd[42]: UI_CMDLINE_READ_LINE: "
            "User 'root', command 'show log messages | match \"g_vfs_done|Input/output error\"'\n"
        ),
        alarms="1 alarms currently active\nAlarm time Class Description\n2026-11-14 Minor RE 0 /var partition usage is high",
    )
    pol2300 = match_platform_policy("ex2300-c-12p", policies)
    assert pol2300 is not None
    verdict4, checks4 = evaluate_hardware_and_fs_triage(
        tr4, sw4, pol2300, tmp_path / "ev4", tmp_path / "cfg4"
    )
    assert verdict4 == TriageVerdict.NEEDS_REMEDIATION
    assert all(c.passed for c in checks4 if c.hard_stop)


def test_firmware_scan_rejects_html_and_ingests_valid_tgz(tmp_path: Path) -> None:
    # Copy releases manifest to tmp_path so test can safely mutate MD5
    rel_copy = tmp_path / "approved-releases.yml"
    rel_copy.write_text(RELEASES_YML.read_text(encoding="utf-8"), encoding="utf-8")
    _, policies, _ = load_release_catalog(rel_copy)

    scan_dir = tmp_path / "downloads"
    fw_dir = tmp_path / "firmware"
    scan_dir.mkdir()

    # Fake HTML login page saved as .tgz must be rejected
    bad_tgz = scan_dir / "junos-arm-32-23.4R2-S8.tgz"
    bad_tgz.write_text("<html><body>Sign In</body></html>", encoding="utf-8")
    assert not inspect_local_tgz(bad_tgz).valid_tgz

    # Replace with valid tar.gz archive for EX4300-48MP
    bad_tgz.unlink()
    good_tgz = scan_dir / "jinstall-host-ex-4300mp-23.4R2-S8-signed.tgz"
    stub = tmp_path / "+COMMENT"
    stub.write_text("vmhost ex4300mp", encoding="utf-8")
    with tarfile.open(good_tgz, "w:gz") as tf:
        tf.add(stub, arcname="+COMMENT")

    res = scan_and_ingest_directory(scan_dir, fw_dir, rel_copy, policies, update_manifest=True)
    assert res[0]["status"] == "ingested"
    dest = Path(res[0]["file"])
    assert dest.exists()

    # Verify UnifiedFirmwareServer serves both /firmware/<token>/... and /api/topology & blocks traversal
    with UnifiedFirmwareServer(
        firmware_dir=fw_dir,
        port=0,
        topology_provider=lambda: {"origin": {"hostname": "test"}, "nodes": [], "edges": []},
        html_provider=render_topology_html,
    ) as srv:
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/api/topology") as r:
            assert b'"origin"' in r.read()
        tok = getattr(srv, "token", "")
        fw_prefix = f"/firmware/{tok}" if tok else "/firmware"
        with urllib.request.urlopen(
            f"http://127.0.0.1:{srv.port}{fw_prefix}/juniper/ex4300-48mp/23.4R2-S8/{good_tgz.name}"
        ) as r:
            assert len(r.read()) > 10
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"http://127.0.0.1:{srv.port}{fw_prefix}/../../etc/passwd")
        assert exc_info.value.code in (403, 404)


def test_ex3400_sanitized_live_evidence_replay(tmp_path: Path) -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    pol = match_platform_policy("ex3400-48p", policies)
    assert pol is not None

    show_version_json = json.dumps(
        {
            "multi-routing-engine-results": [
                {
                    "multi-routing-engine-item": [
                        {
                            "re-name": [{"data": "fpc0"}],
                            "software-information": [
                                {
                                    "host-name": [{"data": "LAB-EX3400-01"}],
                                    "product-model": [{"data": "ex3400-48p"}],
                                    "junos-version": [{"data": "18.1R3-S12.2"}],
                                    "package-information": [
                                        {
                                            "name": [{"data": "junos-ex-3400"}],
                                            "comment": [{"data": "JUNOS EX  Software Suite [18.1R3-S12.2]"}],
                                        },
                                        {
                                            "name": [{"data": "os-kernel"}],
                                            "comment": [{"data": "JUNOS OS Kernel 32-bit [20201105]"}],
                                        },
                                        {
                                            "name": [{"data": "os-runtime-arm-32"}],
                                            "comment": [{"data": "JUNOS OS Runtime 32-bit"}],
                                        },
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
    )
    assert extract_switch_arch(show_version_json) == "arm-32"

    # Also verify "name"-only detection + defensive handling of [] / None fields
    name_only_evo_json = json.dumps(
        {
            "software-information": [
                {
                    "product-model": [{"data": "generic-switch"}],
                    "package-information": [
                        {"package-name": [], "name": None, "comment": None},
                        {
                            "package-name": [],
                            "name": [{"data": "junos-evo-install-ptx-fixed-x86-64-23.4R2"}],
                            "comment": [],
                        },
                    ],
                }
            ]
        }
    )
    assert extract_switch_arch(name_only_evo_json) == "junos-evo"

    name_only_arm32_json = json.dumps(
        {
            "software-information": [
                {
                    "product-model": [{"data": "unknown-model"}],
                    "package-information": [
                        {
                            "name": [{"data": "os-runtime-arm-32"}],
                            "comment": [{"data": ""}],
                        }
                    ],
                }
            ]
        }
    )
    assert extract_switch_arch(name_only_arm32_json) == "arm-32"

    # Also verify multi-routing-engine-results formatted as a dict + "name"-keyed arch extraction
    multi_re_dict_json = json.dumps(
        {
            "multi-routing-engine-results": {
                "multi-routing-engine-item": {
                    "re-name": {"data": "fpc0"},
                    "software-information": {
                        "product-model": {"data": "unknown-model"},
                        "package-information": {
                            "name": {"data": "os-runtime-arm-32"},
                            "comment": {"data": ""},
                        },
                    },
                }
            }
        }
    )
    assert extract_switch_arch(multi_re_dict_json) == "arm-32"

    storage_with_tmpfs = json.dumps(
        {
            "multi-routing-engine-results": [
                {
                    "multi-routing-engine-item": [
                        {
                            "re-name": [{"data": "fpc0"}],
                            "system-storage-information": [
                                {
                                    "filesystem": [
                                        {
                                            "filesystem-name": [{"data": "/dev/gpt/junos"}],
                                            "available-blocks": [
                                                {
                                                    "data": "894976",
                                                    "attributes": {"junos:format": "437M"},
                                                }
                                            ],
                                            "mounted-on": [{"data": "/.mount"}],
                                        },
                                        {
                                            "filesystem-name": [{"data": "tmpfs"}],
                                            "available-blocks": [
                                                {
                                                    "data": "1859584",
                                                    "attributes": {"junos:format": "908M"},
                                                }
                                            ],
                                            "mounted-on": [{"data": "/.mount/tmp"}],
                                        },
                                        {
                                            "filesystem-name": [{"data": "tmpfs"}],
                                            "available-blocks": [
                                                {
                                                    "data": "663552",
                                                    "attributes": {"junos:format": "324M"},
                                                }
                                            ],
                                            "mounted-on": [{"data": "/.mount/mfs"}],
                                        },
                                    ]
                                }
                            ],
                        }
                    ]
                }
            ]
        }
    )
    parsed_free, parsed_mounts = parse_junos_storage(storage_with_tmpfs)
    assert parsed_free == 437
    assert parsed_mounts["/.mount"] == 437
    assert parsed_mounts["/.mount/tmp"] == 908
    assert parsed_mounts["/.mount/mfs"] == 324

    mounts_txt = (
        "/dev/md0.uzip on / (cd9660, local, read-only)\n"
        "/dev/gpt/junos on /.mount (ufs, local, noatime, soft-updates)\n"
        "tmpfs on /.mount/tmp (tmpfs, local)\n"
        "devfs on /dev (devfs, local)\n"
        "/var/jail on /.mount/var/jail (nullfs, local)\n"
        "procfs on /proc (procfs, local)\n"
    )
    snapshot_txt = (
        "fpc0:\n"
        "--------------------------------------------------------------------------\n"
        "Recovery Snapshots:\n"
        "Snapshots available on the OAM volume:\n"
        "recovery.ufs\n"
        "Junos version: 15.1X53-D58.3\n"
    )
    optics_txt = (
        "Physical interface: xe-0/2/0\n"
        "    Laser bias current                        :  6.420 mA\n"
        "    Laser output power                        :  0.5800 mW / -2.37 dBm\n"
        "    Laser receiver power                      :  0.5100 mW / -2.92 dBm\n"
        "    Laser bias current high alarm             :  Off\n"
        "    Laser bias current high alarm threshold   :  70.000 mA\n"
        "    Laser rx power low alarm                  :  Off\n"
        "    Laser rx power low alarm threshold        :  0.0316 mW / -15.00 dBm\n"
    )
    sys_alarms_txt = (
        "1 alarms currently active\n"
        "Alarm time               Class  Description\n"
        "2026-11-20 08:15:00 UTC  Minor  Rescue configuration is not set\n"
    )
    chas_alarms_txt = "No alarms currently active\n"
    chas_env_txt = (
        "Item                           Status     Measurement\n"
        "Power FPC 0 Power Supply 0     OK\n"
        "Power FPC 0 Power Supply 1     Absent\n"
        "Temp  FPC 0 CPU Sensor         OK         42 degrees C\n"
    )
    poe_txt = (
        "Controller  Maximum   Power         Guard    Management   Status        Lldp\n"
        "   0**      740W      36.60W          0W     Class        AT_MODE       Disabled\n"
        "\n"
        "** Firmware upgrade available for PoE controller.\n"
        "Use 'request system firmware upgrade poe fpc-slot 0'\n"
        "to upgrade PoE controller firmware.\n"
    )

    class _ReplayEx3400Transport(FakeJunosTransport):
        storage_payload: str = storage_with_tmpfs

        def run_command(self, command: str, read_timeout: int = 60) -> str:
            cmd = command.strip()
            if cmd == "show version | display json":
                return show_version_json
            if cmd == "show system storage | display json":
                return self.storage_payload
            if cmd == 'start shell command "mount"':
                return mounts_txt
            if cmd == "show system snapshot media internal":
                return snapshot_txt
            if cmd == "show interfaces diagnostics optics":
                return optics_txt
            if cmd == "show system alarms":
                return sys_alarms_txt
            if cmd == "show chassis alarms":
                return chas_alarms_txt
            if cmd == "show chassis environment":
                return chas_env_txt
            if cmd == "show poe controller":
                return poe_txt
            return super().run_command(command, read_timeout=read_timeout)

    sw = SwitchRecord(
        site="LAB",
        hostname="LAB-EX3400-01",
        management_ip="192.0.2.10",
        model="ex3400-48p",
        serial_number="SN_EX3400_01",
        current_version="18.1R3-S12.2",
        role="Access",
        management_method="SSH",
        mac_address="00:00:5e:00:53:01",
        state=SwitchState.READY,
    )
    tr = _ReplayEx3400Transport(
        hostname="LAB-EX3400-01",
        model="ex3400-48p",
        serial_number="SN_EX3400_01",
        running_version="18.1R3-S12.2",
    )
    verdict, checks = evaluate_hardware_and_fs_triage(
        tr, sw, pol, tmp_path / "ev", tmp_path / "cfg", execute_cleanup=False
    )
    checks_by_name = {c.name: c for c in checks}
    assert verdict == TriageVerdict.NEEDS_REMEDIATION
    assert sw.state == SwitchState.READY
    assert sw.free_storage_mb == 437
    assert sw.tmpfs_free_mb == 908
    assert sw.recovery_snapshot == "15.1X53-D58.3"
    assert checks_by_name["fs_read_write"].passed is True
    assert checks_by_name["uplink_optics_health"].passed is True
    assert checks_by_name["chassis_health"].passed is True
    assert checks_by_name["chassis_health"].severity == "warn"

    # Follow-up triage without /.mount/tmp or /tmp must clear stale tmpfs_free_mb to None
    tr.storage_payload = json.dumps(
        {
            "multi-routing-engine-results": [
                {
                    "multi-routing-engine-item": [
                        {
                            "system-storage-information": [
                                {
                                    "filesystem": [
                                        {
                                            "filesystem-name": [{"data": "/dev/gpt/junos"}],
                                            "available-blocks": [
                                                {
                                                    "data": "894976",
                                                    "attributes": {"junos:format": "437M"},
                                                }
                                            ],
                                            "mounted-on": [{"data": "/.mount"}],
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    )
    evaluate_hardware_and_fs_triage(
        tr, sw, pol, tmp_path / "ev2", tmp_path / "cfg2", execute_cleanup=False
    )
    assert sw.free_storage_mb == 437
    assert sw.tmpfs_free_mb is None

    # PoE 0** parsing and postcheck replay
    assert _extract_poe_watts(poe_txt) == pytest.approx(36.60)
    post_ver_json = json.dumps(
        {
            "multi-routing-engine-results": [
                {
                    "multi-routing-engine-item": [
                        {
                            "re-name": [{"data": "fpc0"}],
                            "software-information": [
                                {
                                    "host-name": [{"data": "LAB-EX3400-01"}],
                                    "product-model": [{"data": "ex3400-48p"}],
                                    "junos-version": [{"data": "23.4R2-S8"}],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
    )
    pre_baseline = {
        "show interfaces terse": "ge-0/0/0 up up\nxe-0/2/0 up up\n",
        "show lldp neighbors": "xe-0/2/0 - 00:00:5e:00:53:02 xe-0/0/1 CORE-SW\n",
        "show spanning-tree bridge": "  Root ID                           : 32768.00:00:5e:00:53:02\n",
        "show poe controller": poe_txt,
        "show ethernet-switching table": (
            "Ethernet switching table : 2 entries, 2 learned\n"
            "    default             00:00:5e:00:53:10   D             -           ge-0/0/0.0\n"
            "    default             00:00:5e:00:53:11   D             -           ge-0/0/1.0\n"
        ),
        "show lacp interfaces": "  xe-0/2/0                  Current   Fast periodic Collecting distributing\n",
        "show configuration | display set | no-more": "set system host-name LAB-EX3400-01\n",
    }
    post_baseline = {
        "show version | display json": post_ver_json,
        "show version": "Hostname: LAB-EX3400-01\nModel: ex3400-48p\nJunos: 23.4R2-S8\n",
        "show system alarms": "No alarms currently active\n",
        "show chassis alarms": "No alarms currently active\n",
        "show interfaces terse": pre_baseline["show interfaces terse"],
        "show lldp neighbors": pre_baseline["show lldp neighbors"],
        "show spanning-tree bridge": pre_baseline["show spanning-tree bridge"],
        "show poe controller": poe_txt,
        "show ethernet-switching table": pre_baseline["show ethernet-switching table"],
        "show lacp interfaces": pre_baseline["show lacp interfaces"],
        "show configuration | display set | no-more": pre_baseline[
            "show configuration | display set | no-more"
        ],
    }
    post_checks = run_postchecks(
        pre_baseline,
        post_baseline,
        expected_version="23.4R2-S8",
        diff_output_path=tmp_path / "config_diff.txt",
    )
    post_by_name = {c.name: c for c in post_checks}
    assert all(c.passed for c in post_checks)
    assert post_by_name["target_version_active"].passed is True
    assert post_by_name["poe_delivery_preserved"].passed is True
    assert "36.6W" in post_by_name["poe_delivery_preserved"].message


def test_reset_state_filters_and_preserves_excluded(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    runner = CliRunner()

    def _seed_switches() -> list[SwitchRecord]:
        return [
            SwitchRecord(
                site="SITE_A",
                hostname="EXCLUDED_EOL",
                management_ip="192.0.2.10",
                model="ex4200-48p",
                serial_number="SN_EOL",
                current_version="15.1R7",
                role="Access",
                management_method="SSH",
                state=SwitchState.EXCLUDED,
                last_error="EOL family excluded",
            ),
            SwitchRecord(
                site="SITE_A",
                hostname="EXCLUDED_MANUAL",
                management_ip="192.0.2.11",
                model="ex3400-48p",
                serial_number="SN_MAN",
                current_version="23.2R2-S3",
                role="Access",
                management_method="SSH",
                state=SwitchState.EXCLUDED,
                last_error="Manual hardware hold",
            ),
            SwitchRecord(
                site="SITE_A",
                hostname="A_FAIL",
                management_ip="192.0.2.12",
                model="ex3400-48p",
                serial_number="SN_AF",
                current_version="23.2R2-S3",
                role="Access",
                management_method="SSH",
                state=SwitchState.FAILED,
                last_error="SSH timeout",
                triage_verdict=TriageVerdict.NEEDS_REMEDIATION.value,
                triage_reasons=["Minor alarm"],
            ),
            SwitchRecord(
                site="SITE_A",
                hostname="A_REPL",
                management_ip="192.0.2.13",
                model="ex2300-24p",
                serial_number="SN_AR",
                current_version="23.4R2.13",
                role="Access",
                management_method="SSH",
                state=SwitchState.REPLACE_RECOMMENDED,
                last_error="Flash error",
                triage_verdict=TriageVerdict.REPLACE_RECOMMENDED.value,
                triage_reasons=["Flash I/O"],
            ),
            SwitchRecord(
                site="SITE_A",
                hostname="A_DONE",
                management_ip="192.0.2.14",
                model="ex3400-48p",
                serial_number="SN_AD",
                current_version="23.4R2-S8",
                role="Access",
                management_method="SSH",
                state=SwitchState.COMPLETED,
                last_error="",
            ),
            SwitchRecord(
                site="SITE_B",
                hostname="B_HOLD",
                management_ip="198.51.100.21",
                model="ex3400-48p",
                serial_number="SN_BH",
                current_version="23.2R2-S3",
                role="Access",
                management_method="SSH",
                state=SwitchState.ANCESTOR_HOLD,
                last_error="Held due to leaf",
            ),
            SwitchRecord(
                site="SITE_B",
                hostname="B_STAGED",
                management_ip="198.51.100.22",
                model="ex3400-48p",
                serial_number="SN_BS",
                current_version="23.2R2-S3",
                role="Access",
                management_method="SSH",
                state=SwitchState.STAGED,
                staged_package="/tmp/junos-arm-32-23.4R2-S8.tgz",  # nosec B108
                staged_checksum="a" * 32,
                triage_verdict="eligible",
                last_error="previous warning",
            ),
        ]

    save_inventory(_seed_switches(), manifest_path)

    # 1. --host targeting EXCLUDED switches must NOT reset them
    for excl_host in ("EXCLUDED_EOL", "EXCLUDED_MANUAL"):
        res = runner.invoke(
            main,
            [
                "reset-state",
                "--manifest",
                str(manifest_path),
                "--releases",
                str(RELEASES_YML),
                "--host",
                excl_host,
            ],
        )
        assert res.exit_code == 0, res.output
        assert "No failed, quarantined, or held switches matched your filters." in res.output
    by_host = {s.hostname: s for s in load_inventory(manifest_path)}
    assert by_host["EXCLUDED_EOL"].state == SwitchState.EXCLUDED
    assert by_host["EXCLUDED_EOL"].last_error == "EOL family excluded"
    assert by_host["EXCLUDED_MANUAL"].state == SwitchState.EXCLUDED
    assert by_host["EXCLUDED_MANUAL"].last_error == "Manual hardware hold"

    # 2. --site SITE_A resets only A_FAIL and A_REPL; leaves EXCLUDED_*, A_DONE, and SITE_B intact
    res_site = runner.invoke(
        main,
        [
            "reset-state",
            "--manifest",
            str(manifest_path),
            "--releases",
            str(RELEASES_YML),
            "--site",
            "SITE_A",
        ],
    )
    assert res_site.exit_code == 0, res_site.output
    by_host = {s.hostname: s for s in load_inventory(manifest_path)}
    assert by_host["A_FAIL"].state == SwitchState.READY
    assert by_host["A_FAIL"].last_error == ""
    assert by_host["A_FAIL"].triage_verdict == ""
    assert by_host["A_FAIL"].triage_reasons == []
    assert by_host["A_REPL"].state == SwitchState.READY
    assert by_host["A_REPL"].triage_verdict == ""
    assert by_host["A_REPL"].triage_reasons == []
    assert by_host["EXCLUDED_EOL"].state == SwitchState.EXCLUDED
    assert by_host["EXCLUDED_MANUAL"].state == SwitchState.EXCLUDED
    assert by_host["A_DONE"].state == SwitchState.COMPLETED
    assert by_host["B_HOLD"].state == SwitchState.ANCESTOR_HOLD
    assert by_host["B_STAGED"].state == SwitchState.STAGED

    # 3. Re-seed and filter by --model ex3400: resets A_FAIL, B_HOLD, B_STAGED (clears staged_*)
    save_inventory(_seed_switches(), manifest_path)
    res_model = runner.invoke(
        main,
        [
            "reset-state",
            "--manifest",
            str(manifest_path),
            "--releases",
            str(RELEASES_YML),
            "--model",
            "ex3400",
        ],
    )
    assert res_model.exit_code == 0, res_model.output
    by_host = {s.hostname: s for s in load_inventory(manifest_path)}
    assert by_host["A_FAIL"].state == SwitchState.READY
    assert by_host["B_HOLD"].state == SwitchState.READY
    assert by_host["B_STAGED"].state == SwitchState.READY
    assert by_host["B_STAGED"].staged_package == ""
    assert by_host["B_STAGED"].staged_checksum == ""
    assert by_host["B_STAGED"].triage_verdict == ""
    assert by_host["B_STAGED"].triage_reasons == []
    assert by_host["B_STAGED"].last_error == ""
    assert by_host["A_REPL"].state == SwitchState.REPLACE_RECOMMENDED
    assert by_host["EXCLUDED_EOL"].state == SwitchState.EXCLUDED
    assert by_host["EXCLUDED_MANUAL"].state == SwitchState.EXCLUDED
    assert by_host["A_DONE"].state == SwitchState.COMPLETED

    # 4. Re-seed and filter by comma-separated hostname + IP (--host A_FAIL,198.51.100.22)
    save_inventory(_seed_switches(), manifest_path)
    res_hosts = runner.invoke(
        main,
        [
            "reset-state",
            "--manifest",
            str(manifest_path),
            "--releases",
            str(RELEASES_YML),
            "--host",
            "A_FAIL,198.51.100.22",
        ],
    )
    assert res_hosts.exit_code == 0, res_hosts.output
    by_host = {s.hostname: s for s in load_inventory(manifest_path)}
    assert by_host["A_FAIL"].state == SwitchState.READY
    assert by_host["B_STAGED"].state == SwitchState.READY
    assert by_host["B_STAGED"].staged_package == ""
    assert by_host["B_STAGED"].staged_checksum == ""
    assert by_host["A_REPL"].state == SwitchState.REPLACE_RECOMMENDED
    assert by_host["B_HOLD"].state == SwitchState.ANCESTOR_HOLD
    assert by_host["EXCLUDED_EOL"].state == SwitchState.EXCLUDED
    assert by_host["EXCLUDED_MANUAL"].state == SwitchState.EXCLUDED
    assert by_host["A_DONE"].state == SwitchState.COMPLETED
