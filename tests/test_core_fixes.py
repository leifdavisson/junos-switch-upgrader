# SPDX-License-Identifier: AGPL-3.0-or-later
"""Comprehensive unit tests for Phase 2 core/CLI/models/inventory/web_ui/packaging/PS1 fixes."""

from __future__ import annotations

import io
import json
import threading
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from rich.console import Console

import junos_upgrader.cli as cli_mod
import junos_upgrader.inventory as inv_mod
from junos_upgrader.models import (
    CheckResult,
    CheckSeverity,
    HopSpec,
    NeighborExpectation,
    PlatformPolicy,
    SwitchRecord,
    SwitchState,
    TriageVerdict,
    ensure_within_directory,
    sanitize_path_segment,
    validate_safe_path_segment,
)
from junos_upgrader.topology import RunnerOrigin, TopologyEdge, TopologyGraph, build_topology_graph
from junos_upgrader.web_ui import (
    _safe_id,
    export_topology_markdown,
    render_rich_topology_tree,
    render_topology_html,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASES_YML = REPO_ROOT / "manifests" / "approved-releases.yml"
FIXED_ORIGIN = RunnerOrigin("test-runner", "192.0.2.5", "eth0", "192.0.2.1")


def _make_switch(
    hostname: str = "SW_ACCESS_01",
    ip: str = "192.0.2.10",
    model: str = "ex3400-48p",
    version: str = "23.2R2-S3",
    site: str = "SITE",
    role: str = "Access",
    state: SwitchState = SwitchState.READY,
    neighbors: list[NeighborExpectation] | None = None,
) -> SwitchRecord:
    return SwitchRecord(
        site=site,
        hostname=hostname,
        management_ip=ip,
        model=model,
        serial_number=f"SN_{hostname}",
        current_version=version,
        role=role,
        management_method="SSH",
        state=state,
        expected_neighbors=neighbors or [],
    )


# ---------------------------------------------------------------------------
# models.py tests
# ---------------------------------------------------------------------------


def test_switch_record_deep_copy_and_null_deserialization() -> None:
    sw = _make_switch()
    sw.triage_reasons = ["reason1"]
    sw.downstream_switches = ["LEAF_01"]
    sw.hop_history = [{"hop": "23.2R2-S3", "meta": {"ok": True}}]

    d = sw.to_dict()
    d["triage_reasons"].append("mutated")
    d["downstream_switches"].append("mutated")
    d["hop_history"].append({"hop": "evil"})
    d["hop_history"][0]["meta"]["ok"] = False

    assert sw.triage_reasons == ["reason1"]
    assert sw.downstream_switches == ["LEAF_01"]
    assert len(sw.hop_history) == 1
    assert sw.hop_history[0]["meta"]["ok"] is True

    clone = SwitchRecord.from_dict(sw.to_dict())
    clone.hop_history.append({"hop": "23.4R2-S8"})
    clone.hop_history[0]["meta"]["ok"] = False
    assert len(sw.hop_history) == 1
    assert sw.hop_history[0]["meta"]["ok"] is True

    # Explicit JSON nulls and string int coercion deserialize safely
    raw_with_nulls = {
        "site": "SITE",
        "hostname": "SW_NULLS",
        "management_ip": "192.0.2.20",
        "model": "ex3400-48p",
        "serial_number": "SN001",
        "current_version": "23.2R2-S3",
        "role": None,
        "management_method": None,
        "state": None,
        "triage_reasons": None,
        "downstream_switches": None,
        "expected_neighbors": None,
        "hop_history": None,
        "topology_depth": None,
        "free_storage_mb": "512",
    }
    parsed = SwitchRecord.from_dict(raw_with_nulls)
    assert parsed.role == "Access"
    assert parsed.management_method == "SSH"
    assert parsed.state == SwitchState.NOT_READY
    assert parsed.triage_reasons == []
    assert parsed.downstream_switches == []
    assert parsed.expected_neighbors == []
    assert parsed.hop_history == []
    assert parsed.topology_depth == 0
    assert parsed.free_storage_mb == 512

    with pytest.raises(ValueError, match="free_storage_mb"):
        SwitchRecord.from_dict({**raw_with_nulls, "free_storage_mb": True})
    with pytest.raises(ValueError, match="free_storage_mb"):
        SwitchRecord.from_dict({**raw_with_nulls, "free_storage_mb": "not-an-int"})
    with pytest.raises(ValueError, match="Missing required switch field"):
        SwitchRecord.from_dict({"site": "SITE"})


def test_models_path_traversal_and_policy_invariants(tmp_path: Path) -> None:
    for bad in ("../evil", "a/b", "a\\b", "..", ".", "", "host\x00name"):
        with pytest.raises(ValueError):
            validate_safe_path_segment(bad, "hostname")
        with pytest.raises(ValueError):
            _make_switch(hostname=bad)

    assert sanitize_path_segment("../../.ssh") == "ssh"
    assert sanitize_path_segment("a..b") == "a_b"
    assert sanitize_path_segment("...", fallback="sw") == "sw"

    base = tmp_path / "root"
    base.mkdir()
    assert ensure_within_directory(base, base / "SITE" / "SW_01") == base / "SITE" / "SW_01"
    with pytest.raises(ValueError, match="escapes base directory"):
        ensure_within_directory(base, base / ".." / "outside")

    # PlatformPolicy.family_dir preserves valid patterns & rejects unsafe glob/path chars
    for pat, expected in (
        ("ex2300-*mp*", "ex2300-mp"),
        ("ex4300-48mp*", "ex4300-48mp"),
        ("ex3400*", "ex3400"),
    ):
        pol = PlatformPolicy(
            model_pattern=pat,
            vendor="juniper",
            role_scope="access",
            final_target="23.4R2-S8",
            package_family="junos-arm-32",
            expected_arch="arm-32",
            min_free_storage_mb=250,
            boot_timeout_seconds=600,
        )
        assert pol.family_dir == expected

    for bad_pat in ("../../etc*", "ex4300-??p", "ex[34]*", "a/b*", "a\\b*", "***"):
        pol = PlatformPolicy(
            model_pattern=bad_pat,
            vendor="juniper",
            role_scope="access",
            final_target="23.4R2-S8",
            package_family="junos-arm-32",
            expected_arch="arm-32",
            min_free_storage_mb=250,
            boot_timeout_seconds=600,
        )
        with pytest.raises(ValueError):
            _ = pol.family_dir

    with pytest.raises(ValueError, match="min_free_storage_mb"):
        PlatformPolicy("ex3400*", "juniper", "access", "23.4R2-S8", "f", "arm-32", -1, 600)
    with pytest.raises(ValueError, match="boot_timeout_seconds"):
        PlatformPolicy("ex3400*", "juniper", "access", "23.4R2-S8", "f", "arm-32", 100, 0)

    chk = CheckResult(name="t", passed=True, message="ok", severity=CheckSeverity.WARN)
    assert chk.severity == "warn"
    with pytest.raises(ValueError, match="severity"):
        CheckResult(name="t", passed=True, message="ok", severity="bogus")


# ---------------------------------------------------------------------------
# inventory.py tests
# ---------------------------------------------------------------------------


def test_expand_targets_validation_commas_comments_and_cap(tmp_path: Path) -> None:
    tfile = tmp_path / "targets.csv"
    tfile.write_bytes(
        b"\xef\xbb\xbf"
        b"IP Address,Model,Role\n"
        b"192.0.2.10,ex3400-48p,Access  # inline comment\n"
        b"192.0.2.11,192.0.2.12\n"
        b"# full comment\n"
        b"198.51.100.4/32\n"
    )
    hosts = inv_mod.expand_targets(("192.0.2.1,192.0.2.2", "203.0.113.0/30"), tfile)
    assert hosts == [
        "192.0.2.1",
        "192.0.2.2",
        "203.0.113.1",
        "203.0.113.2",
        "192.0.2.10",
        "192.0.2.11",
        "192.0.2.12",
        "198.51.100.4",
    ]

    with pytest.raises(ValueError, match="Invalid CIDR"):
        inv_mod.expand_targets(("192.0.2.1/99",))

    with pytest.raises(ValueError, match="exceeds max_hosts"):
        inv_mod.expand_targets(("198.51.100.0/24",), max_hosts=16)

    with pytest.raises(ValueError, match="exceeds max_hosts"):
        inv_mod.expand_targets(("2001:db8::/64",))


def test_inventory_atomic_save_and_schema_validation(tmp_path: Path) -> None:
    manifest = tmp_path / "site-inventory.json"
    sw = _make_switch("SW_ROUNDTRIP", "192.0.2.42")
    sw.triage_verdict = TriageVerdict.ELIGIBLE.value
    inv_mod.save_inventory([sw], manifest)

    # No stray temp files remain
    assert list(tmp_path.glob("*.tmp")) == []
    loaded = inv_mod.load_inventory(manifest)
    assert len(loaded) == 1
    assert loaded[0].hostname == "SW_ROUNDTRIP"
    assert loaded[0].management_ip == "192.0.2.42"

    # Malformed manifest schemas rejected cleanly
    bad_root = tmp_path / "bad_root.json"
    bad_root.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        inv_mod.load_inventory(bad_root)

    bad_schema = tmp_path / "bad_schema.json"
    bad_schema.write_text(json.dumps({"schema_version": 99, "switches": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version"):
        inv_mod.load_inventory(bad_schema)

    bad_switches = tmp_path / "bad_switches.json"
    bad_switches.write_text(json.dumps({"schema_version": 2, "switches": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON list"):
        inv_mod.load_inventory(bad_switches)


def test_inventory_json_unwrapping_and_lldp_edge_cases() -> None:
    # Empty multi-RE list and non-dict structures must not crash
    assert (
        inv_mod._unwrap_multi_re({"multi-routing-engine-results": []}, "software-information") == {}
    )
    assert inv_mod._unwrap_multi_re({"software-information": None}, "software-information") == {}
    assert inv_mod._unwrap_multi_re("not-a-dict", "software-information") == {}

    # Multiple stp-interfaces blocks parsed completely
    stp = json.dumps(
        {
            "stp-interface-information": [
                {
                    "stp-instance": [
                        {
                            "stp-interfaces": [
                                {
                                    "stp-interface-entry": [
                                        {
                                            "interface-name": [{"data": "ge-0/0/1.0"}],
                                            "port-role": [{"data": "DESG"}],
                                        }
                                    ]
                                },
                                {
                                    "stp-interface-entry": [
                                        {
                                            "interface-name": [{"data": "xe-0/2/0.0"}],
                                            "port-role": [{"data": "ROOT"}],
                                        }
                                    ]
                                },
                            ]
                        }
                    ]
                }
            ]
        }
    )
    lldp = json.dumps(
        {
            "lldp-neighbors-information": [
                {
                    "lldp-neighbor-information": [
                        {
                            "lldp-local-port-id": [{"data": "xe-0/2/0.0"}],
                            "lldp-remote-system-name": [{"data": "CORE_SW"}],
                            "lldp-remote-port-id": [{"data": "xe-0/0/1"}],
                            "lldp-remote-chassis-id": [{"data": "00:00:5e:00:53:01"}],
                        }
                    ]
                }
            ]
        }
    )
    nbrs = inv_mod._parse_lldp_json(lldp, stp)
    assert len(nbrs) == 1
    assert nbrs[0].is_upstream is True


def test_discover_live_targets_resilience_text_fallback_and_preserve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeProbeTransport:
        def __init__(self, host: str, credentials: list[Any], port: int = 22) -> None:
            self.host = host
            self.port = port
            self.disconnected = False

        def connect(self) -> None:
            return None

        def disconnect(self) -> None:
            self.disconnected = True

        def run_command(self, cmd: str, read_timeout: int = 60) -> str:
            if self.host == "192.0.2.10":
                raise RuntimeError("mid-command disconnect")
            if self.host == "192.0.2.11":
                if cmd == "show version | display json":
                    return "error: syntax error expecting <command>"
                if cmd == "show version":
                    return "Hostname: LAB_SW_TEXT\nModel: ex3400-48p\nJunos: 23.2R2-S3\n"
                return ""
            if self.host == "192.0.2.12":
                if cmd == "show version | display json":
                    return json.dumps(
                        {
                            "software-information": [
                                {
                                    "host-name": [{"data": "../../evil"}],
                                    "product-model": [{"data": "ex3400-48p"}],
                                    "junos-version": [{"data": "unknown-ver"}],
                                }
                            ]
                        }
                    )
                return ""
            return ""

    monkeypatch.setattr(inv_mod, "_tcp_ssh_open", lambda h, p=22, t=3.0: True)
    monkeypatch.setattr(inv_mod, "NetmikoJunosTransport", FakeProbeTransport)
    monkeypatch.setattr(
        inv_mod,
        "build_topology_graph",
        lambda recs, **kw: build_topology_graph(recs, origin=FIXED_ORIGIN),
    )

    out_manifest = tmp_path / "site-inventory.json"
    recs = inv_mod.discover_live_targets(
        ["192.0.2.10", "192.0.2.11", "192.0.2.12"],
        [],
        RELEASES_YML,
        out_manifest,
    )
    assert len(recs) == 2
    by_ip = {r.management_ip: r for r in recs}
    # Plain-text fallback parsed correctly and site inferred from hostname prefix (default site_name="")
    assert by_ip["192.0.2.11"].hostname == "LAB_SW_TEXT"
    assert by_ip["192.0.2.11"].site == "LAB"
    assert by_ip["192.0.2.11"].current_version == "23.2R2-S3"
    # Malicious hostname sanitized and unparseable version set NOT_READY instead of crashing
    assert ".." not in by_ip["192.0.2.12"].hostname
    assert "/" not in by_ip["192.0.2.12"].hostname
    assert by_ip["192.0.2.12"].state == SwitchState.NOT_READY

    # Re-running discovery with 0 reachable hosts must NOT wipe existing non-empty manifest
    monkeypatch.setattr(inv_mod, "_tcp_ssh_open", lambda h, p=22, t=3.0: False)
    empty_recs = inv_mod.discover_live_targets(["192.0.2.99"], [], RELEASES_YML, out_manifest)
    assert empty_recs == []
    assert len(inv_mod.load_inventory(out_manifest)) == 2


def test_import_from_crawler_bom_short_rows_filters_and_duplicates(tmp_path: Path) -> None:
    crawler_dir = tmp_path / "crawler"
    crawler_dir.mkdir()
    # UTF-8 BOM, blank Role, truncated row (None trailing cols), non-Switch row, unparseable FW
    (crawler_dir / "asset_inventory.csv").write_bytes(
        b"\xef\xbb\xbf"
        b"Hostname,IP Address,MAC Address,Device Type,Model,Firmware,Serial Number,Role,Management Method\n"
        b"LAB_SW_01,192.0.2.10,00:00:5e:00:53:10,Switch,ex3400-48p,23.2R2-S3,SN01,,\n"
        b"LAB_AP_01,192.0.2.11,00:00:5e:00:53:11,Access Point,AP-505,8.10,SN02,Access,SSH\n"
        b"LAB_SW_SHORT,192.0.2.12,00:00:5e:00:53:12,Switch,ex3400-48p,badver,SN03\n"
    )
    out = tmp_path / "manifest.json"
    recs = inv_mod.import_from_crawler(crawler_dir, RELEASES_YML, out, origin=FIXED_ORIGIN)
    assert [r.hostname for r in recs] == ["LAB_SW_01", "LAB_SW_SHORT"]
    assert recs[0].role == "Access"
    assert recs[0].management_method == "SSH"
    assert recs[1].state == SwitchState.NOT_READY

    # Duplicate hostname rejected
    (crawler_dir / "asset_inventory.csv").write_text(
        "Hostname,IP Address,Model,Serial Number,Firmware\n"
        "DUP_SW,192.0.2.10,ex3400-48p,SN1,23.2R2-S3\n"
        "DUP_SW,192.0.2.11,ex3400-48p,SN2,23.2R2-S3\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate hostname"):
        inv_mod.import_from_crawler(crawler_dir, RELEASES_YML, out, origin=FIXED_ORIGIN)

    # Missing required columns rejected
    (crawler_dir / "asset_inventory.csv").write_text(
        "Hostname,IP Address\nSW1,192.0.2.10\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="missing required column"):
        inv_mod.import_from_crawler(crawler_dir, RELEASES_YML, out, origin=FIXED_ORIGIN)


def test_scaffold_firmware_repo_includes_mp_and_intermediate_dirs(tmp_path: Path) -> None:
    inv_mod.scaffold_firmware_repo(tmp_path, releases_path=RELEASES_YML)
    for expected in (
        "firmware/juniper/ex2300-mp/23.4R2-S8",
        "firmware/juniper/ex4100-mp/23.4R2-S8",
        "firmware/juniper/ex4400-mp/23.4R2-S8",
        "firmware/juniper/ex4650/21.4",
        "firmware/juniper/qfx5120/22.4",
        "firmware/juniper/qfx5200/21.4",
    ):
        assert (tmp_path / expected).is_dir()


# ---------------------------------------------------------------------------
# web_ui.py tests
# ---------------------------------------------------------------------------


def test_web_ui_escaping_rich_mermaid_and_html(tmp_path: Path) -> None:
    graph = TopologyGraph(
        origin=RunnerOrigin("runner[/bold]", "192.0.2.5", "eth0", "192.0.2.1"),
        nodes={
            "__runner__": {
                "id": "__runner__",
                "label": 'runner[/bold]"<script>alert(1)</script>',
                "kind": "runner",
                "ip": "192.0.2.5",
                "model": "NIC eth0",
                "version": "GW 192.0.2.1",
                "state": "runner",
                "depth": 0,
            },
            "SITE-SW-01": {
                "id": "SITE-SW-01",
                "label": 'SITE-SW-01"\nclick n_1 "javascript:alert(1)"```',
                "kind": "switch",
                "ip": "192.0.2.10",
                "model": "ex3400-48p",
                "version": "23.2R2-S3",
                "next_hop": "23.4R2-S8",
                "final_target": "23.4R2-S8",
                "state": "not-ready",
                "depth": 1,
            },
            "SITE_SW_01": {
                "id": "SITE_SW_01",
                "label": "SITE_SW_01[/var/tmp/pkg.tgz]",
                "kind": "switch",
                "ip": "192.0.2.11",
                "model": "ex3400-48p",
                "version": "23.2R2-S3",
                "next_hop": "",
                "final_target": "23.4R2-S8",
                "state": "rolled-back",
                "depth": 1,
            },
        },
        edges=[
            TopologyEdge("__runner__", "SITE-SW-01", 'eth0"[/dim]', "ge-0/0/1#;`<tag>"),
            TopologyEdge("__runner__", "SITE_SW_01", "eth0", "ge-0/0/2"),
            TopologyEdge("__runner__", "MISSING_NODE", "eth0", "ge-0/0/3"),
        ],
    )

    # Rich tree must NOT raise MarkupError or KeyError on missing node
    buf = io.StringIO()
    con = Console(file=buf, force_terminal=False)
    render_rich_topology_tree(graph, con)
    rendered = buf.getvalue()
    assert "SITE_SW_01[/var/tmp/pkg.tgz]" in rendered

    # Mermaid IDs for SITE-SW-01 vs SITE_SW_01 must not collide
    assert _safe_id("SITE-SW-01") != _safe_id("SITE_SW_01")

    # Markdown export escapes quotes, HTML, newlines, backticks, #, ;
    md_out = export_topology_markdown(graph, tmp_path / "topo.md")
    md_text = md_out.read_text(encoding="utf-8")
    assert "<script>" not in md_text
    assert '"\nclick' not in md_text
    assert md_text.count("```") == 2  # only opening and closing fence
    assert "&lt;script&gt;" in md_text
    assert "&#35;" in md_text and "&#59;" in md_text

    # HTML dashboard checks
    html = render_topology_html()
    assert "Content-Security-Policy" in html
    assert "Object.hasOwn(COLORS" in html
    assert "new Map()" in html
    assert "&#39;" in html
    assert "if (!res.ok)" in html
    assert "inFlight" in html
    assert '"not-ready"' in html and '"rolled-back"' in html
    assert 'id="node-clip"' in html


# ---------------------------------------------------------------------------
# cli.py tests
# ---------------------------------------------------------------------------


def test_resolve_default_releases_path_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    resolved = cli_mod.resolve_default_releases_path()
    assert resolved.is_file()
    assert resolved.name == "approved-releases.yml"


def test_cli_plan_and_status_edge_cases(tmp_path: Path) -> None:
    manifest = tmp_path / "inv.json"
    sw_ok = _make_switch("CAMPUS_SW_01", "192.0.2.10", model="ex3400-48p", version="23.2R2-S3")
    sw_nopol = _make_switch("CAMPUS_SW_02", "192.0.2.11", model="mystery-9999", version="1.0")
    sw_badver = _make_switch("CAMPUS_SW_03", "192.0.2.12", model="ex3400-48p", version="unknown")
    inv_mod.save_inventory([sw_ok, sw_nopol, sw_badver], manifest)

    runner = CliRunner()
    res = runner.invoke(
        cli_mod.main, ["plan", "--manifest", str(manifest), "--releases", str(RELEASES_YML)]
    )
    assert res.exit_code == 0, res.output
    assert "(no matching policy)" in res.output
    assert "unparseable version" in res.output

    # Case-insensitive --host filter
    res_host = runner.invoke(
        cli_mod.main,
        [
            "plan",
            "--manifest",
            str(manifest),
            "--releases",
            str(RELEASES_YML),
            "--host",
            "campus_sw_01",
        ],
    )
    assert res_host.exit_code == 0, res_host.output
    assert "CAMPUS_SW_01" in res_host.output

    # Non-matching explicit --host exits non-zero
    res_miss = runner.invoke(
        cli_mod.main,
        [
            "plan",
            "--manifest",
            str(manifest),
            "--releases",
            str(RELEASES_YML),
            "--host",
            "NO_SUCH_HOST",
        ],
    )
    assert res_miss.exit_code != 0


def test_cli_topology_readonly_redact_serve_and_error_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "inv.json"
    core = _make_switch("REAL_CORE_01", "192.0.2.10", role="Core")
    leaf = _make_switch(
        "REAL_LEAF_01",
        "192.0.2.11",
        neighbors=[NeighborExpectation("ge-0/2/0", "REAL_CORE_01", "xe-0/0/1", is_upstream=True)],
    )
    inv_mod.save_inventory([core, leaf], manifest)
    orig_bytes = manifest.read_bytes()

    captured: dict[str, Any] = {}

    class DummyServer:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)
            self.port = kwargs.get("port", 8080)

        def __enter__(self) -> DummyServer:  # noqa: PYI034
            return self

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr(cli_mod, "UnifiedFirmwareServer", DummyServer)
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or FIXED_ORIGIN),
    )
    monkeypatch.setattr(cli_mod.time, "sleep", lambda _: (_ for _ in ()).throw(KeyboardInterrupt()))

    runner = CliRunner()
    res = runner.invoke(
        cli_mod.main,
        ["topology", "--manifest", str(manifest), "--redact", "--serve", "--port", "9090"],
    )
    assert res.exit_code == 0, res.output
    # Read-only by default: manifest NOT mutated
    assert manifest.read_bytes() == orig_bytes
    # Default bind_host is loopback and printed accurately
    assert captured["bind_host"] == "127.0.0.1"
    assert "http://127.0.0.1:9090/" in res.output

    # Served /api/topology MUST be redacted!
    api_data = captured["topology_provider"]()
    serialized = json.dumps(api_data)
    assert "REAL_CORE_01" not in serialized
    assert "REAL_LEAF_01" not in serialized
    assert "192.0.2.11" not in serialized
    assert "SW-01" in serialized

    # Transient corrupted manifest JSON returns last good snapshot instead of crashing
    manifest.write_text("{corrupt", encoding="utf-8")
    fallback_data = captured["topology_provider"]()
    assert fallback_data == api_data


def test_cli_precheck_identity_mismatch_skips_backup_and_refreshes_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "inv.json"
    sw = _make_switch("SW_PRE_01", "192.0.2.10", version="22.2R3-S5", state=SwitchState.FAILED)
    inv_mod.save_inventory([sw], manifest)

    class DummyTransport:
        def connect(self) -> None:
            return None

        def disconnect(self) -> None:
            return None

    backup_called = {"count": 0}
    passed_kwargs: dict[str, Any] = {}

    def fake_prechecks_mismatch(*args: Any, **kwargs: Any) -> list[CheckResult]:
        passed_kwargs.update(kwargs)
        return [
            CheckResult(
                name="identity_and_version",
                passed=False,
                hard_stop=True,
                severity="fail",
                message="Mismatch on [/var/tmp/pkg.tgz]",
            )
        ]

    monkeypatch.setattr(
        cli_mod, "_make_transport_factory", lambda creds: lambda s: DummyTransport()
    )
    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or FIXED_ORIGIN),
    )
    monkeypatch.setattr(cli_mod, "run_prechecks", fake_prechecks_mismatch)
    monkeypatch.setattr(
        cli_mod,
        "collect_baseline",
        lambda *a, **k: backup_called.__setitem__("count", backup_called["count"] + 1) or {},
    )

    runner = CliRunner()
    res = runner.invoke(
        cli_mod.main,
        [
            "precheck",
            "--manifest",
            str(manifest),
            "--releases",
            str(RELEASES_YML),
            "--evidence-dir",
            str(tmp_path / "ev"),
            "--config-dir",
            str(tmp_path / "cfg"),
            "--allow-unverified-checksums",
        ],
    )
    assert res.exit_code != 0
    assert backup_called["count"] == 0  # Identity mismatch skipped baseline/backup!
    assert passed_kwargs["allow_unverified_checksums"] is True
    assert "[/var/tmp/pkg.tgz]" in res.output  # No Rich MarkupError!

    # Now test passing precheck refreshing stale version and clearing FAILED -> READY
    def fake_prechecks_pass(
        transport: Any, sw_obj: SwitchRecord, *args: Any, **kwargs: Any
    ) -> list[CheckResult]:
        sw_obj.current_version = "23.2R2-S3"
        sw_obj.triage_verdict = TriageVerdict.ELIGIBLE.value
        return [CheckResult(name="identity_and_version", passed=True, message="ok")]

    monkeypatch.setattr(cli_mod, "run_prechecks", fake_prechecks_pass)
    monkeypatch.setattr(cli_mod, "collect_baseline", lambda *a, **k: {})
    monkeypatch.setattr(cli_mod, "backup_configuration", lambda *a, **k: tmp_path / "cfg.txt")
    monkeypatch.setattr(
        cli_mod, "generate_recovery_sheet", lambda *a, **k: tmp_path / "recovery.txt"
    )

    res_ok = runner.invoke(
        cli_mod.main,
        [
            "precheck",
            "--manifest",
            str(manifest),
            "--releases",
            str(RELEASES_YML),
            "--evidence-dir",
            str(tmp_path / "ev"),
            "--config-dir",
            str(tmp_path / "cfg"),
        ],
    )
    assert res_ok.exit_code == 0, res_ok.output
    reloaded = inv_mod.load_inventory(manifest)[0]
    assert reloaded.current_version == "23.2R2-S3"
    assert reloaded.next_hop == "23.4R2-S8"
    assert reloaded.state == SwitchState.READY


def test_cli_upgrade_stage_options_bounds_server_skip_and_bleeding_edge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "inv.json"
    sw = _make_switch("SW_UP_01", "192.0.2.10", model="ex3400-48p", version="23.2R2-S3")
    inv_mod.save_inventory([sw], manifest)

    runner = CliRunner()
    # Invalid numeric bounds rejected by Click
    for bad_args in (
        [
            "upgrade",
            "--manifest",
            str(manifest),
            "--change-number",
            "CHG1",
            "--operator",
            "op",
            "--max-hops",
            "0",
        ],
        [
            "upgrade",
            "--manifest",
            str(manifest),
            "--change-number",
            "CHG1",
            "--operator",
            "op",
            "--max-hops",
            "-1",
        ],
        [
            "upgrade",
            "--manifest",
            str(manifest),
            "--change-number",
            "CHG1",
            "--operator",
            "op",
            "--batch-size",
            "0",
        ],
        [
            "upgrade",
            "--manifest",
            str(manifest),
            "--change-number",
            "CHG1",
            "--operator",
            "op",
            "--http-port",
            "70000",
        ],
        ["upgrade", "--manifest", str(manifest), "--change-number", "../evil", "--operator", "op"],
    ):
        r = runner.invoke(cli_mod.main, bad_args)
        assert r.exit_code != 0

    # Dry-run and SCP mode must NOT start UnifiedFirmwareServer
    server_started = {"count": 0}

    class FailIfStartedServer:
        def __init__(self, **kwargs: Any) -> None:
            server_started["count"] += 1

        def __enter__(self) -> FailIfStartedServer:  # noqa: PYI034
            return self

        def __exit__(self, *_: object) -> None:
            return None

    captured_opts: list[Any] = []

    def fake_run_batches(
        all_sw: Any, targets: Any, *args: Any, **kwargs: Any
    ) -> tuple[list[SwitchRecord], bool]:
        opts = args[3]
        captured_opts.append(opts)
        return list(targets), True

    monkeypatch.setattr(cli_mod, "UnifiedFirmwareServer", FailIfStartedServer)
    monkeypatch.setattr(cli_mod, "run_upgrade_batches", fake_run_batches)
    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or FIXED_ORIGIN),
    )

    for extra in (["--dry-run"], ["--transfer-mode", "scp"]):
        r = runner.invoke(
            cli_mod.main,
            [
                "upgrade",
                "--manifest",
                str(manifest),
                "--releases",
                str(RELEASES_YML),
                "--change-number",
                "CHG001",
                "--operator",
                "netops",
                "--allow-unverified-checksums",
                *extra,
            ],
        )
        assert r.exit_code == 0, r.output
    assert server_started["count"] == 0
    assert captured_opts[0].allow_unverified_checksums is True
    assert isinstance(captured_opts[0].state_lock, type(threading.Lock()))

    # _warn_if_bleeding_edge scoped to targeted switches only
    bleeding_pol = PlatformPolicy(
        model_pattern="ex4100*",
        vendor="juniper",
        role_scope="access",
        final_target="25.2R2.12",
        package_family="junos-install-ex-arm-64",
        expected_arch="arm-64",
        min_free_storage_mb=1000,
        boot_timeout_seconds=600,
        bleeding_edge=True,
        hops=[
            HopSpec(
                "25.2",
                "25.2R2.12",
                "junos-install-ex-arm-64-25.2R2.12.tgz",
                "md5",
                "abc",
                bleeding_edge=True,
            )
        ],
    )
    jtac_pol = PlatformPolicy(
        model_pattern="ex3400*",
        vendor="juniper",
        role_scope="access",
        final_target="23.4R2-S8",
        package_family="junos-arm-32",
        expected_arch="arm-32",
        min_free_storage_mb=600,
        boot_timeout_seconds=600,
        bleeding_edge=False,
        hops=[
            HopSpec(
                "23.4R2-S8",
                "23.4R2-S8",
                "junos-arm-32-23.4R2-S8.tgz",
                "md5",
                "abc",
                bleeding_edge=False,
            )
        ],
    )
    # Targeting ex3400 must NOT trip bleeding-edge bumper for unrelated ex4100!
    cli_mod._warn_if_bleeding_edge(
        [bleeding_pol, jtac_pol],
        accept_bleeding_edge=False,
        require_accept=True,
        targets=[sw],
    )
    # Targeting ex4100 MUST trip bumper!
    sw_4100 = _make_switch("SW_4100", "192.0.2.20", model="ex4100-48p", version="23.4R2-S8")
    with pytest.raises(cli_mod.click.ClickException, match="accept-bleeding-edge"):
        cli_mod._warn_if_bleeding_edge(
            [bleeding_pol, jtac_pol],
            accept_bleeding_edge=False,
            require_accept=True,
            targets=[sw_4100],
        )


def test_cli_password_stdin_and_credential_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured_creds_args: list[tuple[Any, ...]] = []

    def fake_load_creds(*args: Any) -> list[Any]:
        captured_creds_args.append(args)
        raise ValueError("No SSH credentials configured")

    monkeypatch.setattr(cli_mod, "load_credentials", fake_load_creds)
    runner = CliRunner()

    res = runner.invoke(
        cli_mod.main,
        ["discover", "--target", "192.0.2.10", "--username", "netops", "--password-stdin"],
        input="stdin-secret-value\n",
    )
    assert res.exit_code != 0
    assert "No SSH credentials configured" in res.output
    assert captured_creds_args[-1][2] == "stdin-secret-value"

    # Passing --password directly on CLI prints OPSEC warning
    res_warn = runner.invoke(
        cli_mod.main,
        ["discover", "--target", "192.0.2.10", "--username", "netops", "--password", "cli-val"],
    )
    assert res_warn.exit_code != 0
    assert "process lists/shell history" in " ".join(res_warn.output.split())


def test_cli_firmware_and_zero_processed_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()

    # firmware scan on empty dir exits non-zero
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    r_empty = runner.invoke(
        cli_mod.main,
        ["firmware", "scan", str(empty_dir), "--releases", str(RELEASES_YML)],
    )
    assert r_empty.exit_code != 0

    # firmware scan where all files are rejected exits non-zero
    bad_dir = tmp_path / "bad_fw"
    bad_dir.mkdir()
    (bad_dir / "junos-arm-32-23.4R2-S8.tgz").write_text("<html>login</html>", encoding="utf-8")
    r_rej = runner.invoke(
        cli_mod.main,
        [
            "firmware",
            "scan",
            str(bad_dir),
            "--firmware-dir",
            str(tmp_path / "fw"),
            "--releases",
            str(RELEASES_YML),
        ],
    )
    assert r_rej.exit_code != 0

    # firmware login with missing --watch-dir fails fast instead of blocking
    manifest = tmp_path / "inv.json"
    inv_mod.save_inventory([_make_switch("SW_CORE", "192.0.2.10", role="Core")], manifest)
    r_login = runner.invoke(
        cli_mod.main,
        [
            "firmware",
            "login",
            "--manifest",
            str(manifest),
            "--releases",
            str(RELEASES_YML),
            "--watch-dir",
            str(tmp_path / "does_not_exist"),
        ],
    )
    assert r_login.exit_code != 0

    # stage with Core switch without --include-cores processes 0 switches -> non-zero exit
    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or FIXED_ORIGIN),
    )
    monkeypatch.setattr(cli_mod, "run_upgrade_batches", lambda *a, **k: ([], True))
    r_stage_zero = runner.invoke(
        cli_mod.main,
        [
            "stage",
            "--manifest",
            str(manifest),
            "--releases",
            str(RELEASES_YML),
            "--transfer-mode",
            "scp",
        ],
    )
    assert r_stage_zero.exit_code != 0
    assert "0 switches processed" in r_stage_zero.output

    # discover with 0 discovered switches exits non-zero
    monkeypatch.setattr(cli_mod, "discover_live_targets", lambda *a, **k: [])
    r_disc_zero = runner.invoke(
        cli_mod.main,
        ["discover", "--target", "192.0.2.10", "--releases", str(RELEASES_YML)],
    )
    assert r_disc_zero.exit_code != 0


def test_bundled_releases_data_resource_exists() -> None:
    import importlib.resources

    data_file = importlib.resources.files("junos_upgrader").joinpath("data/approved-releases.yml")
    assert data_file.is_file()


def test_cli_stage_and_upgrade_allowed_clients_default_none_and_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "inv.json"
    sw_dns = _make_switch("SW_DNS_01", "sw-lab-01.example.internal", model="ex3400-48p")
    sw_ip = _make_switch("SW_IP_01", "192.0.2.25", model="ex3400-48p")
    inv_mod.save_inventory([sw_dns, sw_ip], manifest)

    server_calls: list[dict[str, Any]] = []

    class CapturingServer:
        def __init__(self, **kwargs: Any) -> None:
            server_calls.append(kwargs)
            self.port = kwargs.get("port", 8080)

        def __enter__(self) -> CapturingServer:  # noqa: PYI034
            return self

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr(cli_mod, "UnifiedFirmwareServer", CapturingServer)
    monkeypatch.setattr(cli_mod, "load_credentials", lambda *a, **k: [])
    monkeypatch.setattr(
        cli_mod,
        "build_topology_graph",
        lambda sws, origin=None: build_topology_graph(sws, origin=origin or FIXED_ORIGIN),
    )
    monkeypatch.setattr(
        cli_mod,
        "run_upgrade_batches",
        lambda all_sw, targets, *a, **k: (list(targets), True),
    )

    runner = CliRunner()
    # Default stage & upgrade pass allowed_clients=None (DNS/NAT/routed friendly, token-protected)
    r_stage = runner.invoke(
        cli_mod.main,
        ["stage", "--manifest", str(manifest), "--releases", str(RELEASES_YML)],
    )
    assert r_stage.exit_code == 0, r_stage.output
    assert server_calls[-1]["allowed_clients"] is None

    r_up = runner.invoke(
        cli_mod.main,
        [
            "upgrade",
            "--manifest",
            str(manifest),
            "--releases",
            str(RELEASES_YML),
            "--change-number",
            "CHG001",
            "--operator",
            "netops",
        ],
    )
    assert r_up.exit_code == 0, r_up.output
    assert server_calls[-1]["allowed_clients"] is None

    # Opt-in --restrict-firmware-clients passes only validated literal IPs (skipping DNS hostnames)
    r_opt = runner.invoke(
        cli_mod.main,
        [
            "upgrade",
            "--manifest",
            str(manifest),
            "--releases",
            str(RELEASES_YML),
            "--change-number",
            "CHG002",
            "--operator",
            "netops",
            "--restrict-firmware-clients",
        ],
    )
    assert r_opt.exit_code == 0, r_opt.output
    assert server_calls[-1]["allowed_clients"] == {"192.0.2.25"}

    # Opt-in --restrict-firmware-clients fails cleanly when targeted switches have only DNS names
    r_dns_only = runner.invoke(
        cli_mod.main,
        [
            "stage",
            "--manifest",
            str(manifest),
            "--releases",
            str(RELEASES_YML),
            "--host",
            "SW_DNS_01",
            "--restrict-firmware-clients",
        ],
    )
    assert r_dns_only.exit_code != 0
    assert "literal IP address" in r_dns_only.output


def test_setup_windows_ps1_security_and_reliability_contracts() -> None:
    ps1 = (REPO_ROOT / "setup-windows.ps1").read_text(encoding="utf-8")
    assert "[ValidateRange(1, 65535)]" in ps1
    assert "Test-SignedInstaller" in ps1
    assert "Get-AuthenticodeSignature" in ps1
    assert "Get-FileHash" in ps1
    assert "-ErrorAction Stop" in ps1
    assert "finally {" in ps1
    assert "SysWOW64" in ps1
    assert "InstallAllUsers=0" in ps1
    assert "DoNotExpandEnvironmentNames" in ps1
    assert "ExpandString" in ps1
    assert "if (-not $Fix)" in ps1
    assert "$fwParams['Program'] = $vpy" in ps1
    assert "exit 1" in ps1
    # Ensure broken wildcard '$env:ProgramFiles\Python*' was removed
    assert "$env:ProgramFiles\\Python*" not in ps1
