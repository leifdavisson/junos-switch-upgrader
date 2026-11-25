# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for glob-based platform policies, EOL exclusions, version parsing, and inventory import/expansion."""

from __future__ import annotations

from pathlib import Path

import pytest

from junos_upgrader.inventory import expand_targets, import_from_crawler, scaffold_firmware_repo
from junos_upgrader.models import HopSpec, PlatformPolicy, SwitchRecord, SwitchState
from junos_upgrader.planner import (
    compute_remaining_hops,
    is_excluded_model,
    is_safe_package_filename,
    load_release_catalog,
    match_platform_policy,
    parse_junos_train,
    parse_junos_version_key,
    refresh_switch_plan,
)
from junos_upgrader.topology import RunnerOrigin

REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASES_YML = REPO_ROOT / "manifests" / "approved-releases.yml"
BUNDLED_RELEASES_YML = REPO_ROOT / "src" / "junos_upgrader" / "data" / "approved-releases.yml"


def test_parse_junos_train_and_version_key_variants() -> None:
    assert parse_junos_train("18.1R3-S4.2") == (18, 1)
    assert parse_junos_train("23.4R2.13") == (23, 4)
    assert parse_junos_train("23.4R2-S8") == (23, 4)
    assert parse_junos_train("15.1X53-D59") == (15, 1)

    # Case-insensitive parsing prevents silent downgrades
    assert parse_junos_version_key("23.4r2-s9") == parse_junos_version_key("23.4R2-S9")
    assert parse_junos_version_key("23.4R2.13") < parse_junos_version_key("23.4R2-S1")
    assert parse_junos_version_key("23.4R2-S8") < parse_junos_version_key("23.4R2-S8-J1")
    assert parse_junos_version_key("23.4R2-S8-J1") < parse_junos_version_key("23.4R2-S8-J2")
    assert parse_junos_version_key("23.4R2-S9") < parse_junos_version_key("23.4R2-S10")
    assert parse_junos_version_key("18.2X75-D40") < parse_junos_version_key("18.2X75-D430")
    assert parse_junos_version_key("18.2X75-D430") < parse_junos_version_key("18.2X75-D430.2")

    # Reject -EVO, trailing garbage, empty, and unknown strings
    for bad in ("23.4R2-S8-EVO", "23.4garbage", "23.4R2-bad", "unknown", "", "not-a-version"):
        with pytest.raises(ValueError):
            parse_junos_version_key(bad)
        with pytest.raises(ValueError):
            parse_junos_train(bad)


def test_glob_platform_specificity_and_mgig_separation() -> None:
    _, policies, exclusions = load_release_catalog(RELEASES_YML)

    # EX4300-48MP must match x86-64-vmhost BEFORE generic ex4300* powerpc
    mp_pol = match_platform_policy("ex4300-48mp", policies)
    assert mp_pol is not None
    assert mp_pol.expected_arch == "x86-64-vmhost"
    assert mp_pol.package_family == "jinstall-host-ex-4300mp"

    std_4300 = match_platform_policy("ex4300-48p", policies)
    assert std_4300 is not None
    assert std_4300.expected_arch == "powerpc"
    assert std_4300.package_family == "jinstall-ex-4300"

    # EX2300-C-12P on 23.4R2.13 -> single intra-train hop to 23.4R2-S8 with HTTP streaming
    ex2300 = match_platform_policy("ex2300-c-12p", policies)
    assert ex2300 is not None
    assert ex2300.prefer_http_stream is True
    hops = compute_remaining_hops("23.4R2.13", ex2300)
    assert [h.target_version for h in hops] == ["23.4R2-S8"]

    # Lowercase newer version must NEVER schedule a downgrade
    assert compute_remaining_hops("23.4r2-s9", ex2300) == []

    # Non-EOL QFX5200 & EX4400 supported; EOL EX4200 / QFX5100 / HP excluded
    assert match_platform_policy("qfx5200-32c", policies) is not None
    assert match_platform_policy("ex4400-48mp", policies) is not None
    assert is_excluded_model("ex4200-48t", exclusions) is not None
    assert is_excluded_model("qfx5100-48s", exclusions) is not None
    assert is_excluded_model("HP 5412zl", exclusions) is not None

    # Character-class glob '[' support in is_excluded_model
    char_exclusions = [{"pattern": "ex[23]200*", "policy": "EOL"}]
    assert is_excluded_model("ex2200-48p", char_exclusions) == "EOL"
    assert is_excluded_model("ex3200-24t", char_exclusions) == "EOL"
    assert is_excluded_model("ex3400-48p", char_exclusions) is None


def test_ex3400_ex4600_ex4100_and_ex4400_hop_sequences() -> None:
    _, policies, _ = load_release_catalog(RELEASES_YML)
    ex3400_pol = match_platform_policy("ex3400-48p", policies)
    ex4600_pol = match_platform_policy("ex4600-40f", policies)
    ex4100_pol = match_platform_policy("ex4100-48mp", policies)
    ex4400_pol = match_platform_policy("ex4400-48p", policies)
    assert ex3400_pol and ex4600_pol and ex4100_pol and ex4400_pol

    ex3400_hops = compute_remaining_hops("18.1R3-S4.2", ex3400_pol)
    assert [h.train for h in ex3400_hops] == [
        "18.4",
        "19.3",
        "20.2",
        "21.2",
        "22.2",
        "23.2",
        "23.4R2-S8",
    ]
    assert ex3400_hops[3].install_options == ["no-validate"]

    ex4600_hops = compute_remaining_hops("17.3R3-S4.2", ex4600_pol)
    assert [h.train for h in ex4600_hops] == ["18.2", "19.1", "19.4", "20.4", "21.4R3-S12"]
    assert all("force-host" in h.install_options for h in ex4600_hops)

    # EX4100 and EX4400 include intermediate hops so legacy installs never jump >4 quarters
    assert [h.train for h in compute_remaining_hops("22.1R1.10", ex4100_pol)] == [
        "22.2",
        "23.2",
        "23.4R2-S8",
    ]
    assert [h.train for h in compute_remaining_hops("21.2R3-S1", ex4400_pol)] == [
        "21.4",
        "22.4",
        "23.4R2-S8",
    ]
    assert "no-validate" in ex4400_pol.hops[0].install_options


def test_compute_remaining_hops_caps_at_final_target_and_dedupes_same_train() -> None:
    pol = PlatformPolicy(
        model_pattern="ex3400*",
        vendor="juniper",
        role_scope="access",
        final_target="23.4R2-S8",
        package_family="junos-arm-32",
        expected_arch="arm-32",
        min_free_storage_mb=600,
        boot_timeout_seconds=600,
        hops=[
            HopSpec("23.2", "23.2R2-S1", "junos-arm-32-23.2R2-S1.tgz", "md5", "a" * 32),
            HopSpec("23.2", "23.2R2-S3", "junos-arm-32-23.2R2-S3.tgz", "md5", "b" * 32),
            HopSpec("23.4", "23.4R2-S8", "junos-arm-32-23.4R2-S8.tgz", "md5", "c" * 32),
            HopSpec("24.4", "24.4R2.23", "junos-arm-32-24.4R2.23.tgz", "md5", "d" * 32),
        ],
    )
    hops = compute_remaining_hops("22.2R3-S5", pol)
    # Keeps only the highest hop in 23.2 (23.2R2-S3) and excludes 24.4R2.23 (> final_target)
    assert [h.target_version for h in hops] == ["23.2R2-S3", "23.4R2-S8"]


def test_load_release_catalog_validation_and_coercion(tmp_path: Path) -> None:
    # Unquoted YAML float train: 18.4 is coerced safely and v1 dict platforms work
    v1_yml = tmp_path / "v1.yml"
    v1_yml.write_text(
        (
            "platforms:\n"
            "  ex3400*:\n"
            "    final_target: 23.4R2-S8\n"
            "    package_family: junos-arm-32\n"
            "    expected_arch: arm-32\n"
            "    hops:\n"
            "      - train: 18.4\n"
            "        target_version: 18.4R3-S15\n"
            "        package_filename: junos-arm-32-18.4R3-S15.tgz\n"
            "        checksum: REPLACE_WITH_JUNIPER_MD5\n"
        ),
        encoding="utf-8",
    )
    _, policies, exclusions = load_release_catalog(v1_yml)
    assert len(policies) == 1
    assert policies[0].hops[0].train == "18.4"
    assert exclusions == []

    # Empty YAML fails cleanly with ValueError
    empty_yml = tmp_path / "empty.yml"
    empty_yml.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="top-level YAML mapping"):
        load_release_catalog(empty_yml)

    # Unsafe package_filename rejected in _parse_hops
    bad_fn_yml = tmp_path / "bad_fn.yml"
    bad_fn_yml.write_text(
        (
            "platforms:\n"
            "  - model_pattern: ex3400*\n"
            "    final_target: 23.4R2-S8\n"
            "    hops:\n"
            "      - train: '23.4'\n"
            "        target_version: 23.4R2-S8\n"
            "        package_filename: '../evil;reboot.tgz'\n"
            "        checksum: REPLACE_WITH_JUNIPER_MD5\n"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Unsafe package_filename"):
        load_release_catalog(bad_fn_yml)

    assert is_safe_package_filename("junos-arm-32-23.4R2-S8.tgz")
    assert not is_safe_package_filename("../evil.tgz")
    assert not is_safe_package_filename("junos-arm-32;reboot.tgz")
    assert not is_safe_package_filename(".hidden.tgz")


def test_refresh_switch_plan_handles_unknown_evo_empty_hops_and_state_hygiene() -> None:
    _, policies, exclusions = load_release_catalog(RELEASES_YML)

    # Unparseable "unknown" or "-EVO" version must NOT crash -> sets NOT_READY + last_error
    for bad_ver in ("unknown", "23.4R2-S8-EVO", ""):
        sw = SwitchRecord(
            site="SITE",
            hostname="SW_BAD_VER",
            management_ip="192.0.2.50",
            model="ex3400-48p",
            serial_number="SN50",
            current_version=bad_ver,
            role="Access",
            management_method="SSH",
            state=SwitchState.READY,
        )
        refresh_switch_plan(sw, policies, exclusions)
        assert sw.state == SwitchState.NOT_READY
        assert sw.next_hop == ""
        assert "Unparseable Junos version" in sw.last_error

    # Empty hops policy must NOT falsely mark outdated switch COMPLETED
    empty_pol = PlatformPolicy(
        model_pattern="ex3400*",
        vendor="juniper",
        role_scope="access",
        final_target="23.4R2-S8",
        package_family="junos-arm-32",
        expected_arch="arm-32",
        min_free_storage_mb=600,
        boot_timeout_seconds=600,
        hops=[],
    )
    sw_old = SwitchRecord(
        site="SITE",
        hostname="SW_OLD",
        management_ip="192.0.2.51",
        model="ex3400-48p",
        serial_number="SN51",
        current_version="22.2R3-S5",
        role="Access",
        management_method="SSH",
        state=SwitchState.READY,
    )
    refresh_switch_plan(sw_old, [empty_pol], [])
    assert sw_old.state == SwitchState.NOT_READY
    assert "No upgrade hop path" in sw_old.last_error

    # ANCESTOR_HOLD must be preserved even when already at final_target
    sw_held = SwitchRecord(
        site="SITE",
        hostname="SW_HELD",
        management_ip="192.0.2.52",
        model="ex3400-48p",
        serial_number="SN52",
        current_version="23.4R2-S8",
        role="Access",
        management_method="SSH",
        state=SwitchState.ANCESTOR_HOLD,
        last_error="Held for downstream",
    )
    refresh_switch_plan(sw_held, policies, exclusions)
    assert sw_held.state == SwitchState.ANCESTOR_HOLD

    # Transitioning from EXCLUDED -> READY clears stale exclusion_reason and last_error
    sw_recover = SwitchRecord(
        site="SITE",
        hostname="SW_REC",
        management_ip="192.0.2.53",
        model="ex3400-48p",
        serial_number="SN53",
        current_version="23.2R2-S3",
        role="Access",
        management_method="SSH",
        state=SwitchState.EXCLUDED,
        exclusion_reason="Previously excluded",
        last_error="Old error",
    )
    refresh_switch_plan(sw_recover, policies, exclusions)
    assert sw_recover.state == SwitchState.READY
    assert sw_recover.exclusion_reason == ""
    assert sw_recover.last_error == ""


def test_bundled_data_manifest_matches_repo_manifest() -> None:
    assert BUNDLED_RELEASES_YML.is_file()
    assert BUNDLED_RELEASES_YML.read_bytes() == RELEASES_YML.read_bytes()


def test_import_synthetic_crawler_inventory_and_expand_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixed_origin = RunnerOrigin("TEST-RUNNER", "192.0.2.1", "eth0", "192.0.2.254")
    monkeypatch.setattr(
        "junos_upgrader.topology.detect_local_runner_origin",
        lambda _ip="192.0.2.1": fixed_origin,
    )

    crawler_dir = tmp_path / "crawler_run"
    norm_dir = crawler_dir / "02_normalized"
    norm_dir.mkdir(parents=True)

    (crawler_dir / "asset_inventory.csv").write_text(
        (
            "Hostname,IP Address,MAC Address,Device Type,Model,Firmware,Serial Number,Role,Management Method\n"
            "CAMPUS_MDF_CORE_01,192.0.2.10,00:00:5e:00:53:10,Switch,ex4600-40f,17.3R3-S4.2,SN0001,Core,SSH\n"
            "CAMPUS_IDF_A_TRANSIT,192.0.2.11,00:00:5e:00:53:11,Switch,ex3400-48p,18.1R3-S4.2,SN0002,Access,SSH\n"
            "CAMPUS_IDF_A_LEAF,192.0.2.12,00:00:5e:00:53:12,Switch,HP 2530-48G,YA.16.01,SN0003,Access,Telnet\n"
            "CAMPUS_IDF_B_MGIG,192.0.2.13,00:00:5e:00:53:13,Switch,ex4100-48mp,23.4R2-S4.11,SN0004,Access,SSH\n"
        ),
        encoding="utf-8",
    )
    (norm_dir / "neighbors.csv").write_text(
        (
            "source_device,site_code,local_port,remote_device,remote_port,remote_ip,remote_mac,platform,device_type,link_confidence,capture_time\n"
            "CAMPUS_MDF_CORE_01,CAMPUS,xe-0/0/0,CAMPUS_IDF_A_TRANSIT,xe-0/2/0,192.0.2.11,00:00:5e:00:53:11,Juniper,switch,two-way,2026-01-01T00:00:00Z\n"
            "CAMPUS_IDF_A_TRANSIT,CAMPUS,ge-0/0/7,CAMPUS_IDF_A_LEAF,48,192.0.2.12,00:00:5e:00:53:12,HP,switch,two-way,2026-01-01T00:00:00Z\n"
            "CAMPUS_MDF_CORE_01,CAMPUS,xe-0/0/1,CAMPUS_IDF_B_MGIG,xe-0/2/0,192.0.2.13,00:00:5e:00:53:13,Juniper,switch,two-way,2026-01-01T00:00:00Z\n"
        ),
        encoding="utf-8",
    )

    out_manifest = tmp_path / "site-inventory.json"
    records = import_from_crawler(crawler_dir, RELEASES_YML, out_manifest)

    assert len(records) == 4
    assert len([r for r in records if r.state == SwitchState.EXCLUDED]) == 1
    assert len([r for r in records if r.state == SwitchState.READY]) == 3

    ex4100 = next(r for r in records if r.hostname == "CAMPUS_IDF_B_MGIG")
    assert ex4100.next_hop == "23.4R2-S8"

    transit = next(r for r in records if r.hostname == "CAMPUS_IDF_A_TRANSIT")
    assert "CAMPUS_IDF_A_LEAF" in transit.downstream_switches

    tfile = tmp_path / "targets.txt"
    tfile.write_text("# comment\n192.0.2.99\n", encoding="utf-8")
    expanded = expand_targets(("198.51.100.0/30",), tfile)
    assert expanded == ["198.51.100.1", "198.51.100.2", "192.0.2.99"]


def test_scaffold_firmware_repo(tmp_path: Path) -> None:
    created = scaffold_firmware_repo(tmp_path / "switch-firmware")
    assert len(created) >= 30
    assert (
        tmp_path / "switch-firmware" / "firmware" / "juniper" / "ex4300-48mp" / "23.4R2-S8"
    ).is_dir()
    assert (tmp_path / "switch-firmware" / "deliverables" / "configs").is_dir()
