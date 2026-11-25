# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pre-upgrade health gates, storage cleanup, filesystem/hardware triage, and baseline checks."""

from __future__ import annotations

import difflib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from junos_upgrader.junos_client import SwitchTransport
from junos_upgrader.models import (
    CheckResult,
    HopSpec,
    PlatformPolicy,
    SwitchRecord,
    SwitchState,
    TriageVerdict,
)
from junos_upgrader.packages import extract_switch_arch, validate_package_match
from junos_upgrader.transfer import SAFE_PACKAGE_FILENAME_RE

BASELINE_COMMANDS: list[tuple[str, str]] = [
    ("show_version.txt", "show version"),
    ("show_version.json", "show version | display json"),
    ("show_chassis_hardware.txt", "show chassis hardware"),
    ("show_chassis_environment.txt", "show chassis environment"),
    ("show_chassis_routing_engine.txt", "show chassis routing-engine"),
    ("show_chassis_firmware.txt", "show chassis firmware"),
    ("show_system_uptime.txt", "show system uptime"),
    ("show_system_alarms.txt", "show system alarms"),
    ("show_chassis_alarms.txt", "show chassis alarms"),
    ("show_system_storage.txt", "show system storage"),
    ("show_system_storage.json", "show system storage | display json"),
    ("show_system_snapshot.txt", "show system snapshot media internal"),
    ("show_system_commit.txt", "show system commit"),
    ("show_interfaces_terse.txt", "show interfaces terse"),
    ("show_interfaces_extensive.txt", "show interfaces extensive"),
    ("show_interfaces_diagnostics_optics.txt", "show interfaces diagnostics optics"),
    ("show_vlans.txt", "show vlans"),
    ("show_spanning_tree_bridge.txt", "show spanning-tree bridge"),
    ("show_spanning_tree_interface.txt", "show spanning-tree interface"),
    ("show_lldp_neighbors.txt", "show lldp neighbors"),
    ("show_ethernet_switching_table.txt", "show ethernet-switching table"),
    ("show_lacp_interfaces.txt", "show lacp interfaces"),
    ("show_route_summary.txt", "show route summary"),
    ("show_route.txt", "show route"),
    ("show_poe_controller.txt", "show poe controller"),
    ("show_poe_interface.txt", "show poe interface"),
    ("config_set.txt", "show configuration | display set | no-more"),
    ("config_hierarchical.txt", "show configuration | no-more"),
]

FAST_DELTA_COMMANDS: list[tuple[str, str]] = [
    ("show_version.txt", "show version"),
    ("show_system_alarms.txt", "show system alarms"),
    ("show_chassis_alarms.txt", "show chassis alarms"),
    ("show_system_storage.json", "show system storage | display json"),
    ("show_interfaces_terse.txt", "show interfaces terse"),
    ("show_lldp_neighbors.txt", "show lldp neighbors"),
    ("show_spanning_tree_bridge.txt", "show spanning-tree bridge"),
    ("show_poe_controller.txt", "show poe controller"),
    ("show_ethernet_switching_table.txt", "show ethernet-switching table"),
    ("show_lacp_interfaces.txt", "show lacp interfaces"),
    ("config_set.txt", "show configuration | display set | no-more"),
]

_HEAVY_BASELINE_COMMANDS = frozenset(
    {
        "show interfaces extensive",
        "show ethernet-switching table",
        "show route",
        "show configuration | display set | no-more",
        "show configuration | no-more",
    }
)

_STORAGE_SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([BKMGT])?$", re.IGNORECASE)
_ROOT_ID_RE = re.compile(r"Root ID\s*:\s*(\S+)", re.IGNORECASE)
_SNAPSHOT_VER_RE = re.compile(r"Junos version\s*:\s*(\S+)", re.IGNORECASE)
_FLASH_ERROR_RE = re.compile(
    r"(g_vfs_done|"
    r"(?:kernel:|da\d+|ad\d+|ada\d+|mmc\d*|flash|ufs|g_vfs).*Input/output error|"
    r"mmc\d*:.*error|bad block|UNEXPECTED INCONSISTENCY)",
    re.IGNORECASE,
)
_RO_MOUNT_RE = re.compile(
    r"^(?!.*(?:cd9660|nullfs|devfs|procfs|fdescfs|linprocfs)).*"
    r"\bon\s+(/\.mount|/var(?:/\S*)?|/)\s+\([^)]*\bread-only\b",
    re.IGNORECASE | re.MULTILINE,
)
_OPTICS_ACTIVE_ALARM_RE = re.compile(
    r"(?:rx\s+power\s+low|output\s+power\s+low|tx\s+power\s+low|laser\s+bias\s+current\s+high)"
    r"\s+alarm\s*:\s*on\b",
    re.IGNORECASE,
)
_HW_ALARM_RE = re.compile(
    r"\b(psu|power\s+supply|pem|fan|fpc|temp|thermal|over\s*temp|hardware|chassis|fru|slot)\b",
    re.IGNORECASE,
)
_MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.IGNORECASE)
_POE_ROW_RE = re.compile(r"^\s*\d+\s+(\d+(?:\.\d+)?)\s*W\s+(\d+(?:\.\d+)?)\s*W", re.IGNORECASE)
_WEAK_SSH_RE = re.compile(
    r"(cbc|hmac-sha1|ssh-dss|diffie-hellman-group1-sha1|protocol-version\s+v1)",
    re.IGNORECASE,
)
_LEGACY_SWITCHING_RE = re.compile(
    r"^\s*set\s+.*\bethernet-switching-options\b", re.IGNORECASE | re.MULTILINE
)
_TELNET_RE = re.compile(r"^\s*set\s+system\s+services\s+telnet\b", re.IGNORECASE | re.MULTILINE)
_DEACTIVATE_TELNET_RE = re.compile(
    r"^\s*deactivate\s+system\s+services\s+telnet\b", re.IGNORECASE | re.MULTILINE
)
_DEACTIVATE_SSH_RE = re.compile(
    r"^\s*deactivate\s+system\s+services\s+ssh\s*$", re.IGNORECASE | re.MULTILINE
)
_MODEL_LINE_RE = re.compile(r"^\s*Model\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_JUNOS_VER_LINE_RE = re.compile(r"^\s*Junos\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_JUNOS_BRACKET_VER_RE = re.compile(
    r"\[(\d+\.\d+[RX]\d+(?:[-.]?[SD]\d+(?:\.\d+)?|\.\d+)?(?:-[A-Za-z0-9.]+)?)\]",
    re.IGNORECASE,
)
_VC_MEMBER_RE = re.compile(
    r"(?:\b(?:Prsnt|NotPrsnt|Inactive|Unprvsnd)\b|^\s*\d+\s+\(FPC\s+\d+\))",
    re.IGNORECASE,
)
_COMMIT_ERR_RE = re.compile(
    r"(?:^\s*error:|\b(?:uncommitted|commit\s+confirmed|rollback\s+in\s+\d+|"
    r"automatically\s+rolled\s+back|auto-rollback)\b)",
    re.IGNORECASE | re.MULTILINE,
)
_CLI_ERROR_RE = re.compile(
    r"(?:^\s*error:|syntax error|unknown command|permission denied)",
    re.IGNORECASE | re.MULTILINE,
)
_PATH_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_path_segment(value: str, fallback: str = "unknown") -> str:
    """Sanitize a single path component so it cannot traverse or inject path separators."""
    cleaned = _PATH_SAFE_RE.sub("_", value.strip())
    cleaned = cleaned.strip("._")
    if not cleaned or cleaned in (".", "..") or ".." in cleaned:
        return fallback
    return cleaned


def safe_subpath(root: Path, *segments: str) -> Path:
    """Join sanitized path segments under root and verify containment."""
    root_resolved = root.resolve()
    target = root.joinpath(*(sanitize_path_segment(seg) for seg in segments))
    target_resolved = target.resolve()
    if target_resolved != root_resolved and root_resolved not in target_resolved.parents:
        raise ValueError(f"Resolved path {target_resolved} escapes root {root_resolved}")
    return target


def _parse_mb(token: str) -> int | None:
    match = _STORAGE_SIZE_RE.match(token.strip())
    if not match:
        return None
    val = float(match.group(1))
    unit = (match.group(2) or "").upper()
    if not unit:
        return 0 if val == 0 else None
    scale = {
        "B": 1 / (1024 * 1024),
        "K": 1 / 1024,
        "M": 1,
        "G": 1024,
        "T": 1024 * 1024,
    }[unit]
    return int(val * scale)


def _as_list(val: Any) -> list[Any]:
    if isinstance(val, list):
        return val
    if isinstance(val, dict):
        return [val]
    return []


def _extract_json_section(data: dict[str, Any], section: str) -> dict[str, Any]:
    if "multi-routing-engine-results" in data:
        results = _as_list(data.get("multi-routing-engine-results"))
        if results and isinstance(results[0], dict):
            items = _as_list(results[0].get("multi-routing-engine-item"))
            if items and isinstance(items[0], dict):
                secs = _as_list(items[0].get(section))
                if secs and isinstance(secs[0], dict):
                    return secs[0]
        return {}
    secs = _as_list(data.get(section))
    return secs[0] if secs and isinstance(secs[0], dict) else {}


def parse_junos_storage(storage_output: str) -> tuple[int | None, dict[str, int]]:
    """Parse available MB from `show system storage` (JSON or text), prioritizing /var/tmp, /var, /.mount."""
    mounts: dict[str, int] = {}
    text = storage_output.strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                sec = _extract_json_section(data, "system-storage-information")
                fs_list = _as_list(sec.get("filesystem"))
                for fs in fs_list:
                    if not isinstance(fs, dict):
                        continue
                    mount_nodes = _as_list(fs.get("mounted-on"))
                    mount = (
                        str(mount_nodes[0].get("data", "")).strip()
                        if mount_nodes and isinstance(mount_nodes[0], dict)
                        else ""
                    )
                    avail_nodes = _as_list(fs.get("available-blocks"))
                    avail_node = (
                        avail_nodes[0] if avail_nodes and isinstance(avail_nodes[0], dict) else {}
                    )
                    attrs = avail_node.get("attributes")
                    fmt = (
                        str(attrs.get("junos:format", "")).strip()
                        if isinstance(attrs, dict)
                        else ""
                    )
                    blocks = str(avail_node.get("data", "")).strip()
                    mb = _parse_mb(fmt) if fmt else None
                    if mb is None and blocks.isdigit():
                        mb = int(blocks) // 2048
                    if mount and mb is not None:
                        mounts[mount] = mb
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            mounts = {}

    if not mounts:
        pending_dev: str | None = None
        for line in text.splitlines():
            parts = line.split()
            if not parts:
                pending_dev = None
                continue
            if len(parts) == 1 and parts[0].startswith("/"):
                pending_dev = parts[0]
                continue
            if pending_dev is not None and len(parts) == 5:
                parts = [pending_dev, *parts]
                pending_dev = None
            else:
                pending_dev = None

            if len(parts) >= 6:
                mount = parts[-1]
                avail_mb = _parse_mb(parts[3])
            elif len(parts) == 5 and parts[-1].startswith("/") and _parse_mb(parts[0]) is not None:
                mount = parts[-1]
                avail_mb = _parse_mb(parts[2])
            else:
                continue

            if avail_mb is not None:
                mounts[mount] = avail_mb

    for preferred in ("/var/tmp", "/var", "/.mount", "/"):  # nosec B108
        if preferred in mounts:
            return mounts[preferred], mounts
    return None, mounts


def parse_recovery_snapshot(snapshot_output: str) -> str:
    """Extract recovery snapshot Junos version from `show system snapshot media internal`."""
    in_recovery = False
    for line in snapshot_output.splitlines():
        if "Recovery Snapshots:" in line:
            in_recovery = True
            continue
        if in_recovery:
            match = _SNAPSHOT_VER_RE.search(line)
            if match:
                return match.group(1)
    return ""


def _extract_version_and_model(ver_json: str, ver_txt: str) -> tuple[str, str]:
    """Extract exact (junos_version, product_model) from JSON or text `show version`."""
    live_ver = ""
    live_model = ""
    if ver_json.strip().startswith("{"):
        try:
            vdata = json.loads(ver_json)
            if isinstance(vdata, dict):
                sw_info = _extract_json_section(vdata, "software-information")
                ver_nodes = _as_list(sw_info.get("junos-version"))
                if ver_nodes and isinstance(ver_nodes[0], dict):
                    live_ver = str(ver_nodes[0].get("data", "")).strip()
                model_nodes = _as_list(sw_info.get("product-model"))
                if model_nodes and isinstance(model_nodes[0], dict):
                    live_model = str(model_nodes[0].get("data", "")).strip()
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            live_ver = ""
            live_model = ""

    if not live_ver and ver_txt:
        m_ver = _JUNOS_VER_LINE_RE.search(ver_txt) or _JUNOS_BRACKET_VER_RE.search(ver_txt)
        if m_ver:
            live_ver = m_ver.group(1).strip()

    if not live_model and ver_txt:
        m_model = _MODEL_LINE_RE.search(ver_txt)
        if m_model:
            live_model = m_model.group(1).strip()

    return live_ver, live_model


def collect_baseline(
    transport: SwitchTransport,
    output_dir: Path,
    fast_delta: bool = False,
) -> dict[str, str]:
    """Run baseline commands (full 28-cmd capture or fast 11-cmd intermediate delta)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, str] = {}
    commands = FAST_DELTA_COMMANDS if fast_delta else BASELINE_COMMANDS
    for filename, cmd in commands:
        timeout = 180 if cmd in _HEAVY_BASELINE_COMMANDS else 60
        output = transport.run_command(cmd, read_timeout=timeout)
        results[cmd] = output
        (output_dir / filename).write_text(output, encoding="utf-8")
    return results


def check_config_landmines(
    config_set_text: str,
    evidence_dir: Path | None = None,
) -> list[CheckResult]:
    """Scan set-format configuration for deprecated SSH, legacy switching, and telnet risks."""
    warnings: list[str] = []
    ssh_deactivated = bool(_DEACTIVATE_SSH_RE.search(config_set_text))
    telnet_deactivated = bool(_DEACTIVATE_TELNET_RE.search(config_set_text))

    if not ssh_deactivated:
        seen_ssh: set[str] = set()
        for line in config_set_text.splitlines():
            stripped = line.strip()
            if not stripped.lower().startswith("set "):
                continue
            if "system services ssh" in stripped.lower() and _WEAK_SSH_RE.search(stripped):
                if stripped not in seen_ssh:
                    seen_ssh.add(stripped)
                    warnings.append(f"Deprecated SSH crypto/protocol stanza: {stripped}")

    if _LEGACY_SWITCHING_RE.search(config_set_text):
        warnings.append(
            "Legacy non-ELS `ethernet-switching-options` syntax detected (review release notes before crossing trains)."
        )
    if not telnet_deactivated and _TELNET_RE.search(config_set_text):
        warnings.append("Plaintext `system services telnet` is enabled.")

    if evidence_dir is not None:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        body = "\n".join(warnings) if warnings else "No configuration landmines detected."
        (evidence_dir / "config_landmines.txt").write_text(body + "\n", encoding="utf-8")

    if not warnings:
        return [
            CheckResult(
                name="config_landmines",
                passed=True,
                hard_stop=False,
                severity="info",
                message="No cross-train configuration landmines detected.",
            )
        ]

    return [
        CheckResult(
            name="config_landmines",
            passed=False,
            hard_stop=False,
            severity="warn",
            message=w,
        )
        for w in warnings
    ]


def _read_existing_recovery_field(output_path: Path, prefix: str) -> str:
    if not output_path.is_file():
        return ""
    try:
        for line in output_path.read_text(encoding="utf-8").splitlines():
            if line.startswith(prefix):
                val = line[len(prefix) :].strip()
                if val and not val.startswith("<"):
                    return val
    except OSError:
        return ""
    return ""


def generate_recovery_sheet(
    switch: SwitchRecord,
    policy: PlatformPolicy,
    baseline: dict[str, str],
    output_path: Path,
) -> Path:
    """Generate a ready-to-paste loader/USB/TFTP recovery cheat-sheet from live baseline data."""
    cfg_set = baseline.get("show configuration | display set | no-more", "")
    route_txt = baseline.get("show route", "")

    netmask = "255.255.255.0"
    cidr_match = re.search(rf"\b{re.escape(switch.management_ip)}/(\d+)\b", cfg_set)
    if cidr_match:
        try:
            iface = ipaddress.IPv4Interface(f"{switch.management_ip}/{cidr_match.group(1)}")
            netmask = str(iface.netmask)
        except ValueError:
            pass
    else:
        prev_mask = _read_existing_recovery_field(output_path, "Netmask:")
        if prev_mask:
            netmask = prev_mask

    gateway = "<DEFAULT_GATEWAY>"
    gw_cfg = re.search(r"routing-options static route 0\.0\.0\.0/0 next-hop (\S+)", cfg_set)
    if gw_cfg:
        gateway = gw_cfg.group(1)
    else:
        gw_rt = re.search(r"0\.0\.0\.0/0.*?\bto\s+(\d+\.\d+\.\d+\.\d+)", route_txt, re.DOTALL)
        if gw_rt:
            gateway = gw_rt.group(1)
        else:
            prev_gw = _read_existing_recovery_field(output_path, "Gateway:")
            if prev_gw:
                gateway = prev_gw

    if any(tok in policy.expected_arch for tok in ("vmhost", "qfx", "ex-4650")):
        recovery_cmds = (
            "Boot Alternate Slice / USB Recovery (Host/QFX/EX4300-MP):\n"
            "  1. Capture console output and check boot menu for alternate slice.\n"
            "  2. If VMHost fails: boot from certified USB install media and restore config.set.txt.\n"
            "  3. Post-boot verify `show vmhost status` and `request system configuration rescue save`.\n"
        )
    else:
        recovery_cmds = (
            "Loader TFTP Format/Install Procedure (EX2300/EX3400/EX4100/EX4300/EX4400):\n"
            f"  loader> set ipaddr={switch.management_ip}\n"
            f"  loader> set netmask={netmask}\n"
            f"  loader> set gatewayip={gateway}\n"
            "  loader> set serverip=<TFTP_SERVER_IP>\n"
            f"  loader> install --format tftp://<TFTP_SERVER_IP>/<junos-install-media-net-{policy.family_dir}.tgz>\n"
        )

    lines = [
        f"# Recovery Cheat-Sheet: {switch.hostname}",
        f"Site: {switch.site}",
        f"Model: {switch.model} (arch={switch.kernel_arch or policy.expected_arch})",
        f"Serial: {switch.serial_number}",
        f"Management IP: {switch.management_ip}",
        f"Netmask: {netmask}",
        f"Gateway: {gateway}",
        f"Version at Backup: {switch.current_version} -> Target: {switch.final_target or policy.final_target}",
        f"OAM Recovery Snapshot: {switch.recovery_snapshot or 'none recorded'}",
        f"Console Server / Port: {switch.console_port or 'UNASSIGNED (local console required)'}",
        f"Upstream Switch: {switch.upstream_switch or 'unknown'} ({switch.upstream_local_port} <-> {switch.upstream_remote_port})",
        "",
        recovery_cmds.rstrip(),
        "",
        "Restore saved config after recovery boot:",
        "  configure",
        "  load override /var/tmp/config.set.txt",
        "  commit and-quit",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def backup_configuration(
    transport: SwitchTransport,
    config_dir: Path,
    baseline: dict[str, str],
    save_rescue: bool = True,
) -> Path:
    """Persist set-format and hierarchical configs (when captured) and optionally save rescue config."""
    config_dir.mkdir(parents=True, exist_ok=True)
    set_cfg = baseline.get("show configuration | display set | no-more", "")
    set_path = config_dir / "config.set.txt"
    set_path.write_text(set_cfg, encoding="utf-8")

    hier_cfg = baseline.get("show configuration | no-more", "")
    if hier_cfg:
        hier_path = config_dir / "config.hierarchical.txt"
        hier_path.write_text(hier_cfg, encoding="utf-8")

    if save_rescue:
        transport.run_command("request system configuration rescue save")
    return set_path


def _extract_safe_var_tmp_tgz_paths(tmp_list: str) -> list[str]:
    """Extract only safe regular `/var/tmp/<name>.tgz` paths from `file list /var/tmp detail`."""
    paths: list[str] = []
    seen: set[str] = set()
    for raw_line in tmp_list.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("total ") or line.endswith(":"):
            continue
        # Never follow or delete symlink entries or symlink targets
        if line.startswith("l") or " -> " in line:
            continue
        parts = line.split()
        if not parts:
            continue
        # In `ls -l` detail output, columns 0..7 are perms/links/owner/group/size/month/day/time
        if len(parts) >= 9 and parts[0][0] in "-d":
            if parts[0].startswith("d"):
                continue
            token = " ".join(parts[8:])
        elif len(parts) == 1:
            token = parts[0]
        else:
            token = parts[-1]

        if token.startswith("/var/tmp/"):  # nosec B108
            candidate_name = token[len("/var/tmp/") :]  # nosec B108
        elif "/" in token or "\\" in token:
            continue
        else:
            candidate_name = token

        if ".." in candidate_name or not SAFE_PACKAGE_FILENAME_RE.fullmatch(candidate_name):
            continue
        full_path = f"/var/tmp/{candidate_name}"  # nosec B108
        if full_path not in seen:
            seen.add(full_path)
            paths.append(full_path)
    return paths


def auto_cleanup_storage(
    transport: SwitchTransport,
    evidence_dir: Path,
    execute_cleanup: bool = True,
    preserve_paths: set[str] | None = None,
) -> tuple[int | None, str]:
    """Audit /var/crash & /var/tmp, preview cleanup, and optionally execute safe cleanup."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    crash_list = transport.run_command("file list /var/crash detail")
    tmp_list = transport.run_command("file list /var/tmp detail")
    dry_clean = transport.run_command("request system storage cleanup dry-run", read_timeout=90)

    (evidence_dir / "var_crash_list.txt").write_text(crash_list, encoding="utf-8")
    (evidence_dir / "var_tmp_list.txt").write_text(tmp_list, encoding="utf-8")
    (evidence_dir / "storage_cleanup_dry_run.txt").write_text(dry_clean, encoding="utf-8")

    preserved = {p.strip() for p in (preserve_paths or set()) if p.strip()}
    if execute_cleanup:
        for full_path in _extract_safe_var_tmp_tgz_paths(tmp_list):
            if full_path in preserved:
                continue
            transport.run_command(f"file delete {full_path}")
        # Junos `request system storage cleanup` purges /var/tmp/*; skip it when preserving a pre-staged image
        if not any(p.startswith("/var/tmp/") for p in preserved):  # nosec B108
            clean_out = transport.run_command(
                "request system storage cleanup no-confirm", read_timeout=120
            )
            (evidence_dir / "storage_cleanup_executed.txt").write_text(clean_out, encoding="utf-8")

    storage_json = transport.run_command("show system storage | display json")
    if not storage_json.strip().startswith("{"):
        storage_json = transport.run_command("show system storage")
    free_mb, _ = parse_junos_storage(storage_json)
    return free_mb, dry_clean


def evaluate_hardware_and_fs_triage(
    transport: SwitchTransport,
    switch: SwitchRecord,
    policy: PlatformPolicy,
    evidence_dir: Path,
    config_root: Path,
    execute_cleanup: bool = False,
    ignore_old_cores: bool = False,
    expected_hop_filename: str = "",
) -> tuple[TriageVerdict, list[CheckResult]]:
    """Run hardware, flash filesystem, crash, and optics triage to separate Replace vs Upgrade."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    checks: list[CheckResult] = []
    replace_triggers: list[str] = []

    preserve: set[str] | None = None
    # Only preserve when an image is actually staged on-device under /var/tmp/
    if switch.staged_package and switch.staged_package.startswith("/var/tmp/"):  # nosec B108
        staged_name = Path(switch.staged_package).name
        if not expected_hop_filename or staged_name == expected_hop_filename:
            preserve = {f"/var/tmp/{staged_name}"}  # nosec B108
    free_mb, _ = auto_cleanup_storage(
        transport,
        evidence_dir,
        execute_cleanup=execute_cleanup,
        preserve_paths=preserve,
    )
    switch.free_storage_mb = free_mb

    # 1. Read-only mount check (fail-closed if mount output is empty or permission-denied)
    mount_out = transport.run_command('start shell command "mount"')
    (evidence_dir / "mounts.txt").write_text(mount_out, encoding="utf-8")
    mount_cmd_err = not mount_out.strip() or bool(_CLI_ERROR_RE.search(mount_out))
    ro_bad = (not mount_cmd_err) and bool(_RO_MOUNT_RE.search(mount_out))
    if mount_cmd_err:
        checks.append(
            CheckResult(
                name="fs_read_write",
                passed=False,
                hard_stop=True,
                severity="fail",
                message=(
                    'Unable to inspect mount state via `start shell command "mount"`: '
                    f"{mount_out.strip()[:160] or 'empty output'}"
                ),
            )
        )
    else:
        checks.append(
            CheckResult(
                name="fs_read_write",
                passed=not ro_bad,
                severity="replace" if ro_bad else "info",
                message=(
                    "Flash filesystems are mounted read-write."
                    if not ro_bad
                    else "CRITICAL: Root or /var/.mount filesystem mounted READ-ONLY!"
                ),
            )
        )
    if ro_bad:
        replace_triggers.append("Read-only filesystem detected")

    # 2. Flash/MMC hardware I/O errors in syslog (ignore our own UI_CMDLINE audit echo)
    log_out = transport.run_command(
        'show log messages | match "g_vfs_done|Input/output error|mmc[0-9]*:.*[Ee]rror|bad block|UNEXPECTED INCONSISTENCY" | except UI_CMDLINE | last 25'
    )
    (evidence_dir / "flash_log_scan.txt").write_text(log_out, encoding="utf-8")
    filtered_log = "\n".join(
        ln
        for ln in log_out.splitlines()
        if "UI_CMDLINE" not in ln and "show log messages" not in ln
    )
    flash_err = bool(_FLASH_ERROR_RE.search(filtered_log))
    checks.append(
        CheckResult(
            name="fs_flash_errors",
            passed=not flash_err,
            severity="replace" if flash_err else "info",
            message=(
                "No flash/MMC I/O errors found in syslog."
                if not flash_err
                else f"CRITICAL: Flash/MMC I/O errors detected in messages: {filtered_log.strip()[:160]}"
            ),
        )
    )
    if flash_err:
        replace_triggers.append("Flash/MMC I/O errors in syslog")

    # 3. Chassis environment & alarms (Fan, Thermal, PSU, FPC, PoE hardware faults)
    env_out = transport.run_command("show chassis environment")
    chas_alarms = transport.run_command("show chassis alarms")
    sys_alarms = transport.run_command("show system alarms")
    (evidence_dir / "chassis_environment.txt").write_text(env_out, encoding="utf-8")

    alarm_bad = (
        "No alarms currently active" not in chas_alarms
        or "No alarms currently active" not in sys_alarms
    )
    chas_non_var_alarm = "No alarms currently active" not in chas_alarms and not (
        "1 alarms currently active" in chas_alarms and "/var partition usage is high" in chas_alarms
    )
    chas_hw_alarm = chas_non_var_alarm and bool(_HW_ALARM_RE.search(chas_alarms))
    # Empty redundant PSU/module slots report "Absent" even on healthy switches with unrelated alarms
    hw_fault = any(
        bad in env_out.lower() for bad in ("failed", "over temp", "defect", "offline")
    ) or ("absent" in env_out.lower() and chas_hw_alarm)
    only_var_usage_alarm = (
        alarm_bad
        and not chas_non_var_alarm
        and not hw_fault
        and "1 alarms currently active" in sys_alarms
        and "/var partition usage is high" in sys_alarms
        and (free_mb is not None and free_mb >= policy.min_free_storage_mb)
    )
    checks.append(
        CheckResult(
            name="chassis_health",
            passed=not (hw_fault or (alarm_bad and not only_var_usage_alarm)),
            hard_stop=(hw_fault or (alarm_bad and not only_var_usage_alarm)),
            severity=(
                "replace"
                if hw_fault
                else ("warn" if only_var_usage_alarm else ("fail" if alarm_bad else "info"))
            ),
            message=(
                "Chassis environment OK and zero active alarms."
                if not (hw_fault or alarm_bad)
                else (
                    "Minor storage usage alarm active (/var partition usage is high) — auto-cleanup enabled for install."
                    if only_var_usage_alarm
                    else f"Hardware/alarm fault: env_fault={hw_fault}, sys={sys_alarms.strip()!r}, chas={chas_alarms.strip()!r}"
                )
            ),
        )
    )
    if hw_fault:
        replace_triggers.append("Chassis fan/thermal/PSU/FPC hardware fault")

    # 4. Crash dumps in /var/crash
    crash_txt = (evidence_dir / "var_crash_list.txt").read_text(encoding="utf-8")
    crash_files = [
        line.strip()
        for line in crash_txt.splitlines()
        if any(ext in line for ext in ("vmcore", ".core"))
    ]
    crash_bad = len(crash_files) > 0 and not ignore_old_cores
    checks.append(
        CheckResult(
            name="no_crash_dumps",
            passed=not crash_bad,
            severity="replace" if crash_bad else "info",
            message=(
                "No kernel/process crash dumps in /var/crash."
                if not crash_bad
                else f"Crash dumps present in /var/crash: {', '.join(crash_files[:3])}"
            ),
        )
    )
    if crash_bad:
        replace_triggers.append("Core/vmcore crash dumps in /var/crash")

    # 5. Uplink optics alarms (only active ': On' alarms, never ': Off')
    optics_out = transport.run_command("show interfaces diagnostics optics")
    optics_bad = bool(_OPTICS_ACTIVE_ALARM_RE.search(optics_out))
    checks.append(
        CheckResult(
            name="uplink_optics_health",
            passed=not optics_bad,
            severity="replace" if optics_bad else "info",
            message=(
                "Optics levels within normal thresholds (or copper only)."
                if not optics_bad
                else "Optics alarm detected (low Rx/Tx power or high laser bias — risk of link loss after reboot)!"
            ),
        )
    )
    if optics_bad:
        replace_triggers.append("Optics alarm on SFP/SFP+ link")

    # 6. Storage floor
    storage_ok = free_mb is not None and free_mb >= policy.min_free_storage_mb
    checks.append(
        CheckResult(
            name="storage_floor",
            passed=storage_ok,
            severity="replace" if not storage_ok else "info",
            message=(
                f"Free storage {free_mb} MB >= {policy.min_free_storage_mb} MB floor."
                if storage_ok
                else f"Storage {free_mb} MB below minimum {policy.min_free_storage_mb} MB floor."
            ),
            details={"free_mb": free_mb, "min_mb": policy.min_free_storage_mb},
        )
    )
    if not storage_ok:
        replace_triggers.append(
            f"Insufficient storage ({free_mb} MB < {policy.min_free_storage_mb} MB)"
        )

    # 7. Recovery snapshot info (informational/warning)
    snap_out = transport.run_command("show system snapshot media internal")
    switch.recovery_snapshot = parse_recovery_snapshot(snap_out)
    checks.append(
        CheckResult(
            name="recovery_snapshot",
            passed=True,
            hard_stop=False,
            severity="info" if switch.recovery_snapshot else "warn",
            message=(
                f"Recovery OAM snapshot present: {switch.recovery_snapshot}."
                if switch.recovery_snapshot
                else "No internal OAM recovery snapshot detected."
            ),
        )
    )

    if replace_triggers:
        # Immediately quarantine and export live config while the switch is reachable!
        q_dir = safe_subpath(config_root, switch.site, switch.hostname, "quarantine_backup")
        set_cfg = transport.run_command("show configuration | display set | no-more")
        hier_cfg = transport.run_command("show configuration | no-more")
        backup_configuration(
            transport,
            q_dir,
            {
                "show configuration | display set | no-more": set_cfg,
                "show configuration | no-more": hier_cfg,
            },
            save_rescue=False,
        )
        switch.triage_verdict = TriageVerdict.REPLACE_RECOMMENDED.value
        switch.triage_reasons = replace_triggers
        switch.state = SwitchState.REPLACE_RECOMMENDED
        return TriageVerdict.REPLACE_RECOMMENDED, checks

    if alarm_bad or mount_cmd_err:
        switch.triage_verdict = TriageVerdict.NEEDS_REMEDIATION.value
        reasons: list[str] = []
        if mount_cmd_err:
            reasons.append("Unable to inspect flash mount state (shell mount error)")
        if alarm_bad:
            reasons.append(
                "Minor /var partition usage alarm (auto-cleanup recommended)"
                if only_var_usage_alarm
                else "Active system/chassis alarm"
            )
        switch.triage_reasons = reasons
        return TriageVerdict.NEEDS_REMEDIATION, checks

    switch.triage_verdict = TriageVerdict.ELIGIBLE.value
    switch.triage_reasons = []
    return TriageVerdict.ELIGIBLE, checks


def run_prechecks(
    transport: SwitchTransport,
    switch: SwitchRecord,
    policy: PlatformPolicy,
    hop: HopSpec,
    evidence_dir: Path,
    config_root: Path,
    local_pkg_file: Path | None = None,
    require_release_notes: bool = True,
    execute_cleanup: bool = False,
    ignore_old_cores: bool = False,
    allow_no_console: bool = False,
    allow_unverified_checksums: bool = False,
) -> list[CheckResult]:
    """Execute release-note, identity, VC, package-match, and hardware/FS triage gates."""
    checks: list[CheckResult] = []

    # 1. Release notes gate
    rn_ok = (not require_release_notes) or hop.release_notes_reviewed
    checks.append(
        CheckResult(
            name="release_notes_reviewed",
            passed=rn_ok,
            message=(
                f"Release notes gate passed for {hop.target_version}."
                if rn_ok
                else f"Hop {hop.target_version} has release_notes_reviewed=false in approved-releases.yml."
            ),
        )
    )

    # 2. Live identity + architecture (exact model/version comparison, never substring)
    ver_json = transport.run_command("show version | display json")
    ver_txt = transport.run_command("show version")
    hw_out = transport.run_command("show chassis hardware")
    switch.kernel_arch = extract_switch_arch(
        ver_json if ver_json.strip().startswith("{") else ver_txt
    )

    live_ver, live_model = _extract_version_and_model(ver_json, ver_txt)
    model_ok = bool(live_model) and live_model.lower() == switch.model.strip().lower()
    serial_ok = not switch.serial_number or bool(
        re.search(rf"\b{re.escape(switch.serial_number.strip())}\b", hw_out)
    )
    version_ok = bool(live_ver) and live_ver.lower() == switch.current_version.strip().lower()

    if model_ok and serial_ok and live_ver and not version_ok:
        old_ver = switch.current_version
        switch.current_version = live_ver
        checks.append(
            CheckResult(
                name="identity_and_version",
                passed=True,
                hard_stop=False,
                severity="warn",
                message=(
                    f"Live version {live_ver} differs from manifest {old_ver}; "
                    f"refreshed current_version to {live_ver} (arch={switch.kernel_arch})."
                ),
            )
        )
    else:
        checks.append(
            CheckResult(
                name="identity_and_version",
                passed=model_ok and serial_ok and version_ok,
                message=(
                    f"Identity verified ({switch.model}, {switch.serial_number}, {switch.current_version}, arch={switch.kernel_arch})."
                    if (model_ok and serial_ok and version_ok)
                    else (
                        f"Identity mismatch: model_ok={model_ok} (live={live_model!r}), "
                        f"serial_ok={serial_ok}, version_ok={version_ok} (live={live_ver!r})"
                    )
                ),
            )
        )

    # 3. Virtual Chassis gate (1-member FPC 0 on standalone EX2300/EX3400 is normal; >1 is a VC)
    vc_out = transport.run_command("show virtual-chassis status")
    vc_members = sum(1 for ln in vc_out.splitlines() if _VC_MEMBER_RE.search(ln))
    vc_active = "Virtual Chassis ID:" in vc_out and vc_members > 1
    checks.append(
        CheckResult(
            name="no_virtual_chassis",
            passed=not vc_active,
            message=(
                "No Virtual Chassis detected; switch is operationally independent."
                if not vc_active
                else "Virtual Chassis detected! Hard-stop: requires VC-specific procedure."
            ),
        )
    )

    # 4. Clean commit state (detect pending commit-confirmed rollback / uncommitted errors, ignoring commit comments)
    commit_out = transport.run_command("show system commit")
    non_comment_commit = "\n".join(
        ln for ln in commit_out.splitlines() if not ln.lstrip().lower().startswith("comment:")
    )
    commit_ok = not bool(_COMMIT_ERR_RE.search(non_comment_commit))
    checks.append(
        CheckResult(
            name="clean_commit_state",
            passed=commit_ok,
            message=(
                "Configuration commit state is clean."
                if commit_ok
                else f"Commit state check failed: {commit_out.strip()}"
            ),
        )
    )

    # 5. Console access gate (Core requires console_port unless allow_no_console; transit warns)
    if switch.role.lower() == "core" and not switch.console_port:
        checks.append(
            CheckResult(
                name="console_access",
                passed=False,
                hard_stop=not allow_no_console,
                severity="warn" if allow_no_console else "fail",
                message=(
                    f"Core switch {switch.hostname} has no console_port assigned in manifest "
                    "(pass --allow-no-console only if on-site console is staged)."
                ),
            )
        )
    elif switch.downstream_switches and not switch.console_port:
        checks.append(
            CheckResult(
                name="console_access",
                passed=False,
                hard_stop=False,
                severity="warn",
                message=(
                    f"Transit switch {switch.hostname} feeds {len(switch.downstream_switches)} "
                    "downstream switch(es) and has no console_port recorded."
                ),
            )
        )
    else:
        checks.append(
            CheckResult(
                name="console_access",
                passed=True,
                hard_stop=False,
                severity="info",
                message=(
                    f"Console port recorded: {switch.console_port}."
                    if switch.console_port
                    else "Access leaf switch; console optional."
                ),
            )
        )

    # 6. Cross-train configuration landmine scan
    cfg_set = transport.run_command("show configuration | display set | no-more")
    checks.extend(check_config_landmines(cfg_set, evidence_dir=evidence_dir))

    # 7. Package-to-switch compatibility
    chassis_fw = (
        transport.run_command("show chassis firmware") if "-mp" in switch.model.lower() else ""
    )
    checks.extend(
        validate_package_match(
            switch,
            policy,
            hop,
            local_file=local_pkg_file,
            chassis_firmware_out=chassis_fw,
            allow_unverified_checksums=allow_unverified_checksums,
        )
    )

    # 8. Hardware & filesystem triage
    _, triage_checks = evaluate_hardware_and_fs_triage(
        transport,
        switch,
        policy,
        evidence_dir=evidence_dir,
        config_root=config_root,
        execute_cleanup=execute_cleanup,
        ignore_old_cores=ignore_old_cores,
        expected_hop_filename=hop.package_filename,
    )
    checks.extend(triage_checks)
    return checks


def _extract_up_interfaces(terse_output: str) -> set[str]:
    up: set[str] = set()
    for line in terse_output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1].lower() == "up" and parts[2].lower() == "up":
            up.add(parts[0])
    return up


def _extract_lldp_pairs(lldp_output: str) -> set[tuple[str, str]]:
    """Extract (local_interface, remote_identity) pairs from ELS 5-col or legacy 3-col LLDP output."""
    pairs: set[tuple[str, str]] = set()
    iface_prefixes = ("ge-", "xe-", "et-", "mge-", "me0", "vme")
    for line in lldp_output.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[0].startswith(iface_prefixes):
            continue
        local_if = parts[0]
        # Real ELS Junos: Local Interface | Parent Interface | Chassis Id | Port info | System Name
        if len(parts) >= 5 and (
            parts[1] == "-"
            or parts[1].startswith(("ae", "ge-", "xe-", "et-", "mge-"))
            or _MAC_RE.fullmatch(parts[2])
        ):
            chassis_id = parts[2]
            sys_name = parts[-1]
            remote_id = f"{chassis_id}/{sys_name}" if sys_name != chassis_id else chassis_id
            pairs.add((local_if, remote_id))
        elif len(parts) == 4 and (parts[1] == "-" or parts[1].startswith("ae")):
            pairs.add((local_if, parts[2]))
        else:
            pairs.add((local_if, parts[1]))
    return pairs


def _extract_poe_watts(poe_output: str) -> float | None:
    """Extract total PoE power consumption in Watts from `show poe controller`."""
    if not poe_output or "not valid" in poe_output.lower() or "error:" in poe_output.lower():
        return None
    total = 0.0
    matched = False
    for line in poe_output.splitlines():
        m = _POE_ROW_RE.match(line)
        if m:
            total += float(m.group(2))
            matched = True
    return total if matched else None


def _extract_mac_count(eth_table_output: str) -> int:
    """Count dynamically learned MAC entries in `show ethernet-switching table`."""
    count = 0
    for ln in eth_table_output.splitlines():
        if not _MAC_RE.search(ln):
            continue
        parts = ln.split()
        mac_idx = next((i for i, tok in enumerate(parts) if _MAC_RE.fullmatch(tok)), -1)
        if mac_idx >= 0 and mac_idx + 1 < len(parts):
            flag = parts[mac_idx + 1].upper()
            # Skip static/local/CPU entries (S, L, SL, R) so only learned forwarding MACs count
            if flag in ("S", "L", "SL", "R", "STATIC", "LOCAL"):
                continue
        if parts and parts[-1].lower().startswith(("irb", "vme", "router", "cpu")):
            continue
        count += 1
    return count


def _extract_lacp_up_members(lacp_output: str) -> set[str]:
    """Return member interfaces in Collecting/Distributing (`CD`) state from `show lacp interfaces`."""
    active: set[str] = set()
    for line in lacp_output.splitlines():
        parts = line.split()
        lower = line.lower()
        if (
            len(parts) >= 2
            and parts[0].startswith(("ge-", "xe-", "et-", "mge-"))
            and "collecting distributing" in lower
            and not any(bad in lower for bad in ("defaulted", "expired", "detached"))
        ):
            active.add(parts[0])
    return active


def run_postchecks(
    pre_baseline: dict[str, str],
    post_baseline: dict[str, str],
    expected_version: str,
    diff_output_path: Path | None = None,
) -> list[CheckResult]:
    """Compare post-upgrade state against expected version and pre-hop baseline."""
    checks: list[CheckResult] = []

    ver_json = post_baseline.get("show version | display json", "")
    ver_out = post_baseline.get("show version", "")
    live_ver, _ = _extract_version_and_model(ver_json, ver_out)
    ver_ok = bool(live_ver) and live_ver.lower() == expected_version.strip().lower()
    checks.append(
        CheckResult(
            name="target_version_active",
            passed=ver_ok,
            message=(
                f"Running target version {expected_version}."
                if ver_ok
                else f"Expected version {expected_version} not active (detected {live_ver or 'unknown'} in `show version`)."
            ),
        )
    )

    sys_alarms = post_baseline.get("show system alarms", "")
    chas_alarms = post_baseline.get("show chassis alarms", "")
    chas_clean = "No alarms currently active" in chas_alarms
    sys_clean = "No alarms currently active" in sys_alarms
    only_var_alarm = (
        chas_clean
        and not sys_clean
        and "1 alarms currently active" in sys_alarms
        and "/var partition usage is high" in sys_alarms
    )
    alarms_ok = sys_clean and chas_clean
    checks.append(
        CheckResult(
            name="post_no_active_alarms",
            passed=alarms_ok,
            hard_stop=not (alarms_ok or only_var_alarm),
            severity="info" if alarms_ok else ("warn" if only_var_alarm else "fail"),
            message=(
                "No post-upgrade system or chassis alarms."
                if alarms_ok
                else (
                    f"Minor post-upgrade /var storage alarm: {sys_alarms.strip()}"
                    if only_var_alarm
                    else f"Post-upgrade alarms detected! sys={sys_alarms.strip()!r}, chas={chas_alarms.strip()!r}"
                )
            ),
        )
    )

    pre_terse = pre_baseline.get("show interfaces terse", "")
    post_terse = post_baseline.get("show interfaces terse", "")
    pre_up = _extract_up_interfaces(pre_terse)
    post_up = _extract_up_interfaces(post_terse)
    terse_errored = (
        bool(_CLI_ERROR_RE.search(pre_terse))
        or bool(_CLI_ERROR_RE.search(post_terse))
        or (not pre_up and not post_up)
    )
    missing_up = sorted(pre_up - post_up)
    checks.append(
        CheckResult(
            name="interfaces_up_preserved",
            passed=(not terse_errored) and len(missing_up) == 0,
            message=(
                f"All {len(pre_up)} previously up interfaces are up."
                if (not terse_errored and not missing_up)
                else (
                    "Unable to verify interface status (`show interfaces terse` empty or errored)."
                    if terse_errored
                    else f"Interfaces failed to return up: {', '.join(missing_up)}"
                )
            ),
        )
    )

    pre_lldp_raw = pre_baseline.get("show lldp neighbors", "")
    post_lldp_raw = post_baseline.get("show lldp neighbors", "")
    lldp_errored = bool(_CLI_ERROR_RE.search(pre_lldp_raw)) or bool(
        _CLI_ERROR_RE.search(post_lldp_raw)
    )
    pre_lldp = _extract_lldp_pairs(pre_lldp_raw)
    post_lldp = _extract_lldp_pairs(post_lldp_raw)
    missing_lldp = sorted(pre_lldp - post_lldp)
    checks.append(
        CheckResult(
            name="lldp_neighbors_preserved",
            passed=(not lldp_errored) and len(missing_lldp) == 0,
            message=(
                f"All {len(pre_lldp)} LLDP neighbor links preserved."
                if (not lldp_errored and not missing_lldp)
                else (
                    "Unable to verify LLDP neighbors (`show lldp neighbors` returned an error)."
                    if lldp_errored
                    else f"Missing LLDP neighbors after reboot: {missing_lldp}"
                )
            ),
        )
    )

    pre_stp = _ROOT_ID_RE.findall(pre_baseline.get("show spanning-tree bridge", ""))
    post_stp = _ROOT_ID_RE.findall(post_baseline.get("show spanning-tree bridge", ""))
    stp_ok = pre_stp == post_stp
    checks.append(
        CheckResult(
            name="rstp_root_preserved",
            passed=stp_ok,
            message=(
                "RSTP root bridge ID matches pre-upgrade baseline."
                if stp_ok
                else f"RSTP root bridge ID changed after upgrade (pre={pre_stp}, post={post_stp})!"
            ),
        )
    )

    # PoE power delivery check
    pre_poe = _extract_poe_watts(pre_baseline.get("show poe controller", ""))
    post_poe = _extract_poe_watts(post_baseline.get("show poe controller", ""))
    if pre_poe is not None and pre_poe >= 5.0:
        if post_poe is None or post_poe < 1.0:
            checks.append(
                CheckResult(
                    name="poe_delivery_preserved",
                    passed=False,
                    hard_stop=True,
                    severity="fail",
                    message=f"PoE power delivery dropped from {pre_poe:.1f}W to {post_poe or 0.0:.1f}W!",
                )
            )
        elif post_poe < pre_poe * 0.5:
            checks.append(
                CheckResult(
                    name="poe_delivery_preserved",
                    passed=False,
                    hard_stop=False,
                    severity="warn",
                    message=f"PoE consumption dropped >50% ({pre_poe:.1f}W -> {post_poe:.1f}W); verify APs/phones.",
                )
            )
        else:
            checks.append(
                CheckResult(
                    name="poe_delivery_preserved",
                    passed=True,
                    message=f"PoE delivery verified ({pre_poe:.1f}W -> {post_poe:.1f}W).",
                )
            )

    # MAC table repopulation check
    pre_macs = _extract_mac_count(pre_baseline.get("show ethernet-switching table", ""))
    post_macs = _extract_mac_count(post_baseline.get("show ethernet-switching table", ""))
    if pre_macs >= 2:
        mac_ok = post_macs > 0
        checks.append(
            CheckResult(
                name="mac_table_repopulated",
                passed=mac_ok,
                hard_stop=True,
                severity="info" if mac_ok else "fail",
                message=(
                    f"MAC table repopulated ({post_macs} learned vs {pre_macs} pre-hop)."
                    if mac_ok
                    else f"MAC table is empty after settle (0 learned vs {pre_macs} pre-hop)!"
                ),
            )
        )

    # LACP bundle preservation check
    pre_lacp = _extract_lacp_up_members(pre_baseline.get("show lacp interfaces", ""))
    if pre_lacp:
        post_lacp = _extract_lacp_up_members(post_baseline.get("show lacp interfaces", ""))
        missing_lacp = sorted(pre_lacp - post_lacp)
        checks.append(
            CheckResult(
                name="lacp_bundles_preserved",
                passed=len(missing_lacp) == 0,
                hard_stop=True,
                severity="info" if not missing_lacp else "fail",
                message=(
                    f"All {len(pre_lacp)} LACP member(s) Collecting/Distributing."
                    if not missing_lacp
                    else f"LACP member(s) failed to bundle post-upgrade: {', '.join(missing_lacp)}"
                ),
            )
        )

    if diff_output_path is not None:
        pre_cfg = pre_baseline.get("show configuration | display set | no-more", "").splitlines()
        post_cfg = post_baseline.get("show configuration | display set | no-more", "").splitlines()
        diff_lines = list(
            difflib.unified_diff(
                pre_cfg, post_cfg, fromfile="pre.set", tofile="post.set", lineterm=""
            )
        )
        diff_output_path.parent.mkdir(parents=True, exist_ok=True)
        diff_output_path.write_text("\n".join(diff_lines) + "\n", encoding="utf-8")

    return checks
