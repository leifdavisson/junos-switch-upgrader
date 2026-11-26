# SPDX-License-Identifier: AGPL-3.0-or-later
"""Site-generic inventory discovery (live SSH, CIDR/IP list, CSV, or crawler import)."""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import os
import re
import socket
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from junos_upgrader.checks import parse_junos_storage
from junos_upgrader.junos_client import CredentialSet, NetmikoJunosTransport
from junos_upgrader.models import (
    NeighborExpectation,
    SwitchRecord,
    SwitchState,
    sanitize_path_segment,
    validate_safe_path_segment,
)
from junos_upgrader.packages import extract_switch_arch
from junos_upgrader.planner import load_release_catalog, refresh_switch_plan
from junos_upgrader.topology import build_topology_graph

logger = logging.getLogger(__name__)

MAX_CIDR_HOSTS = 4096
SUPPORTED_MANIFEST_SCHEMA_VERSIONS = (1, 2)

_SITE_PREFIX_RE = re.compile(r"^([A-Z]{2,4})[_-]")
_CSV_HEADER_TOKENS = {
    "ip",
    "ip address",
    "ip_address",
    "host",
    "hostname",
    "target",
    "targets",
    "address",
}
_REQUIRED_CRAWLER_COLUMNS = (
    "Hostname",
    "IP Address",
    "Model",
    "Serial Number",
    "Firmware",
)
_TEXT_HOST_RE = re.compile(r"^\s*Hostname:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_TEXT_MODEL_RE = re.compile(r"^\s*Model:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_TEXT_VER_RE = re.compile(
    r"(?:^\s*Junos:\s*|\[)(\d+\.\d+[RX]\d+(?:[-.][SDJ]\d+(?:\.\d+)?|\.\d+)?)",
    re.IGNORECASE | re.MULTILINE,
)


def infer_site_code(hostname: str, fallback: str = "SITE") -> str:
    """Derive site code from hostname prefix or return fallback."""
    match = _SITE_PREFIX_RE.match(hostname.strip().upper())
    return match.group(1) if match else fallback


def _is_ip_or_cidr(token: str) -> bool:
    try:
        if "/" in token:
            ipaddress.ip_network(token, strict=False)
        else:
            ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def expand_targets(
    target_specs: tuple[str, ...],
    targets_file: Path | None = None,
    *,
    max_hosts: int = MAX_CIDR_HOSTS,
) -> list[str]:
    """Expand IP addresses, hostnames, CIDRs, or file lines into deduplicated target hosts."""
    if max_hosts < 1:
        raise ValueError(f"max_hosts must be >= 1, got {max_hosts}")

    raw_items: list[str] = []
    for spec in target_specs:
        for part in spec.split(","):
            tok = part.strip()
            if tok:
                raw_items.append(tok)

    if targets_file and targets_file.exists():
        for line in targets_file.read_text(encoding="utf-8-sig").splitlines():
            clean = line.split("#", 1)[0].strip()
            if not clean:
                continue
            if "," in clean:
                parts = [p.strip() for p in clean.split(",") if p.strip()]
                if not parts:
                    continue
                if parts[0].lower() in _CSV_HEADER_TOKENS:
                    continue
                if all(_is_ip_or_cidr(p) for p in parts):
                    raw_items.extend(parts)
                else:
                    raw_items.append(parts[0])
            else:
                if clean.lower() in _CSV_HEADER_TOKENS:
                    continue
                raw_items.append(clean)

    hosts: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        token = item.strip()
        if not token:
            continue
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR target: {token!r}") from exc

            if net.num_addresses <= 2:
                host_count = net.num_addresses
            else:
                host_count = net.num_addresses - 2
            if host_count > max_hosts:
                raise ValueError(
                    f"CIDR target {token!r} expands to {host_count} hosts "
                    f"(exceeds max_hosts={max_hosts}). Split into smaller subnets."
                )
            for ip in net.hosts():
                s = str(ip)
                if s not in seen:
                    seen.add(s)
                    hosts.append(s)
            continue
        if token not in seen:
            seen.add(token)
            hosts.append(token)
    return hosts


def _tcp_ssh_open(host: str, port: int = 22, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _first_json_data(node: Any, *keys: str) -> str:
    cur = node
    for key in keys:
        if isinstance(cur, list):
            cur = cur[0] if cur else {}
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(key, {})
    if isinstance(cur, list):
        cur = cur[0] if cur else {}
    if isinstance(cur, dict):
        val = cur.get("data", "")
        return "" if val is None else str(val).strip()
    return "" if cur is None else str(cur).strip()


def _as_list(val: Any) -> list[Any]:
    if isinstance(val, list):
        return val
    if isinstance(val, dict):
        return [val]
    return []


def _unwrap_multi_re(data: Any, section: str) -> dict[str, Any]:
    """Unwrap Junos `multi-routing-engine-results` JSON wrapper safely if present."""
    if not isinstance(data, dict):
        return {}
    if "multi-routing-engine-results" in data:
        for mre in _as_list(data.get("multi-routing-engine-results")):
            if not isinstance(mre, dict):
                continue
            for item in _as_list(mre.get("multi-routing-engine-item")):
                if not isinstance(item, dict) or section not in item:
                    continue
                for sec in _as_list(item.get(section)):
                    if isinstance(sec, dict):
                        return sec
        return {}
    for sec in _as_list(data.get(section)):
        if isinstance(sec, dict):
            return sec
    return {}


def _parse_lldp_json(lldp_raw: str, stp_raw: str) -> list[NeighborExpectation]:
    root_ports: set[str] = set()
    if stp_raw.strip().startswith("{"):
        try:
            stp_data = json.loads(stp_raw)
            stp_info = _unwrap_multi_re(stp_data, "stp-interface-information")
            instances = _as_list(stp_info.get("stp-instance"))
            for inst in instances:
                if not isinstance(inst, dict):
                    continue
                for iface_blk in _as_list(inst.get("stp-interfaces")):
                    if not isinstance(iface_blk, dict):
                        continue
                    for ent in _as_list(iface_blk.get("stp-interface-entry")):
                        if not isinstance(ent, dict):
                            continue
                        role = _first_json_data(ent, "port-role").upper()
                        if "ROOT" in role:
                            iface = _first_json_data(ent, "interface-name").split(".")[0]
                            if iface:
                                root_ports.add(iface)
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            pass

    neighbors: list[NeighborExpectation] = []
    if lldp_raw.strip().startswith("{"):
        try:
            data = json.loads(lldp_raw)
            lldp_info = _unwrap_multi_re(data, "lldp-neighbors-information")
            entries = _as_list(lldp_info.get("lldp-neighbor-information"))
            for ent in entries:
                if not isinstance(ent, dict):
                    continue
                local_port = _first_json_data(ent, "lldp-local-port-id").split(".")[0]
                remote_dev = _first_json_data(ent, "lldp-remote-system-name")
                remote_port = _first_json_data(ent, "lldp-remote-port-id") or _first_json_data(
                    ent, "lldp-remote-port-description"
                )
                remote_mac = _first_json_data(ent, "lldp-remote-chassis-id")
                if local_port and (remote_dev or remote_mac):
                    neighbors.append(
                        NeighborExpectation(
                            local_port=local_port,
                            remote_device=remote_dev or remote_mac,
                            remote_port=remote_port,
                            remote_mac=remote_mac,
                            is_upstream=(local_port in root_ports),
                        )
                    )
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            pass
    return neighbors


def _parse_version_text(ver_text: str) -> tuple[str, str, str]:
    """Extract (hostname, model, version) from plain-text `show version` output."""
    host_m = _TEXT_HOST_RE.search(ver_text)
    model_m = _TEXT_MODEL_RE.search(ver_text)
    ver_m = _TEXT_VER_RE.search(ver_text)
    return (
        host_m.group(1).strip() if host_m else "",
        model_m.group(1).strip() if model_m else "",
        ver_m.group(1).strip() if ver_m else "",
    )


def _probe_single_switch(
    host: str,
    credentials: list[CredentialSet],
    site_name: str,
    *,
    port: int = 22,
) -> SwitchRecord | None:
    from netmiko import NetmikoBaseException
    from paramiko import SSHException

    transport = NetmikoJunosTransport(host=host, credentials=credentials, port=port)
    try:
        transport.connect()
    except (OSError, RuntimeError, NetmikoBaseException, SSHException, EOFError) as exc:
        logger.debug("Discovery connect failed for %s:%d: %s", host, port, exc)
        return None

    ver_txt = ""
    try:
        ver_json = transport.run_command("show version | display json")
        if not ver_json.strip().startswith("{"):
            ver_txt = transport.run_command("show version")
        hw_json = transport.run_command("show chassis hardware | display json")
        stor_json = transport.run_command("show system storage | display json")
        lldp_json = transport.run_command("show lldp neighbors | display json")
        stp_json = transport.run_command("show spanning-tree interface | display json")
    except (OSError, RuntimeError, ValueError, NetmikoBaseException, SSHException, EOFError) as exc:
        logger.warning("Discovery command failed on %s: %s", host, exc)
        return None
    finally:
        transport.disconnect()

    raw_hostname = host
    model = "unknown"
    version = "unknown"
    if ver_json.strip().startswith("{"):
        try:
            vdata = json.loads(ver_json)
            sw_info = _unwrap_multi_re(vdata, "software-information")
            raw_hostname = _first_json_data(sw_info, "host-name") or host
            model = _first_json_data(sw_info, "product-model") or "unknown"
            version = _first_json_data(sw_info, "junos-version") or "unknown"
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            pass

    if ver_txt or model == "unknown" or version == "unknown":
        txt_source = ver_txt or ver_json
        t_host, t_model, t_ver = _parse_version_text(txt_source)
        if raw_hostname == host and t_host:
            raw_hostname = t_host
        if model == "unknown" and t_model:
            model = t_model
        if version == "unknown" and t_ver:
            version = t_ver

    serial = ""
    if hw_json.strip().startswith("{"):
        try:
            hdata = json.loads(hw_json)
            chas_inv = _unwrap_multi_re(hdata, "chassis-inventory")
            chas_list = _as_list(chas_inv.get("chassis"))
            chas = chas_list[0] if chas_list and isinstance(chas_list[0], dict) else {}
            serial = _first_json_data(chas, "serial-number")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            pass

    hostname = sanitize_path_segment(raw_hostname, fallback=sanitize_path_segment(host, "switch"))
    resolved_site = sanitize_path_segment(
        site_name or infer_site_code(hostname),
        fallback="SITE",
    )

    free_mb, stor_mounts = parse_junos_storage(stor_json)
    tmpfs_mb = stor_mounts.get("/.mount/tmp")
    if tmpfs_mb is None:
        tmpfs_mb = stor_mounts.get("/tmp")
    arch_source = ver_json if ver_json.strip().startswith("{") else (ver_txt or ver_json)
    arch = extract_switch_arch(arch_source)
    neighbors = _parse_lldp_json(lldp_json, stp_json)
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    return SwitchRecord(
        site=resolved_site,
        hostname=hostname,
        management_ip=host,
        model=model,
        serial_number=serial,
        current_version=version,
        role=(
            "Core"
            if ("4600" in model.lower() or "4650" in model.lower() or "qfx" in model.lower())
            else "Access"
        ),
        management_method="SSH",
        kernel_arch=arch,
        free_storage_mb=free_mb,
        tmpfs_free_mb=tmpfs_mb,
        state=SwitchState.READY,
        last_updated=now_iso,
        expected_neighbors=neighbors,
    )


def discover_live_targets(
    targets: list[str],
    credentials: list[CredentialSet],
    approved_releases_path: Path,
    output_manifest_path: Path,
    site_name: str = "",
    max_workers: int = 16,
    *,
    ssh_port: int = 22,
    tcp_timeout: float = 3.0,
) -> list[SwitchRecord]:
    """Probe target IPs/CIDRs over SSH, build topology graph, and persist manifest."""
    _, policies, exclusions = load_release_catalog(approved_releases_path)

    reachable: list[str] = []
    if targets:
        with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(targets)))) as pool:
            futs = {pool.submit(_tcp_ssh_open, h, ssh_port, tcp_timeout): h for h in targets}
            for fut in as_completed(futs):
                try:
                    if fut.result():
                        reachable.append(futs[fut])
                except Exception as exc:  # noqa: BLE001
                    logger.debug("TCP probe error for %s: %s", futs[fut], exc)

    records: list[SwitchRecord] = []
    if reachable:
        with ThreadPoolExecutor(max_workers=min(8, len(reachable))) as pool:
            futs = {
                pool.submit(_probe_single_switch, h, credentials, site_name, port=ssh_port): h
                for h in sorted(reachable)
            }
            for fut in as_completed(futs):
                host = futs[fut]
                try:
                    rec = fut.result()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Discovery worker failed for %s: %s", host, exc)
                    continue
                if rec is not None:
                    try:
                        refresh_switch_plan(rec, policies, exclusions)
                    except ValueError as exc:
                        rec.state = SwitchState.NOT_READY
                        rec.last_error = (
                            f"Unparseable running version {rec.current_version!r}: {exc}"
                        )
                    records.append(rec)

    # Disambiguate duplicate hostnames so topology maps never silently collide
    seen_names: set[str] = set()
    for rec in sorted(records, key=lambda r: (r.site, r.hostname, r.management_ip)):
        if rec.hostname in seen_names:
            rec.hostname = sanitize_path_segment(
                f"{rec.hostname}_{rec.management_ip}",
                fallback=f"{rec.hostname}_dup",
            )
        seen_names.add(rec.hostname)

    records.sort(key=lambda r: (r.site, r.hostname))
    if records:
        build_topology_graph(records)
        save_inventory(records, output_manifest_path)
    elif not output_manifest_path.exists():
        save_inventory(records, output_manifest_path)
    return records


def _load_neighbors_map(neighbors_csv: Path) -> dict[str, list[NeighborExpectation]]:
    """Load switch-to-switch LLDP expectations from net-docu-crawler neighbors.csv."""
    if not neighbors_csv.exists():
        return {}
    by_host: dict[str, list[NeighborExpectation]] = {}
    with neighbors_csv.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            if (row.get("device_type") or "").strip().lower() != "switch":
                continue
            src = (row.get("source_device") or "").strip()
            if not src:
                continue
            by_host.setdefault(src, []).append(
                NeighborExpectation(
                    local_port=(row.get("local_port") or "").strip(),
                    remote_device=(row.get("remote_device") or "").strip(),
                    remote_port=(row.get("remote_port") or "").strip(),
                    remote_ip=(row.get("remote_ip") or "").strip(),
                    remote_mac=(row.get("remote_mac") or "").strip(),
                )
            )
    return by_host


def import_from_crawler(
    deliverable_dir: Path,
    approved_releases_path: Path,
    output_manifest_path: Path,
    *,
    origin: Any | None = None,
) -> list[SwitchRecord]:
    """Import asset_inventory.csv and neighbors.csv into a topology-aware manifest."""
    asset_csv = deliverable_dir / "asset_inventory.csv"
    if not asset_csv.exists():
        raise FileNotFoundError(f"Missing asset_inventory.csv in {deliverable_dir}")

    neighbors_map = _load_neighbors_map(deliverable_dir / "02_normalized" / "neighbors.csv")
    _, policies, exclusions = load_release_catalog(approved_releases_path)
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    records: list[SwitchRecord] = []
    seen_hostnames: set[str] = set()
    with asset_csv.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = set(reader.fieldnames or [])
        missing_cols = [col for col in _REQUIRED_CRAWLER_COLUMNS if col not in fieldnames]
        if missing_cols:
            raise ValueError(
                f"asset_inventory.csv missing required column(s): {', '.join(missing_cols)}"
            )

        for row_num, row in enumerate(reader, start=2):
            raw_host = (row.get("Hostname") or "").strip()
            raw_ip = (row.get("IP Address") or "").strip()
            if not raw_host and not raw_ip:
                continue

            device_type = (row.get("Device Type") or "").strip().lower()
            if device_type and device_type not in (
                "switch",
                "network switch",
                "l2 switch",
                "l3 switch",
            ):
                continue

            if not raw_host or not raw_ip:
                raise ValueError(
                    f"asset_inventory.csv row {row_num} missing required Hostname or IP Address"
                )
            hostname = validate_safe_path_segment(raw_host, f"Hostname (row {row_num})")
            if hostname in seen_hostnames:
                raise ValueError(
                    f"Duplicate hostname {hostname!r} in asset_inventory.csv (row {row_num})"
                )
            seen_hostnames.add(hostname)

            role = (row.get("Role") or "").strip() or "Access"
            mgmt_method = (row.get("Management Method") or "").strip() or "SSH"

            record = SwitchRecord(
                site=infer_site_code(hostname),
                hostname=hostname,
                management_ip=raw_ip,
                model=(row.get("Model") or "").strip(),
                serial_number=(row.get("Serial Number") or "").strip(),
                current_version=(row.get("Firmware") or "").strip(),
                role=role,
                management_method=mgmt_method,
                mac_address=(row.get("MAC Address") or "").strip(),
                state=SwitchState.READY,
                last_updated=now_iso,
                expected_neighbors=neighbors_map.get(hostname, []),
            )
            try:
                refresh_switch_plan(record, policies, exclusions)
            except ValueError as exc:
                record.state = SwitchState.NOT_READY
                record.last_error = f"Unparseable firmware {record.current_version!r}: {exc}"
            records.append(record)

    if records:
        build_topology_graph(records, origin=origin)
    save_inventory(records, output_manifest_path)
    return records


def save_inventory(records: list[SwitchRecord], manifest_path: Path) -> None:
    """Atomically persist switch manifest records to JSON via temp file + fsync + replace."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "schema_version": 2,
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "switches": [r.to_dict() for r in records],
    }
    encoded = json.dumps(payload, indent=2) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{manifest_path.name}.",
        suffix=".tmp",
        dir=str(manifest_path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, manifest_path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def load_inventory(manifest_path: Path) -> list[SwitchRecord]:
    """Load and validate switch manifest records from JSON."""
    data: Any = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Manifest {manifest_path} root must be a JSON object")

    schema_ver = data.get("schema_version")
    if schema_ver is not None and (
        isinstance(schema_ver, bool)
        or not isinstance(schema_ver, int)
        or schema_ver not in SUPPORTED_MANIFEST_SCHEMA_VERSIONS
    ):
        raise ValueError(
            f"Unsupported manifest schema_version {schema_ver!r} in {manifest_path} "
            f"(supported: {SUPPORTED_MANIFEST_SCHEMA_VERSIONS})"
        )

    switches_raw = data.get("switches", [])
    if not isinstance(switches_raw, list):
        raise ValueError(f"Manifest {manifest_path} field 'switches' must be a JSON list")

    records: list[SwitchRecord] = []
    for idx, item in enumerate(switches_raw):
        try:
            records.append(SwitchRecord.from_dict(item))
        except ValueError as exc:
            raise ValueError(
                f"Invalid switch entry at switches[{idx}] in {manifest_path}: {exc}"
            ) from exc
    return records


def scaffold_firmware_repo(repo_root: Path, releases_path: Path | None = None) -> list[Path]:
    """Create the aligned firmware/ and deliverables/ directory tree."""
    dirs = [
        "manifests",
        "firmware/juniper/ex2300-mp/18.4",
        "firmware/juniper/ex2300-mp/19.3",
        "firmware/juniper/ex2300-mp/20.2",
        "firmware/juniper/ex2300-mp/21.2",
        "firmware/juniper/ex2300-mp/22.2",
        "firmware/juniper/ex2300-mp/23.2",
        "firmware/juniper/ex2300-mp/23.4R2-S8",
        "firmware/juniper/ex2300/18.4",
        "firmware/juniper/ex2300/19.3",
        "firmware/juniper/ex2300/20.2",
        "firmware/juniper/ex2300/21.2",
        "firmware/juniper/ex2300/22.2",
        "firmware/juniper/ex2300/23.2",
        "firmware/juniper/ex2300/23.4R2-S8",
        "firmware/juniper/ex3400/18.4",
        "firmware/juniper/ex3400/19.3",
        "firmware/juniper/ex3400/20.2",
        "firmware/juniper/ex3400/21.2",
        "firmware/juniper/ex3400/22.2",
        "firmware/juniper/ex3400/23.2",
        "firmware/juniper/ex3400/23.4R2-S8/runtime",
        "firmware/juniper/ex3400/23.4R2-S8/install-media-usb",
        "firmware/juniper/ex3400/23.4R2-S8/install-media-net",
        "firmware/juniper/ex3400/23.4R2-S8/release-notes",
        "firmware/juniper/ex4100-mp/23.4R2-S8",
        "firmware/juniper/ex4100/23.4R2-S8",
        "firmware/juniper/ex4300-48mp/21.4",
        "firmware/juniper/ex4300-48mp/22.4",
        "firmware/juniper/ex4300-48mp/23.4R2-S8",
        "firmware/juniper/ex4300/19.4",
        "firmware/juniper/ex4300/20.4",
        "firmware/juniper/ex4300/21.4R3-S12",
        "firmware/juniper/ex4400-mp/23.4R2-S8",
        "firmware/juniper/ex4400/23.4R2-S8",
        "firmware/juniper/ex4600/18.2",
        "firmware/juniper/ex4600/19.1",
        "firmware/juniper/ex4600/19.4",
        "firmware/juniper/ex4600/20.4",
        "firmware/juniper/ex4600/21.4R3-S12/runtime",
        "firmware/juniper/ex4600/21.4R3-S12/install-media-usb",
        "firmware/juniper/ex4600/21.4R3-S12/release-notes",
        "firmware/juniper/ex4650/21.4",
        "firmware/juniper/ex4650/22.4",
        "firmware/juniper/ex4650/23.4R2-S8",
        "firmware/juniper/qfx5120/21.4",
        "firmware/juniper/qfx5120/22.4",
        "firmware/juniper/qfx5120/23.4R2-S8",
        "firmware/juniper/qfx5200/21.4",
        "firmware/juniper/qfx5200/22.4",
        "firmware/juniper/qfx5200/23.4R2-S8",
        "deliverables/configs",
        "deliverables/evidence",
        "deliverables/recovery/usb-build-instructions",
        "deliverables/recovery/console-procedures",
    ]

    if releases_path is not None and releases_path.exists():
        _, policies, _ = load_release_catalog(releases_path)
        for pol in policies:
            for hop in pol.hops:
                rel = f"firmware/{pol.vendor}/{pol.family_dir}/{hop.train}"
                if rel not in dirs:
                    dirs.append(rel)

    created: list[Path] = []
    for rel in dirs:
        target = repo_root / rel
        target.mkdir(parents=True, exist_ok=True)
        created.append(target)
    return created
