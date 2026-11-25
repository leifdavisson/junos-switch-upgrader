# SPDX-License-Identifier: AGPL-3.0-or-later
"""Topology-ordered, leaf-first multi-hop upgrade orchestrator."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from junos_upgrader.checks import safe_subpath, sanitize_path_segment
from junos_upgrader.drivers import get_driver
from junos_upgrader.inventory import save_inventory
from junos_upgrader.junos_client import SwitchTransport
from junos_upgrader.models import PlatformPolicy, SwitchRecord, SwitchState
from junos_upgrader.planner import (
    compute_remaining_hops,
    match_platform_policy,
    refresh_switch_plan,
)
from junos_upgrader.topology import (
    TopologyGraph,
    build_topology_graph,
    compute_topology_waves,
    mark_ancestor_holds,
)
from junos_upgrader.transfer import (
    TransferOutcome,
    UnifiedFirmwareServer,
    _is_usable_external_url,
    resolve_local_firmware_file,
    resolve_transfer_mode,
)


@dataclass
class UpgradeOptions:
    """Execution parameters for a controlled topology-ordered upgrade wave."""

    firmware_base_url: str
    firmware_dir: Path
    evidence_root: Path
    config_root: Path
    manifest_path: Path
    change_number: str
    operator: str
    batch_size: int = 1
    max_hops: int | None = None
    include_cores: bool = False
    auto_cleanup: bool = True
    ignore_old_cores: bool = False
    transfer_mode: str = "auto"
    require_release_notes: bool = True
    reboot_poll_interval: float = 10.0
    reboot_wait_down_seconds: float = 90.0
    post_settle_seconds: float = 60.0
    reconnect_timeout_seconds: float = 60.0
    fast_intermediate_hops: bool = True
    stage_only: bool = False
    allow_no_console: bool = False
    refresh_snapshot: bool = False
    accept_bleeding_edge: bool = False
    allow_unverified_checksums: bool = False
    dry_run: bool = False
    state_lock: threading.Lock | None = None


TransportFactory = Callable[[SwitchRecord], SwitchTransport]


def _wait_for_reboot(
    transport: SwitchTransport,
    timeout_seconds: int,
    poll_interval: float,
    wait_down_seconds: float = 90.0,
) -> bool:
    """Confirm switch drops offline for reboot (if wait_down_seconds > 0), then await SSH return."""
    if wait_down_seconds > 0:
        saw_down = False
        down_deadline = time.monotonic() + wait_down_seconds
        while True:
            if not transport.is_reachable(timeout=2.0):
                saw_down = True
                break
            if time.monotonic() >= down_deadline:
                break
            if poll_interval > 0:
                time.sleep(poll_interval)
        if not saw_down:
            return False

    deadline = time.monotonic() + timeout_seconds
    while True:
        if transport.is_reachable(timeout=3.0):
            return True
        if time.monotonic() >= deadline:
            return False
        if poll_interval > 0:
            time.sleep(poll_interval)


def _reconnect_post_reboot(
    transport: SwitchTransport,
    poll_interval: float,
    reconnect_timeout_seconds: float,
) -> Exception | None:
    """Reconnect SSH after reboot with exponential backoff while sshd/mgd finishes initializing."""
    deadline = time.monotonic() + max(0.0, reconnect_timeout_seconds)
    backoff = min(max(poll_interval, 0.0), 5.0)
    attempt = 0
    last_err: Exception | None = None
    while True:
        attempt += 1
        try:
            transport.connect()
            return None
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            now = time.monotonic()
            if poll_interval <= 0 and attempt >= 3:
                return last_err
            if now >= deadline and attempt >= 3:
                return last_err
            if backoff > 0:
                remaining = deadline - now
                sleep_for = min(backoff, remaining) if remaining > 0 else 0.0
                if sleep_for > 0:
                    time.sleep(sleep_for)
                backoff = min(backoff * 1.5, 15.0)


def upgrade_single_switch(
    switch: SwitchRecord,
    policy: PlatformPolicy,
    exclusions: list[dict[str, str]],
    policies: list[PlatformPolicy],
    transport: SwitchTransport,
    opts: UpgradeOptions,
    server: UnifiedFirmwareServer | None = None,
    persist_fn: Callable[[], None] | None = None,
    state_lock: threading.Lock | None = None,
) -> SwitchRecord:
    """Upgrade (or pre-stage) a single switch hop-by-hop using its SwitchDriver."""
    driver = get_driver(policy.vendor)
    lock = state_lock or opts.state_lock

    def _locked():
        return lock if lock is not None else contextlib.nullcontext()

    # In dry-run mode, operate on an isolated copy so manifest state is never mutated/blocked.
    if opts.dry_run:
        with _locked():
            work_sw = SwitchRecord.from_dict(switch.to_dict())
    else:
        work_sw = switch

    with _locked():
        work_sw.change_number = opts.change_number
        work_sw.operator = opts.operator

    def _persist() -> None:
        with _locked():
            work_sw.last_updated = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not opts.dry_run and persist_fn is not None:
            persist_fn()

    pending_hops = list(compute_remaining_hops(work_sw.current_version, policy))
    if not pending_hops:
        with _locked():
            refresh_switch_plan(work_sw, policies, exclusions)
        _persist()
        return work_sw

    executed_hops = 0
    replanned_versions: set[str] = set()

    while pending_hops:
        if opts.max_hops is not None and executed_hops >= opts.max_hops:
            break
        hop = pending_hops.pop(0)

        if (
            (hop.bleeding_edge or policy.bleeding_edge)
            and not opts.accept_bleeding_edge
            and not opts.dry_run
        ):
            with _locked():
                work_sw.state = SwitchState.FAILED
                work_sw.last_error = (
                    f"BLEEDING-EDGE BUMPER: {hop.target_version} is beyond JTAC baseline "
                    f"({policy.jtac_baseline or 'non-JTAC'}). Pass --accept-bleeding-edge to proceed."
                )
            _persist()
            return work_sw

        hop_tag = f"hop_{executed_hops + 1}_{sanitize_path_segment(hop.target_version)}"
        ev_dir = safe_subpath(
            opts.evidence_root, work_sw.site, opts.change_number, work_sw.hostname, hop_tag
        )
        cfg_pre_dir = safe_subpath(opts.config_root, work_sw.site, work_sw.hostname, "pre", hop_tag)
        cfg_post_dir = safe_subpath(
            opts.config_root, work_sw.site, work_sw.hostname, "post", hop_tag
        )
        local_pkg = resolve_local_firmware_file(opts.firmware_dir, policy, hop)

        has_more_hops = bool(pending_hops) and (
            opts.max_hops is None or (executed_hops + 1) < opts.max_hops
        )
        use_fast_pre = opts.fast_intermediate_hops and executed_hops > 0
        use_fast_post = opts.fast_intermediate_hops and has_more_hops

        try:
            transport.connect()
        except Exception as exc:  # noqa: BLE001
            with _locked():
                work_sw.state = SwitchState.FAILED
                work_sw.last_error = f"SSH connection failed before hop {hop.target_version}: {exc}"
            _persist()
            return work_sw

        try:
            pre_ver = work_sw.current_version
            pre_checks = driver.precheck(
                transport=transport,
                switch=work_sw,
                policy=policy,
                hop=hop,
                evidence_dir=ev_dir / "pre",
                config_root=opts.config_root,
                local_pkg_file=local_pkg,
                require_release_notes=opts.require_release_notes,
                execute_cleanup=(opts.auto_cleanup and not opts.dry_run),
                ignore_old_cores=opts.ignore_old_cores,
                allow_no_console=opts.allow_no_console,
                allow_unverified_checksums=opts.allow_unverified_checksums,
            )
            failed_pre = [c for c in pre_checks if not c.passed and c.hard_stop]
            hop_specific_checks = frozenset(
                {
                    "release_notes_reviewed",
                    "package_family_match",
                    "local_tgz_present",
                    "local_tgz_integrity",
                    "platform_mgig_advisory",
                }
            )
            device_failed = [c for c in failed_pre if c.name not in hop_specific_checks]

            # If precheck discovered a different live version (newer OR older) and no
            # device/identity/triage hard-stops failed, re-plan BEFORE failing on stale hop checks!
            if (
                work_sw.current_version != pre_ver
                and not device_failed
                and work_sw.state != SwitchState.REPLACE_RECOMMENDED
            ):
                with _locked():
                    refresh_switch_plan(work_sw, policies, exclusions)
                remaining_now = compute_remaining_hops(work_sw.current_version, policy)
                if not remaining_now:
                    with _locked():
                        work_sw.last_error = ""
                    _persist()
                    return work_sw
                if remaining_now[0].target_version != hop.target_version:
                    if work_sw.current_version in replanned_versions:
                        with _locked():
                            work_sw.state = SwitchState.FAILED
                            work_sw.last_error = f"Version re-plan loop detected at live version {work_sw.current_version}."
                        _persist()
                        return work_sw
                    replanned_versions.add(work_sw.current_version)
                    pending_hops = list(remaining_now)
                    _persist()
                    continue

            if failed_pre:
                with _locked():
                    if work_sw.state != SwitchState.REPLACE_RECOMMENDED:
                        work_sw.state = SwitchState.FAILED
                    work_sw.last_error = "; ".join(c.message for c in failed_pre)
                _persist()
                return work_sw

            pre_baseline = driver.collect_baseline(
                transport, ev_dir / "pre", fast_delta=use_fast_pre
            )
            backup_path, _ = driver.backup_and_recovery(
                transport,
                work_sw,
                policy,
                cfg_pre_dir,
                pre_baseline,
                save_rescue=(not opts.dry_run),
            )
            with _locked():
                work_sw.backup_filename = str(backup_path)

            if opts.dry_run:
                with _locked():
                    work_sw.last_error = ""
                _persist()
                return work_sw

            # Two-phase business-hours staging mode
            if opts.stage_only:
                chosen_mode = resolve_transfer_mode(
                    transfer_mode=opts.transfer_mode,
                    policy=policy,
                    free_storage_mb=work_sw.free_storage_mb,
                    local_file=local_pkg,
                    external_base_url=opts.firmware_base_url,
                )
                if chosen_mode == "http-stream":
                    if local_pkg is None and not _is_usable_external_url(opts.firmware_base_url):
                        with _locked():
                            work_sw.state = SwitchState.FAILED
                            work_sw.last_error = (
                                f"Local package {hop.package_filename} missing from {opts.firmware_dir} "
                                "for HTTP stream staging."
                            )
                        _persist()
                        return work_sw
                    with _locked():
                        # Mark as stream-staged (not /var/tmp/) so Phase 2 cleanup is NOT skipped
                        work_sw.staged_package = f"http-stream:{hop.package_filename}"
                        work_sw.staged_checksum = hop.checksum
                        work_sw.state = SwitchState.STAGED
                        work_sw.last_error = ""
                    _persist()
                    return work_sw

                expected_remote = f"/var/tmp/{hop.package_filename}"  # nosec B108
                if work_sw.staged_package == expected_remote:
                    ok_existing, _ = driver.verify_staged_checksum(
                        transport,
                        expected_remote,
                        hop.checksum_type,
                        hop.checksum,
                        allow_unverified_checksums=opts.allow_unverified_checksums,
                    )
                    if ok_existing:
                        with _locked():
                            work_sw.state = SwitchState.STAGED
                            work_sw.last_error = ""
                        _persist()
                        return work_sw

                transfer = driver.stage_package(
                    transport=transport,
                    switch=work_sw,
                    policy=policy,
                    hop=hop,
                    firmware_dir=opts.firmware_dir,
                    server=server,
                    external_base_url=opts.firmware_base_url,
                    transfer_mode=opts.transfer_mode,
                )
                if transfer.remote_staged_path:
                    ok_chk, chk_msg = driver.verify_staged_checksum(
                        transport,
                        transfer.remote_staged_path,
                        hop.checksum_type,
                        hop.checksum,
                        allow_unverified_checksums=opts.allow_unverified_checksums,
                    )
                    if not ok_chk:
                        with _locked():
                            work_sw.state = SwitchState.FAILED
                            work_sw.last_error = chk_msg
                        _persist()
                        return work_sw
                    with _locked():
                        work_sw.staged_package = transfer.remote_staged_path
                        work_sw.staged_checksum = hop.checksum
                elif transfer.uses_no_copy:
                    with _locked():
                        work_sw.staged_package = f"http-stream:{hop.package_filename}"
                        work_sw.staged_checksum = hop.checksum
                with _locked():
                    work_sw.state = SwitchState.STAGED
                    work_sw.last_error = ""
                _persist()
                return work_sw

            # Check whether this hop was already staged cleanly onto /var/tmp
            expected_remote = f"/var/tmp/{hop.package_filename}"  # nosec B108
            transfer: TransferOutcome | None = None
            if work_sw.staged_package == expected_remote:
                ok_staged, _ = driver.verify_staged_checksum(
                    transport,
                    expected_remote,
                    hop.checksum_type,
                    hop.checksum,
                    allow_unverified_checksums=opts.allow_unverified_checksums,
                )
                if ok_staged:
                    transfer = TransferOutcome(
                        mode_used="pre-staged",
                        software_add_target=expected_remote,
                        uses_no_copy=False,
                        remote_staged_path=expected_remote,
                        details=f"Reused verified pre-staged {expected_remote}",
                    )

            if transfer is None:
                transfer = driver.stage_package(
                    transport=transport,
                    switch=work_sw,
                    policy=policy,
                    hop=hop,
                    firmware_dir=opts.firmware_dir,
                    server=server,
                    external_base_url=opts.firmware_base_url,
                    transfer_mode=opts.transfer_mode,
                )
                if not transfer.uses_no_copy and transfer.remote_staged_path:
                    ok_chk, chk_msg = driver.verify_staged_checksum(
                        transport,
                        transfer.remote_staged_path,
                        hop.checksum_type,
                        hop.checksum,
                        allow_unverified_checksums=opts.allow_unverified_checksums,
                    )
                    if not ok_chk:
                        with _locked():
                            work_sw.state = SwitchState.FAILED
                            work_sw.last_error = chk_msg
                        _persist()
                        return work_sw

            with _locked():
                work_sw.state = SwitchState.DOWNLOADED
            _persist()

            with _locked():
                work_sw.state = SwitchState.INSTALLING
            _persist()

            ok_install, install_msg = driver.install_and_reboot(transport, hop, transfer)
            if not ok_install:
                with _locked():
                    work_sw.state = SwitchState.FAILED
                    work_sw.last_error = install_msg
                _persist()
                return work_sw

            with _locked():
                work_sw.staged_package = ""
                work_sw.staged_checksum = ""
                work_sw.state = SwitchState.REBOOTING
            _persist()
        except Exception as exc:  # noqa: BLE001
            with _locked():
                work_sw.state = SwitchState.FAILED
                work_sw.last_error = f"Unexpected error during hop {hop.target_version}: {exc}"
            _persist()
            return work_sw
        finally:
            transport.disconnect()

        if not _wait_for_reboot(
            transport,
            timeout_seconds=policy.boot_timeout_seconds,
            poll_interval=opts.reboot_poll_interval,
            wait_down_seconds=opts.reboot_wait_down_seconds,
        ):
            with _locked():
                work_sw.state = SwitchState.FAILED
                work_sw.last_error = (
                    f"Reboot timer ({policy.boot_timeout_seconds}s) expired or switch never went "
                    f"offline for {work_sw.hostname} ({work_sw.management_ip}). See recovery.txt."
                )
            _persist()
            return work_sw

        if opts.post_settle_seconds > 0:
            time.sleep(opts.post_settle_seconds)

        post_conn_err = _reconnect_post_reboot(
            transport,
            poll_interval=opts.reboot_poll_interval,
            reconnect_timeout_seconds=opts.reconnect_timeout_seconds,
        )
        if post_conn_err is not None:
            with _locked():
                work_sw.state = SwitchState.FAILED
                work_sw.last_error = f"Post-reboot SSH reconnect failed: {post_conn_err}"
            _persist()
            return work_sw

        try:
            post_baseline = driver.collect_baseline(
                transport, ev_dir / "post", fast_delta=use_fast_post
            )
            post_checks = driver.postcheck(
                pre_baseline,
                post_baseline,
                expected_version=hop.target_version,
                diff_output_path=ev_dir / "config_diff.txt",
            )
            failed_post = [c for c in post_checks if not c.passed and c.hard_stop]
            if failed_post:
                # Capture post config locally for forensics WITHOUT overwriting rescue config!
                driver.backup_and_recovery(
                    transport, work_sw, policy, cfg_post_dir, post_baseline, save_rescue=False
                )
                with _locked():
                    work_sw.state = SwitchState.FAILED
                    work_sw.last_error = "; ".join(c.message for c in failed_post)
                _persist()
                return work_sw

            with _locked():
                work_sw.current_version = hop.target_version
                work_sw.state = SwitchState.VALIDATED
                work_sw.last_error = ""
                work_sw.hop_history.append(
                    {
                        "hop": hop.target_version,
                        "package": hop.package_filename,
                        "transfer_mode": transfer.mode_used,
                        "change_number": opts.change_number,
                        "operator": opts.operator,
                        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "status": "validated",
                    }
                )
                refresh_switch_plan(work_sw, policies, exclusions)

            # Only save rescue configuration & refresh recovery.txt AFTER postchecks pass and version updates
            driver.backup_and_recovery(
                transport, work_sw, policy, cfg_post_dir, post_baseline, save_rescue=True
            )

            if opts.refresh_snapshot and work_sw.state == SwitchState.COMPLETED:
                try:
                    ok_snap, snap_msg = driver.refresh_recovery_snapshot(transport, policy)
                    with _locked():
                        if ok_snap:
                            work_sw.recovery_snapshot = hop.target_version
                        else:
                            work_sw.last_error = f"Snapshot refresh warning: {snap_msg}"
                except Exception as snap_exc:  # noqa: BLE001
                    with _locked():
                        work_sw.last_error = f"Snapshot refresh warning: {snap_exc}"

            executed_hops += 1
            _persist()
        except Exception as exc:  # noqa: BLE001
            with _locked():
                work_sw.state = SwitchState.FAILED
                work_sw.last_error = (
                    f"Post-reboot verification failed for {hop.target_version}: {exc}"
                )
            _persist()
            return work_sw
        finally:
            transport.disconnect()

    return work_sw


def run_upgrade_batches(
    all_switches: list[SwitchRecord],
    target_switches: list[SwitchRecord],
    policies: list[PlatformPolicy],
    exclusions: list[dict[str, str]],
    transport_factory: TransportFactory,
    opts: UpgradeOptions,
    server: UnifiedFirmwareServer | None = None,
    graph: TopologyGraph | None = None,
) -> tuple[list[SwitchRecord], bool]:
    """Execute upgrades in leaf-first topology waves, holding ancestors & stopping on failure."""
    topo = graph or build_topology_graph(all_switches)
    waves = compute_topology_waves(
        target_switches, topo, batch_size=opts.batch_size, include_cores=opts.include_cores
    )
    processed: list[SwitchRecord] = []
    wave_ok = True
    manifest_lock = opts.state_lock or threading.Lock()

    def _safe_persist() -> None:
        if opts.dry_run:
            return
        with manifest_lock:
            save_inventory(all_switches, opts.manifest_path)

    for wave in waves:
        with ThreadPoolExecutor(max_workers=max(1, len(wave))) as pool:
            futures = {}
            for sw in wave:
                with manifest_lock:
                    if sw.state == SwitchState.ANCESTOR_HOLD:
                        continue
                policy = match_platform_policy(sw.model, policies)
                if not policy:
                    continue
                try:
                    transport = transport_factory(sw)
                except Exception as exc:  # noqa: BLE001
                    wave_ok = False
                    if opts.dry_run:
                        failed_copy = SwitchRecord.from_dict(sw.to_dict())
                        failed_copy.state = SwitchState.FAILED
                        failed_copy.last_error = f"Transport initialization failed: {exc}"
                        processed.append(failed_copy)
                    else:
                        with manifest_lock:
                            sw.state = SwitchState.FAILED
                            sw.last_error = f"Transport initialization failed: {exc}"
                            mark_ancestor_holds(sw, all_switches, topo)
                        processed.append(sw)
                    continue

                fut = pool.submit(
                    upgrade_single_switch,
                    sw,
                    policy,
                    exclusions,
                    policies,
                    transport,
                    opts,
                    server,
                    _safe_persist,
                    manifest_lock,
                )
                futures[fut] = sw

            for fut in as_completed(futures):
                sw = futures[fut]
                try:
                    updated = fut.result()
                except Exception as exc:  # noqa: BLE001
                    if opts.dry_run:
                        updated = SwitchRecord.from_dict(sw.to_dict())
                        updated.state = SwitchState.FAILED
                        updated.last_error = f"Unhandled worker exception: {exc}"
                    else:
                        with manifest_lock:
                            sw.state = SwitchState.FAILED
                            sw.last_error = f"Unhandled worker exception: {exc}"
                        updated = sw
                processed.append(updated)
                if updated.state in (SwitchState.FAILED, SwitchState.REPLACE_RECOMMENDED):
                    wave_ok = False
                    if not opts.dry_run:
                        with manifest_lock:
                            mark_ancestor_holds(updated, all_switches, topo)

        _safe_persist()
        if not wave_ok:
            break

    return processed, wave_ok
