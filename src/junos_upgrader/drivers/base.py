# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vendor-neutral SwitchDriver protocol separating upgrade FSM from device CLI details."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from junos_upgrader.junos_client import SwitchTransport
from junos_upgrader.models import CheckResult, HopSpec, PlatformPolicy, SwitchRecord
from junos_upgrader.transfer import TransferOutcome, UnifiedFirmwareServer


class SwitchDriver(Protocol):
    """Lifecycle interface every vendor upgrade driver implements."""

    vendor: str

    def precheck(
        self,
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
        allow_aaa_only_ssh: bool = False,
    ) -> list[CheckResult]: ...

    def collect_baseline(
        self,
        transport: SwitchTransport,
        output_dir: Path,
        fast_delta: bool = False,
    ) -> dict[str, str]: ...

    def backup_and_recovery(
        self,
        transport: SwitchTransport,
        switch: SwitchRecord,
        policy: PlatformPolicy,
        config_dir: Path,
        baseline: dict[str, str],
        save_rescue: bool = True,
    ) -> tuple[Path, Path]: ...

    def stage_package(
        self,
        transport: SwitchTransport,
        switch: SwitchRecord,
        policy: PlatformPolicy,
        hop: HopSpec,
        firmware_dir: Path,
        server: UnifiedFirmwareServer | None,
        external_base_url: str,
        transfer_mode: str = "auto",
    ) -> TransferOutcome: ...

    def verify_staged_checksum(
        self,
        transport: SwitchTransport,
        remote_path: str,
        checksum_type: str,
        expected_checksum: str,
        allow_unverified_checksums: bool = False,
    ) -> tuple[bool, str]: ...

    def install_and_reboot(
        self,
        transport: SwitchTransport,
        hop: HopSpec,
        transfer: TransferOutcome,
    ) -> tuple[bool, str]: ...

    def postcheck(
        self,
        pre_baseline: dict[str, str],
        post_baseline: dict[str, str],
        expected_version: str,
        diff_output_path: Path | None = None,
    ) -> list[CheckResult]: ...

    def refresh_recovery_snapshot(
        self,
        transport: SwitchTransport,
        policy: PlatformPolicy,
    ) -> tuple[bool, str]: ...
