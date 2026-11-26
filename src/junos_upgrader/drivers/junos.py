# SPDX-License-Identifier: AGPL-3.0-or-later
"""Juniper Junos OS implementation of SwitchDriver."""

from __future__ import annotations

import hmac
import re
from pathlib import Path, PurePosixPath

from junos_upgrader.checks import (
    backup_configuration,
    collect_baseline,
    generate_recovery_sheet,
    run_postchecks,
    run_prechecks,
)
from junos_upgrader.junos_client import SwitchTransport
from junos_upgrader.models import CheckResult, HopSpec, PlatformPolicy, SwitchRecord
from junos_upgrader.transfer import (
    TransferOutcome,
    UnifiedFirmwareServer,
    stage_or_stream_package,
    validate_cli_target,
    validate_package_filename,
)

_CHECKSUM_CLI_MAP: dict[str, str] = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha-256",
    "sha-256": "sha-256",
}
_CHECKSUM_HEX_LEN: dict[str, int] = {
    "md5": 32,
    "sha1": 40,
    "sha-256": 64,
}
_HEX_DIGEST_RE = re.compile(r"=\s*([0-9a-fA-F]{32,64})\b")
_ALLOWED_INSTALL_OPTIONS = frozenset({"no-validate", "force-host", "no-copy", "unlink", "force"})
_CHECKSUM_CLI_ERR_TOKENS = (
    "error:",
    "syntax error",
    "unknown command",
    "no such file",
    "cannot open",
    "permission denied",
)
_INSTALL_FAIL_TOKENS = (
    "error:",
    "syntax error",
    "unknown command",
    "validation failed",
    "installation failed",
    "signature verification failed",
    "authentication error",
    "veriexec:",
    "not enough space",
    "no space left",
    "filesystem full",
    "fetch:",
    "no such file",
    "file not found",
    "404 not found",
    "host not found",
    "cannot open",
    "cannot allocate",
    "checksum mismatch",
    "truncated",
    "aborted",
    "incompatible",
    "not supported",
    "package is not valid",
)
_REBOOT_FAIL_TOKENS = (
    "error:",
    "syntax error",
    "unknown command",
    "permission denied",
    "failed",
)
_SNAPSHOT_FAIL_TOKENS = (
    "error:",
    "syntax error",
    "unknown command",
    "failed",
    "not supported",
    "cannot ",
    "no space",
    "aborted",
)


def _validated_staged_delete_path(remote_path: str) -> str | None:
    """Return a validated /tmp or /var/tmp package file path safe for `file delete`, or None."""
    if (
        not remote_path
        or not remote_path.startswith(("/var/tmp/", "/tmp/"))  # nosec B108
        or ".." in remote_path
    ):
        return None
    try:
        clean_remote = validate_cli_target(remote_path, "remote_staged_path")
        posix = PurePosixPath(clean_remote)
        if posix.parent.as_posix() not in ("/tmp", "/var/tmp"):  # nosec B108
            return None
        if clean_remote != f"{posix.parent.as_posix()}/{posix.name}":
            return None
        validate_package_filename(posix.name)
    except ValueError:
        return None
    return clean_remote


class JunosSwitchDriver:
    """Junos EX/QFX implementation of the SwitchDriver lifecycle protocol."""

    vendor = "juniper"

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
    ) -> list[CheckResult]:
        return run_prechecks(
            transport=transport,
            switch=switch,
            policy=policy,
            hop=hop,
            evidence_dir=evidence_dir,
            config_root=config_root,
            local_pkg_file=local_pkg_file,
            require_release_notes=require_release_notes,
            execute_cleanup=execute_cleanup,
            ignore_old_cores=ignore_old_cores,
            allow_no_console=allow_no_console,
            allow_unverified_checksums=allow_unverified_checksums,
            allow_aaa_only_ssh=allow_aaa_only_ssh,
        )

    def collect_baseline(
        self,
        transport: SwitchTransport,
        output_dir: Path,
        fast_delta: bool = False,
    ) -> dict[str, str]:
        return collect_baseline(transport, output_dir, fast_delta=fast_delta)

    def backup_and_recovery(
        self,
        transport: SwitchTransport,
        switch: SwitchRecord,
        policy: PlatformPolicy,
        config_dir: Path,
        baseline: dict[str, str],
        save_rescue: bool = True,
    ) -> tuple[Path, Path]:
        backup_path = backup_configuration(transport, config_dir, baseline, save_rescue=save_rescue)
        # Store recovery.txt directly under the switch config root (configs/<site>/<hostname>/recovery.txt)
        switch_cfg_root = (
            config_dir.parents[1] if config_dir.parent.name in ("pre", "post") else config_dir
        )
        recovery_path = generate_recovery_sheet(
            switch=switch,
            policy=policy,
            baseline=baseline,
            output_path=switch_cfg_root / "recovery.txt",
        )
        return backup_path, recovery_path

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
    ) -> TransferOutcome:
        return stage_or_stream_package(
            transport=transport,
            switch=switch,
            policy=policy,
            hop=hop,
            firmware_dir=firmware_dir,
            server=server,
            external_base_url=external_base_url,
            transfer_mode=transfer_mode,
        )

    def verify_staged_checksum(
        self,
        transport: SwitchTransport,
        remote_path: str,
        checksum_type: str,
        expected_checksum: str,
        allow_unverified_checksums: bool = False,
    ) -> tuple[bool, str]:
        cli_algo = _CHECKSUM_CLI_MAP.get(checksum_type.strip().lower())
        if cli_algo is None:
            return (
                False,
                f"Unsupported checksum_type {checksum_type!r} (allowed: md5, sha1, sha-256).",
            )

        try:
            clean_remote = validate_cli_target(remote_path, "remote_path")
            if not clean_remote.startswith(("/var/tmp/", "/tmp/")) or ".." in clean_remote:  # nosec B108
                return (
                    False,
                    f"Remote path must be a direct file under /var/tmp/ or /tmp/: {remote_path!r}",
                )
            validate_package_filename(Path(clean_remote).name)
        except ValueError as exc:
            return False, str(exc)

        expected_clean = expected_checksum.strip().lower()
        is_placeholder = (not expected_clean) or ("replace" in expected_clean)
        if is_placeholder and not allow_unverified_checksums:
            return (
                False,
                f"Refusing unverified/placeholder checksum ({expected_checksum!r}) for {clean_remote}; "
                "run `firmware scan` or pass --allow-unverified-checksums.",
            )

        chk_out = transport.run_command(
            f"file checksum {cli_algo} {clean_remote}",
            read_timeout=120,
        )
        lower_out = chk_out.lower()
        if not lower_out.strip() or any(tok in lower_out for tok in _CHECKSUM_CLI_ERR_TOKENS):
            return False, chk_out.strip() or f"Empty checksum output for {clean_remote}"

        if is_placeholder:
            return True, f"UNVERIFIED: placeholder checksum skipped ({chk_out.strip()})"

        expected_len = _CHECKSUM_HEX_LEN[cli_algo]
        if not re.fullmatch(rf"[0-9a-f]{{{expected_len}}}", expected_clean):
            return (
                False,
                f"Invalid expected {cli_algo} checksum length/format for {clean_remote}: {expected_checksum!r}",
            )

        match = _HEX_DIGEST_RE.search(chk_out)
        if not match:
            return False, f"Could not parse {cli_algo} digest for {clean_remote}: {chk_out.strip()}"
        actual_digest = match.group(1).lower()
        if not hmac.compare_digest(actual_digest, expected_clean):
            return (
                False,
                f"Checksum mismatch for {clean_remote}: got {actual_digest}, expected {expected_clean}",
            )
        return True, chk_out.strip()

    def install_and_reboot(
        self,
        transport: SwitchTransport,
        hop: HopSpec,
        transfer: TransferOutcome,
    ) -> tuple[bool, str]:
        try:
            target = validate_cli_target(transfer.software_add_target, "software_add_target")
        except ValueError as exc:
            return False, str(exc)

        extra_opts: list[str] = []
        for raw_opt in hop.install_options:
            opt = str(raw_opt).strip()
            if opt not in _ALLOWED_INSTALL_OPTIONS:
                return (
                    False,
                    f"Disallowed Junos install option {raw_opt!r} "
                    f"(allowed: {sorted(_ALLOWED_INSTALL_OPTIONS)})",
                )
            if opt not in extra_opts:
                extra_opts.append(opt)
        if transfer.uses_no_copy and "no-copy" not in extra_opts:
            extra_opts.append("no-copy")
        if "unlink" not in extra_opts:
            extra_opts.append("unlink")
        opts_str = (" " + " ".join(extra_opts)) if extra_opts else ""

        install_out = transport.run_command(
            f"request system software add {target}{opts_str}",
            read_timeout=900,
        )
        lower_out = install_out.lower()
        scan_out = lower_out
        if "notice: 'pending' set will be activated at next reboot" in lower_out:
            scan_out = "\n".join(
                ln for ln in lower_out.splitlines() if not ln.lstrip().startswith("veriexec:")
            )
        if not scan_out.strip() or any(tok in scan_out for tok in _INSTALL_FAIL_TOKENS):
            clean_staged = _validated_staged_delete_path(transfer.remote_staged_path)
            if clean_staged is not None:
                try:
                    transport.run_command(f"file delete {clean_staged}", read_timeout=30)
                except Exception:  # noqa: BLE001
                    pass
            if not scan_out.strip():
                return False, "Software add failed: empty response from switch."
            return False, f"Software add failed: {install_out.strip()}"

        if hasattr(transport, "run_interactive_yes"):
            reboot_out = transport.run_interactive_yes(
                "request system reboot", read_timeout=30, allow_disconnect=True
            )
        else:
            reboot_out = transport.run_command("request system reboot", read_timeout=30)
        reboot_lower = reboot_out.lower()
        if any(tok in reboot_lower for tok in _REBOOT_FAIL_TOKENS):
            return False, f"Reboot command failed: {reboot_out.strip()}"
        return True, install_out.strip()

    def postcheck(
        self,
        pre_baseline: dict[str, str],
        post_baseline: dict[str, str],
        expected_version: str,
        diff_output_path: Path | None = None,
    ) -> list[CheckResult]:
        return run_postchecks(
            pre_baseline=pre_baseline,
            post_baseline=post_baseline,
            expected_version=expected_version,
            diff_output_path=diff_output_path,
        )

    def refresh_recovery_snapshot(
        self,
        transport: SwitchTransport,
        policy: PlatformPolicy,
    ) -> tuple[bool, str]:
        arch = policy.expected_arch.lower()
        if any(tok in arch for tok in ("vmhost", "qfx", "ex-4650")):
            cmd = "request vmhost snapshot"
        elif "powerpc" in arch:
            cmd = "request system snapshot slice alternate"
        else:
            cmd = "request system snapshot recovery"
        if hasattr(transport, "run_interactive_yes"):
            out = transport.run_interactive_yes(cmd, read_timeout=300, allow_disconnect=False)
        else:
            out = transport.run_command(cmd, read_timeout=300)
        lower_out = out.lower()
        ok = bool(lower_out.strip()) and not any(tok in lower_out for tok in _SNAPSHOT_FAIL_TOKENS)
        return ok, out.strip()
