# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test fixtures and FakeJunosTransport test double (tests only)."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from junos_upgrader.topology import RunnerOrigin

TEST_ORIGIN = RunnerOrigin(
    hostname="test-runner",
    outbound_ip="192.0.2.5",
    outbound_iface="eth0",
    gateway_ip="192.0.2.1",
)

DEFAULT_REALISTIC_OPTICS = (
    "Physical interface: xe-0/2/0\n"
    "    Laser bias current                        :  7.834 mA\n"
    "    Laser output power                        :  0.6010 mW / -2.21 dBm\n"
    "    Receiver signal average optical power     :  0.5430 mW / -2.65 dBm\n"
    "    Laser bias current high alarm             :  Off\n"
    "    Laser bias current low alarm              :  Off\n"
    "    Laser output power high alarm             :  Off\n"
    "    Laser output power low alarm              :  Off\n"
    "    Laser rx power high alarm                 :  Off\n"
    "    Laser rx power low alarm                  :  Off\n"
)

DEFAULT_ELS_LLDP = (
    "Local Interface    Parent Interface    Chassis Id          Port info          System Name\n"
    "xe-0/2/0           -                   00:00:5e:00:53:01   xe-0/0/1           CORE_SW\n"
)

DEFAULT_STP_BRIDGE = (
    "STP bridge parameters\n"
    "Routing instance name               : GLOBAL\n"
    "Context ID                          : 0\n"
    "Enabled protocol                    : RSTP\n"
    "  Root ID                           : 32768.00:00:5e:00:53:01\n"
)


def create_valid_tgz(dest: Path, comment: str = "arm-32") -> tuple[Path, str, str]:
    """Create a valid gzip-compressed tar archive with +COMMENT and return (path, md5, sha256)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    comment_file = dest.parent / f".comment_{dest.stem}.tmp"
    comment_file.write_text(comment, encoding="utf-8")
    try:
        with tarfile.open(dest, "w:gz") as tf:
            tf.add(comment_file, arcname="+COMMENT")
    finally:
        if comment_file.exists():
            comment_file.unlink()
    raw = dest.read_bytes()
    return dest, hashlib.md5(raw).hexdigest(), hashlib.sha256(raw).hexdigest()


@dataclass
class FakeJunosTransport:
    """In-memory Junos SSH/SCP test double mimicking EX2300/EX3400/EX4600 JSON & CLI outputs."""

    hostname: str
    model: str
    serial_number: str
    running_version: str
    pkg_arch_tag: str = "os-runtime-arm-32"
    free_storage_mb: int = 1200
    storage_mount: str = "/.mount"
    tmpfs_free_mb: int | None = None
    tmpfs_mount: str = "/.mount/tmp"
    alarms: str = "No alarms currently active"
    sys_alarms: str | None = None
    chas_alarms: str | None = None
    post_sys_alarms: str | None = None
    post_chas_alarms: str | None = None
    chassis_env: str = "Power FPC 0 Power Supply 0 OK\nTemp FPC 0 CPU Sensor OK 44 degrees C\n"
    mount_output: str = "/dev/gpt/junos on /.mount (ufs, local, soft-updates)\n"
    flash_log_output: str = ""
    crash_files_output: str = ""
    var_tmp_output: str = "total 0\n"
    optics_output: str = DEFAULT_REALISTIC_OPTICS
    snapshot_output: str = (
        "Recovery Snapshots:\nSnapshots available on the OAM volume:\n"
        "recovery.ufs\nJunos version: 19.3R2.9\n"
    )
    lldp_output: str = DEFAULT_ELS_LLDP
    post_lldp_output: str | None = None
    stp_bridge_output: str = DEFAULT_STP_BRIDGE
    post_stp_bridge_output: str | None = None
    interfaces_terse_output: str = "ge-0/0/0 up up\nxe-0/2/0 up up\n"
    post_interfaces_terse_output: str | None = None
    config_set_extra: str = ""
    poe_watts_pre: float | None = 15.4
    poe_watts_post: float | None = 15.4
    mac_count_pre: int = 4
    mac_count_post: int = 4
    lacp_up_pre: list[str] = field(default_factory=list)
    lacp_up_post: list[str] = field(default_factory=list)
    virtual_chassis: bool = False
    uncommitted_changes: bool = False
    fail_http_copy: bool = False
    fail_install: bool = False
    fail_reboot: bool = False
    fail_reboot_cmd: bool = False
    fail_snapshot: bool = False
    raise_on_snapshot: bool = False
    go_down_polls: int = 0
    _down_polls_left: int = field(default=0, init=False)
    _post_reboot: bool = field(default=False, init=False)
    checksum_override: str | None = None
    checksums_by_filename: dict[str, str] = field(default_factory=dict)
    pending_version: str | None = None
    commands_executed: list[str] = field(default_factory=list)
    scp_uploads: list[tuple[Path, str]] = field(default_factory=list)

    def connect(self) -> None:
        return None

    def disconnect(self) -> None:
        return None

    def is_reachable(self, timeout: float = 3.0) -> bool:
        if self._down_polls_left > 0:
            self._down_polls_left -= 1
            return False
        return not self.fail_reboot

    def scp_put(self, local_path: Path, remote_path: str) -> None:
        self.scp_uploads.append((local_path, remote_path))

    def run_interactive_yes(
        self,
        command: str,
        read_timeout: int = 60,
        allow_disconnect: bool = False,
    ) -> str:
        return self.run_command(command, read_timeout=read_timeout)

    def run_command(self, command: str, read_timeout: int = 60) -> str:
        self.commands_executed.append(command)
        cmd = command.strip()

        if cmd == "show version | display json":
            return json.dumps(
                {
                    "software-information": [
                        {
                            "host-name": [{"data": self.hostname}],
                            "product-model": [{"data": self.model}],
                            "junos-version": [{"data": self.running_version}],
                            "package-information": [
                                {
                                    "package-name": [{"data": self.pkg_arch_tag}],
                                    "comment": [{"data": ""}],
                                }
                            ],
                        }
                    ]
                }
            )
        if cmd == "show version":
            return (
                f"Hostname: {self.hostname}\n"
                f"Model: {self.model}\n"
                f"Junos: {self.running_version}\n"
                f"Package: {self.pkg_arch_tag}\n"
            )
        if cmd == "show chassis hardware":
            return f"Chassis                                {self.serial_number}  {self.model.upper()}\n"
        if cmd == "show chassis environment":
            return self.chassis_env
        if cmd == "show chassis firmware":
            return (
                "Part                     Type       Tag         Firmware\n"
                "FPC 0                    PoE        1           v2.1\n"
            )
        if cmd == "show virtual-chassis status":
            if self.virtual_chassis:
                return (
                    "Virtual Chassis ID: 0000.5e00.5302\n"
                    "0 (FPC 0) Prsnt Master*\n"
                    "1 (FPC 1) Prsnt Backup\n"
                )
            return "Virtual Chassis ID: 0000.5e00.5301\n0 (FPC 0) Prsnt Master*\n"
        if cmd in ("show system storage | display json", "show system storage"):
            if "json" in cmd:
                filesystems = [
                    {
                        "filesystem-name": [{"data": "/dev/gpt/junos"}],
                        "available-blocks": [
                            {
                                "data": str(self.free_storage_mb * 2048),
                                "attributes": {
                                    "junos:format": f"{self.free_storage_mb}M"
                                },
                            }
                        ],
                        "mounted-on": [{"data": self.storage_mount}],
                    }
                ]
                if self.tmpfs_free_mb is not None:
                    filesystems.append(
                        {
                            "filesystem-name": [{"data": "tmpfs"}],
                            "available-blocks": [
                                {
                                    "data": str(self.tmpfs_free_mb * 2048),
                                    "attributes": {
                                        "junos:format": f"{self.tmpfs_free_mb}M"
                                    },
                                }
                            ],
                            "mounted-on": [{"data": self.tmpfs_mount}],
                        }
                    )
                return json.dumps({"system-storage-information": [{"filesystem": filesystems}]})
            text = (
                "Filesystem Size Used Avail Capacity Mounted on\n"
                f"/dev/gpt/junos 1.3G 950M {self.free_storage_mb}M 76% {self.storage_mount}\n"
            )
            if self.tmpfs_free_mb is not None:
                text += f"tmpfs 1.0G 0B {self.tmpfs_free_mb}M 0% {self.tmpfs_mount}\n"
            return text
        if cmd == 'start shell command "mount"':
            return self.mount_output
        if cmd.startswith("show log messages"):
            return self.flash_log_output
        if cmd == "file list /var/crash detail":
            return self.crash_files_output
        if cmd == "file list /var/tmp detail":
            return self.var_tmp_output
        if cmd.startswith("request system storage cleanup"):
            return "No files deleted"
        if cmd == "show system snapshot media internal":
            return self.snapshot_output
        if cmd in (
            "request system snapshot recovery",
            "request system snapshot slice alternate",
            "request vmhost snapshot",
        ):
            if self.raise_on_snapshot:
                raise TimeoutError("Snapshot timed out")
            if self.fail_snapshot:
                return "error: snapshot failed"
            return "Snapshot created successfully"
        if cmd == "show system alarms":
            if self._post_reboot and self.post_sys_alarms is not None:
                return self.post_sys_alarms
            return self.sys_alarms if self.sys_alarms is not None else self.alarms
        if cmd == "show chassis alarms":
            if self._post_reboot and self.post_chas_alarms is not None:
                return self.post_chas_alarms
            return self.chas_alarms if self.chas_alarms is not None else self.alarms
        if cmd == "show system commit":
            if self.uncommitted_changes:
                return (
                    "0   2026-11-21 10:00:00 UTC by netops via cli\n"
                    "    commit confirmed, rollback in 5 minutes\n"
                )
            return "0 2026-11-21 10:00:00 UTC by netops via cli"
        if cmd == "show interfaces diagnostics optics":
            return self.optics_output
        if cmd == "show interfaces terse":
            if self._post_reboot and self.post_interfaces_terse_output is not None:
                return self.post_interfaces_terse_output
            return self.interfaces_terse_output
        if cmd == "show lldp neighbors":
            if self._post_reboot and self.post_lldp_output is not None:
                return self.post_lldp_output
            return self.lldp_output
        if cmd == "show spanning-tree bridge":
            if self._post_reboot and self.post_stp_bridge_output is not None:
                return self.post_stp_bridge_output
            return self.stp_bridge_output
        if cmd == "show poe controller":
            watts = self.poe_watts_post if self._post_reboot else self.poe_watts_pre
            if watts is None or "ex4600" in self.model.lower() or "qfx" in self.model.lower():
                return "error: command is not valid"
            return (
                "Controller  Maximum   Power         Guard    Management   Status\n"
                f"   0        124W      {watts:.2f}W          0W     Class        AT_MODE\n"
            )
        if cmd == "show ethernet-switching table":
            cnt = self.mac_count_post if self._post_reboot else self.mac_count_pre
            if cnt <= 0:
                return "Ethernet switching table : 0 entries, 0 learned\n"
            rows = [
                f"    default             00:00:5e:00:53:{i + 10:02x}   D             -           ge-0/0/{i}.0"
                for i in range(cnt)
            ]
            return f"Ethernet switching table : {cnt} entries, {cnt} learned\n" + "\n".join(rows)
        if cmd == "show lacp interfaces":
            members = self.lacp_up_post if self._post_reboot else self.lacp_up_pre
            if not members:
                return ""
            return "\n".join(
                f"  {iface}                  Current   Fast periodic Collecting distributing"
                for iface in members
            )
        if cmd == "show route":
            return "0.0.0.0/0 *[Static/5] 1w0d 00:00:00\n > to 192.0.2.1 via irb.0\n"
        if cmd == "show configuration | display set | no-more":
            base = (
                f"set system host-name {self.hostname}\n"
                "set interfaces irb unit 0 family inet address 192.0.2.10/24\n"
                "set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1\n"
            )
            return base + (self.config_set_extra + "\n" if self.config_set_extra else "")
        if cmd == "show configuration | no-more":
            return f"system {{\n    host-name {self.hostname};\n}}\n"
        if cmd.startswith("file copy "):
            if self.fail_http_copy:
                return "error: fetch: connection refused"
            return "100% 240MB 24.0MB/s"
        if cmd.startswith("file checksum "):
            remote_path = cmd.split()[-1]
            fname = Path(remote_path).name
            algo = cmd.split()[2].upper()
            digest = (
                self.checksum_override
                or self.checksums_by_filename.get(fname)
                or "0" * (64 if "256" in algo else 32)
            )
            return f"{algo} ({remote_path}) = {digest}"
        if cmd.startswith("request system software add "):
            if self.fail_install:
                return "ERROR: Installation failed"
            m = re.search(
                r"(\d+\.\d+[RX]\d+(?:[-.]?[SD]\d+(?:\.\d+)?|\.\d+)?)",
                cmd,
                re.IGNORECASE,
            )
            if m:
                self.pending_version = m.group(1)
            return "NOTICE: 'pending' set will be activated at next reboot"
        if cmd == "request system reboot":
            if self.fail_reboot_cmd:
                return "error: permission denied"
            self._down_polls_left = self.go_down_polls
            if self.pending_version and not self.fail_reboot:
                self.running_version = self.pending_version
                self.pending_version = None
                self._post_reboot = True
            return "Reboot the system ? [yes,no] (no) yes\nShutdown NOW!"
        return f"OK: {cmd}"

    def configure_local_fallback_user(
        self,
        username: str,
        *,
        password: str | None = None,
        ssh_public_key: str | None = None,
    ) -> tuple[bool, str]:
        self.commands_executed.append(f"configure_local_fallback_user:{username}")
        lines = [f"set system login user {username} class super-user"]
        if ssh_public_key:
            lines.append(
                f'set system login user {username} authentication ssh-ed25519 "{ssh_public_key.strip()}"'
            )
        elif password:
            lines.append(
                f'set system login user {username} authentication encrypted-password "$6$fakehash"'
            )
        extra = "\n".join(lines)
        self.config_set_extra = (
            f"{self.config_set_extra}\n{extra}" if self.config_set_extra else extra
        )
        return True, f"Configured and committed local super-user fallback '{username}'."
