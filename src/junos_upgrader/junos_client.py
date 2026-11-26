# SPDX-License-Identifier: AGPL-3.0-or-later
"""Live SSH/SCP switch transport, credential loader, and routing probe."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

_INTERACTIVE_EXPECT_RE = r"(?:\[yes,no\]|proceed\s*\?|\[y/n\]|\(yes/no\)|[>#%]\s*$)"
_INTERACTIVE_CONFIRM_RE = re.compile(
    r"(?:\[yes,no\]|proceed\s*\?|\[y/n\]|\(yes/no\))",
    re.IGNORECASE,
)
_CLI_PROMPT_RE = r"[>#%]\s*$"


def _is_placeholder_password(password: str) -> bool:
    clean = password.strip().upper()
    return clean == "CHANGE_ME" or clean.startswith("CHANGE_ME_")


@dataclass(frozen=True)
class CredentialSet:
    """SSH authentication entry (never serialized to logs or manifests)."""

    username: str
    password: str = field(default="", repr=False)
    key_file: str | None = None
    name: str = "cli"
    vendor: str = ""


class SwitchTransport(Protocol):
    """Protocol for executing Junos CLI commands and SCP transfers."""

    def connect(self) -> None: ...
    def disconnect(self) -> None: ...
    def run_command(self, command: str, read_timeout: int = 60) -> str: ...
    def run_interactive_yes(
        self,
        command: str,
        read_timeout: int = 60,
        allow_disconnect: bool = False,
    ) -> str: ...
    def scp_put(self, local_path: Path, remote_path: str) -> None: ...
    def is_reachable(self, timeout: float = 3.0) -> bool: ...


def detect_outbound_ip(
    target_ip: str,
    *,
    allow_loopback_fallback: bool = True,
) -> str:
    """Determine the local IPv4/IPv6 address used to reach target_ip."""
    family = socket.AF_INET
    try:
        addr = ipaddress.ip_address(target_ip)
        if addr.version == 6:
            family = socket.AF_INET6
    except ValueError:
        try:
            infos = socket.getaddrinfo(target_ip, 22, type=socket.SOCK_DGRAM)
            if infos:
                family = infos[0][0]
        except OSError as exc:
            if not allow_loopback_fallback:
                raise RuntimeError(
                    f"Unable to resolve or route target {target_ip!r}: {exc}"
                ) from exc
            return "127.0.0.1"

    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((target_ip, 22))
            return str(sock.getsockname()[0])
    except OSError as exc:
        if not allow_loopback_fallback:
            raise RuntimeError(
                f"Unable to determine outbound local IP for target {target_ip!r}: {exc}"
            ) from exc
        return "127.0.0.1"


def load_credentials(
    credentials_file: Path | None = None,
    username: str | None = None,
    password: str | None = None,
    key_file: str | None = None,
) -> list[CredentialSet]:
    """Load SSH credentials from CLI/env and/or a net-docu-crawler credentials JSON file.

    Juniper-tagged or untagged entries are prioritized ahead of unrelated vendors.
    Raises ValueError when no valid credentials are configured or only CHANGE_ME placeholders remain.
    """
    creds: list[CredentialSet] = []
    saw_placeholder = False
    cli_user = username or os.environ.get("JUNOS_USER")
    cli_pass = password if password is not None else os.environ.get("JUNOS_PASSWORD", "")
    cli_key = key_file or os.environ.get("JUNOS_KEY_FILE")

    if credentials_file and credentials_file.exists():
        raw: Any = json.loads(credentials_file.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            entries = raw.get("ssh") or raw.get("credentials") or [raw]
        elif isinstance(raw, list):
            entries = raw
        else:
            entries = []

        juniper_first: list[CredentialSet] = []
        others: list[CredentialSet] = []
        for idx, item in enumerate(entries):
            if not isinstance(item, dict):
                continue
            u = item.get("username") or item.get("user")
            if not u:
                continue
            p = str(item.get("password") or item.get("pass") or "")
            kf = item.get("key_file")
            if _is_placeholder_password(p) and not kf:
                saw_placeholder = True
                continue
            vendor = str(item.get("vendor", "")).lower()
            entry = CredentialSet(
                username=str(u),
                password="" if _is_placeholder_password(p) else p,
                key_file=str(kf) if kf else None,
                name=str(item.get("name", f"entry-{idx}")),
                vendor=vendor,
            )
            if vendor in ("juniper", "junos", ""):
                juniper_first.append(entry)
            else:
                others.append(entry)
        creds.extend(juniper_first)
        creds.extend(others)

    if cli_user:
        if _is_placeholder_password(cli_pass) and not cli_key:
            saw_placeholder = True
        else:
            creds.insert(
                0,
                CredentialSet(
                    username=cli_user,
                    password="" if _is_placeholder_password(cli_pass) else cli_pass,
                    key_file=cli_key,
                    name="cli-env",
                    vendor="juniper",
                ),
            )

    if not creds:
        if saw_placeholder:
            raise ValueError(
                "Only CHANGE_ME placeholder SSH passwords were found. "
                "Replace placeholder credentials or supply --username/--password/--key-file."
            )
        raise ValueError(
            "No SSH credentials configured. Supply --credentials-file, "
            "--username/--password/--key-file, or JUNOS_USER/JUNOS_PASSWORD."
        )
    return creds


@dataclass
class NetmikoJunosTransport:
    """Live SSH/SCP transport to a Juniper Junos switch via Netmiko."""

    host: str
    credentials: list[CredentialSet] = field(repr=False)
    port: int = 22
    conn_timeout: int = 12
    ssh_strict: bool = False
    connected_username: str = field(default="", init=False)
    _conn: Any | None = field(default=None, init=False, repr=False)

    def connect(self) -> None:
        from netmiko import (
            ConnectHandler,
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
        )
        from paramiko import SSHException
        from paramiko.ssh_exception import IncompatiblePeer

        # Suppress Paramiko's background Transport thread tracebacks on stderr during
        # subnet discovery / legacy handshake fallbacks; exceptions are still raised here.
        paramiko_transport_logger = logging.getLogger("paramiko.transport")
        if paramiko_transport_logger.level == logging.NOTSET:
            paramiko_transport_logger.setLevel(logging.CRITICAL)

        if self._conn is not None:
            self.disconnect()

        if not self.credentials:
            raise ValueError(f"No SSH credentials configured for {self.host}:{self.port}")

        last_err: Exception | None = None
        for idx, cred in enumerate(self.credentials):
            params: dict[str, Any] = {
                "device_type": "juniper_junos",
                "host": self.host,
                "username": cred.username,
                "port": self.port,
                "conn_timeout": self.conn_timeout,
                "global_delay_factor": 1.5,
            }
            if self.ssh_strict:
                params["ssh_strict"] = True
                params["system_host_keys"] = True
            if cred.key_file:
                params["use_keys"] = True
                params["key_file"] = os.path.expanduser(cred.key_file)
            elif not cred.password:
                params["use_keys"] = True
            if cred.password:
                params["password"] = cred.password

            try:
                try:
                    self._conn = ConnectHandler(**params)
                except (NetmikoAuthenticationException, NetmikoTimeoutException):
                    raise
                except SSHException:
                    # Fallback for legacy Junos 17.x/18.x SSH servers on Paramiko 4.0
                    legacy_params = {
                        **params,
                        "disabled_algorithms": {"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]},
                    }
                    self._conn = ConnectHandler(**legacy_params)
            except NetmikoAuthenticationException as exc:
                last_err = exc
                continue
            except NetmikoTimeoutException:
                raise
            except IncompatiblePeer:
                # KEX/host-key negotiation failed before auth; retrying other credentials won't help.
                raise
            except SSHException as exc:
                if cred.key_file and idx < len(self.credentials) - 1:
                    last_err = exc
                    continue
                raise

            try:
                self._conn.send_command("set cli screen-length 0", read_timeout=15)
                self._conn.send_command("set cli screen-width 511", read_timeout=15)
            except Exception:
                self.disconnect()
                raise

            self.connected_username = cred.username
            return

        if last_err is not None:
            raise last_err
        raise RuntimeError(f"Unable to authenticate to {self.host}:{self.port}")

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:  # noqa: BLE001
                pass
            finally:
                self._conn = None

    def run_command(self, command: str, read_timeout: int = 60) -> str:
        if self._conn is None:
            raise RuntimeError("Transport is not connected")
        return str(self._conn.send_command(command, read_timeout=read_timeout))

    def run_interactive_yes(
        self,
        command: str,
        read_timeout: int = 60,
        allow_disconnect: bool = False,
    ) -> str:
        """Execute a Junos command that may prompt `[yes,no]` and confirm with `yes`."""
        if self._conn is None:
            raise RuntimeError("Transport is not connected")
        from netmiko import NetmikoTimeoutException
        from paramiko import SSHException

        out = str(
            self._conn.send_command(
                command,
                expect_string=_INTERACTIVE_EXPECT_RE,
                strip_prompt=False,
                strip_command=False,
                read_timeout=read_timeout,
            )
        )
        if _INTERACTIVE_CONFIRM_RE.search(out):
            try:
                out += str(
                    self._conn.send_command(
                        "yes",
                        expect_string=_CLI_PROMPT_RE,
                        strip_prompt=False,
                        strip_command=False,
                        read_timeout=read_timeout,
                        cmd_verify=False,
                    )
                )
            except (OSError, EOFError, NetmikoTimeoutException, SSHException):
                if not allow_disconnect:
                    raise
                return out
        return out

    def scp_put(self, local_path: Path, remote_path: str) -> None:
        if self._conn is None:
            raise RuntimeError("Transport is not connected")
        from netmiko import SCPConn

        scp = SCPConn(self._conn)
        try:
            scp.scp_put_file(str(local_path), remote_path)
        finally:
            scp.close()

    def is_reachable(self, timeout: float = 3.0) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout):
                return True
        except OSError:
            return False
