# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unified HTTP + SCP firmware server and package transfer orchestration."""

from __future__ import annotations

import functools
import hmac
import ipaddress
import json
import re
import secrets
import shutil
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse

from junos_upgrader.junos_client import SwitchTransport, detect_outbound_ip
from junos_upgrader.models import HopSpec, PlatformPolicy, SwitchRecord

SAFE_PACKAGE_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.tgz$")
CLI_UNSAFE_RE = re.compile(r"[\s;|`$&<>\"'\r\n\x00]")
VALID_TRANSFER_MODES = frozenset(
    {"auto", "http", "http-stream", "scp", "external-http", "http-with-scp-fallback"}
)
_LOOPBACK_CLIENTS = frozenset({"127.0.0.1", "::1", "::ffff:127.0.0.1"})
_PLACEHOLDER_DOMAINS = (
    "example.internal",
    "example.com",
    "example.org",
    "example.net",
    "invalid",
    "example",
)
_MAX_TRANSFER_LOG = 1000
_HTTP_COPY_FAIL_TOKENS = (
    "error:",
    "fetch:",
    "syntax error",
    "unknown command",
    "no space left",
    "not enough space",
    "filesystem full",
    "connection timed out",
    "connection refused",
    "no route to host",
    "permission denied",
    "could not resolve",
    "404 ",
    "403 ",
    "500 ",
    "not found",
    "transfer failed",
    "failed to ",
    "cannot open",
    "no such file",
    "truncated",
    "aborted",
)


def validate_package_filename(filename: str) -> str:
    """Validate that a firmware package filename is a safe basename ending in .tgz."""
    clean = filename.strip()
    if (
        not clean
        or ".." in clean
        or "/" in clean
        or "\\" in clean
        or not SAFE_PACKAGE_FILENAME_RE.fullmatch(clean)
    ):
        raise ValueError(f"Unsafe or invalid firmware package filename: {filename!r}")
    return clean


def validate_cli_target(value: str, label: str = "target") -> str:
    """Validate that a URL or remote path contains no Junos CLI injection characters."""
    clean = value.strip()
    if not clean or CLI_UNSAFE_RE.search(clean):
        raise ValueError(f"Unsafe CLI characters in {label}: {value!r}")
    return clean


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _http_copy_failed(output: str) -> bool:
    lower = output.lower().strip()
    if not lower:
        return True
    return any(tok in lower for tok in _HTTP_COPY_FAIL_TOKENS)


@dataclass
class TransferOutcome:
    """Result of staging or preparing an image URL for a switch hop."""

    mode_used: str  # http-stream | http-copy | scp | external-url | pre-staged
    software_add_target: str
    uses_no_copy: bool
    remote_staged_path: str = ""
    details: str = ""


class _ThreadingHTTPServerV6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _normalize_ip(raw: str) -> str:
    """Normalize IPv4/IPv6 addresses (unwrapping IPv4-mapped IPv6) for reliable ACL comparison."""
    clean = raw.strip().split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(clean)
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            addr = mapped
        return addr.compressed
    except ValueError:
        return clean.lower()


class _UnifiedHandler(SimpleHTTPRequestHandler):
    """Serve token-protected .tgz binaries under /firmware/<token>/ and loopback-only UI under /."""

    timeout = 30

    def __init__(
        self,
        *args: Any,
        firmware_dir: Path,
        topology_provider: Callable[[], dict[str, Any]],
        html_provider: Callable[[], str],
        transfer_log: list[dict[str, Any]],
        transfer_log_lock: threading.Lock,
        token: str,
        allow_remote_ui: bool,
        allowed_clients: set[str] | None,
        **kwargs: Any,
    ) -> None:
        self._firmware_dir = firmware_dir.resolve()
        self._topology_provider = topology_provider
        self._html_provider = html_provider
        self._transfer_log = transfer_log
        self._transfer_log_lock = transfer_log_lock
        self._token = token
        self._allow_remote_ui = allow_remote_ui
        self._allowed_clients = (
            {_normalize_ip(c) for c in allowed_clients} if allowed_clients is not None else None
        )
        super().__init__(*args, directory=str(self._firmware_dir), **kwargs)

    def _client_ip(self) -> str:
        raw = str(self.client_address[0]) if self.client_address else ""
        return _normalize_ip(raw)

    def _is_loopback_client(self) -> bool:
        return self._client_ip() in _LOOPBACK_CLIENTS

    def _is_allowed_firmware_client(self) -> bool:
        if self._allowed_clients is None:
            return True
        return self._client_ip() in self._allowed_clients

    def log_message(self, format: str, *args: Any) -> None:
        # Keep stdout clean for Rich progress displays; log firmware hits with token redacted.
        if args and "/firmware/" in str(args[0]):
            sanitized = str(args[0]).replace(self._token, "<redacted>")
            entry = {"client": self._client_ip(), "request": sanitized}
            with self._transfer_log_lock:
                self._transfer_log.append(entry)
                if len(self._transfer_log) > _MAX_TRANSFER_LOG:
                    del self._transfer_log[: len(self._transfer_log) - _MAX_TRANSFER_LOG]

    def _resolve_firmware_target(self, raw_path: str) -> Path | None:
        if "\x00" in raw_path:
            return None
        stripped = raw_path.split("?", 1)[0].split("#", 1)[0]
        try:
            clean = unquote(stripped)
        except Exception:  # noqa: BLE001
            return None
        if "\x00" in clean or "\\" in clean or not clean.startswith("/firmware/"):
            return None

        remainder = clean[len("/firmware/") :]
        if "/" not in remainder:
            return None
        req_token, rel = remainder.split("/", 1)
        if not req_token or not hmac.compare_digest(req_token, self._token):
            return None
        rel = rel.lstrip("/")
        if not rel or rel.endswith("/"):
            return None

        try:
            candidate = (self._firmware_dir / rel).resolve()
        except (ValueError, OSError):
            return None

        if self._firmware_dir not in candidate.parents:
            return None
        if not candidate.is_file() or not candidate.name.lower().endswith(".tgz"):
            return None
        return candidate

    def translate_path(self, path: str) -> str:
        target = self._resolve_firmware_target(path)
        if target is not None:
            return str(target)
        return str(self._firmware_dir / "__blocked_path__")

    def _check_ui_access(self) -> bool:
        if not self._allow_remote_ui and not self._is_loopback_client():
            self.send_error(HTTPStatus.FORBIDDEN, "Dashboard restricted to loopback clients")
            return False
        return True

    def _serve_bytes(
        self,
        body: bytes,
        content_type: str,
        *,
        head_only: bool,
        no_store: bool = False,
    ) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        if no_store:
            self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _serve_firmware(self, *, head_only: bool) -> None:
        if not self._is_allowed_firmware_client():
            self.send_error(HTTPStatus.FORBIDDEN, "Client IP not permitted for firmware download")
            return
        target = self._resolve_firmware_target(self.path)
        if target is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Firmware file not found")
            return
        try:
            stat = target.stat()
            if head_only:
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/gzip")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(stat.st_size))
                self.end_headers()
                return
            with target.open("rb") as fh:
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/gzip")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(stat.st_size))
                self.end_headers()
                shutil.copyfileobj(fh, self.wfile)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "Firmware file not found")

    def _handle_request(self, *, head_only: bool) -> None:
        clean = self.path.split("?", 1)[0].split("#", 1)[0]
        if clean in ("/", "/index.html"):
            if not self._check_ui_access():
                return
            body = self._html_provider().encode("utf-8")
            self._serve_bytes(body, "text/html; charset=utf-8", head_only=head_only)
            return
        if clean == "/api/topology":
            if not self._check_ui_access():
                return
            payload = json.dumps(self._topology_provider(), indent=2).encode("utf-8")
            self._serve_bytes(
                payload, "application/json; charset=utf-8", head_only=head_only, no_store=True
            )
            return
        if clean.startswith("/firmware/"):
            self._serve_firmware(head_only=head_only)
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_GET(self) -> None:
        self._handle_request(head_only=False)

    def do_HEAD(self) -> None:
        self._handle_request(head_only=True)


class UnifiedFirmwareServer:
    """Single-folder HTTP firmware host + live topology dashboard server."""

    def __init__(
        self,
        firmware_dir: Path,
        topology_provider: Callable[[], dict[str, Any]] | None = None,
        port: int = 8080,
        bind_host: str = "0.0.0.0",  # nosec B104
        allow_remote_ui: bool = False,
        allowed_clients: set[str] | None = None,
        html_provider: Callable[[], str] | None = None,
    ) -> None:
        self.firmware_dir = firmware_dir
        self.topology_provider = topology_provider or (lambda: {"nodes": [], "edges": []})
        self.html_provider = html_provider or (lambda: "<h1>junos-switch-upgrader</h1>")
        self.port = port
        self.bind_host = bind_host
        self.allow_remote_ui = allow_remote_ui
        self.allowed_clients = (
            {_normalize_ip(c) for c in allowed_clients} if allowed_clients is not None else None
        )
        self.token = secrets.token_urlsafe(16)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._transfer_log_lock = threading.Lock()
        self.transfer_log: list[dict[str, Any]] = []

    def start(self) -> int:
        if self._server is not None:
            return self.port
        self.firmware_dir.mkdir(parents=True, exist_ok=True)
        handler = functools.partial(
            _UnifiedHandler,
            firmware_dir=self.firmware_dir,
            topology_provider=self.topology_provider,
            html_provider=self.html_provider,
            transfer_log=self.transfer_log,
            transfer_log_lock=self._transfer_log_lock,
            token=self.token,
            allow_remote_ui=self.allow_remote_ui,
            allowed_clients=self.allowed_clients,
        )
        server_cls: type[ThreadingHTTPServer] = ThreadingHTTPServer
        try:
            if ipaddress.ip_address(self.bind_host).version == 6:
                server_cls = _ThreadingHTTPServerV6
        except ValueError:
            pass
        self._server = server_cls((self.bind_host, self.port), handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="unified-firmware-http",
            daemon=True,
        )
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None

    def __enter__(self) -> UnifiedFirmwareServer:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def build_http_url(self, target_switch_ip: str, rel_path: str) -> str:
        if self.port <= 0:
            raise RuntimeError("UnifiedFirmwareServer must be started before building URLs.")
        target_is_loopback = _is_loopback_host(target_switch_ip)
        if self.bind_host not in ("0.0.0.0", "::", ""):  # nosec B104
            if _is_loopback_host(self.bind_host) and not target_is_loopback:
                raise RuntimeError(
                    f"HTTP server is bound to loopback ({self.bind_host}) and unreachable from "
                    f"switch {target_switch_ip}."
                )
            host_ip = self.bind_host
        else:
            host_ip = detect_outbound_ip(
                target_switch_ip,
                allow_loopback_fallback=target_is_loopback,
            )
        host_fmt = f"[{host_ip}]" if ":" in host_ip and not host_ip.startswith("[") else host_ip
        quoted_rel = "/".join(quote(seg, safe="") for seg in rel_path.lstrip("/").split("/") if seg)
        return f"http://{host_fmt}:{self.port}/firmware/{self.token}/{quoted_rel}"


def resolve_local_firmware_file(
    firmware_dir: Path, policy: PlatformPolicy, hop: HopSpec
) -> Path | None:
    """Locate a hop .tgz strictly inside firmware_dir across canonical subpaths or flat folder."""
    safe_name = validate_package_filename(hop.package_filename)
    if not firmware_dir.exists():
        return None
    fw_root = firmware_dir.resolve()

    def _is_contained_file(path: Path) -> bool:
        try:
            if not path.is_file():
                return False
            resolved = path.resolve()
            return fw_root in resolved.parents
        except OSError:
            return False

    candidates = [
        firmware_dir / "juniper" / policy.family_dir / hop.train / safe_name,
        firmware_dir / policy.family_dir / hop.train / safe_name,
        firmware_dir / policy.family_dir / safe_name,
        firmware_dir / safe_name,
    ]
    for path in candidates:
        if _is_contained_file(path):
            return path
    for found in firmware_dir.rglob("*.tgz"):
        if found.name == safe_name and _is_contained_file(found):
            return found
    return None


def _is_usable_external_url(url: str) -> bool:
    clean = url.strip()
    if not clean or CLI_UNSAFE_RE.search(clean):
        return False
    parsed = urlparse(clean)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return False
    host = parsed.hostname.lower().rstrip(".")
    for placeholder in _PLACEHOLDER_DOMAINS:
        if host == placeholder or host.endswith(f".{placeholder}"):
            return False
    return True


def resolve_transfer_mode(
    transfer_mode: str,
    policy: PlatformPolicy,
    free_storage_mb: int | None,
    local_file: Path | None,
    external_base_url: str,
) -> str:
    """Resolve effective transfer mode consistently across stage and upgrade flows."""
    if transfer_mode not in VALID_TRANSFER_MODES:
        raise ValueError(
            f"Unsupported transfer_mode {transfer_mode!r}; "
            "expected one of: auto, http, http-stream, scp."
        )
    if transfer_mode != "auto":
        return transfer_mode
    has_external = _is_usable_external_url(external_base_url)
    if local_file is None and has_external:
        return "external-http"
    pkg_mb = (local_file.stat().st_size / (1024 * 1024)) if local_file else 350.0
    if policy.prefer_http_stream or (
        free_storage_mb is not None and free_storage_mb < int(pkg_mb * 1.8)
    ):
        return "http-stream"
    return "http-with-scp-fallback"


def _cleanup_remote_partial(transport: SwitchTransport, remote_pkg: str) -> None:
    try:
        transport.run_command(f"file delete {remote_pkg}", read_timeout=30)
    except Exception:  # noqa: BLE001
        pass


def stage_or_stream_package(
    transport: SwitchTransport,
    switch: SwitchRecord,
    policy: PlatformPolicy,
    hop: HopSpec,
    firmware_dir: Path,
    server: UnifiedFirmwareServer | None,
    external_base_url: str,
    transfer_mode: str = "auto",
) -> TransferOutcome:
    """Deliver firmware from the single local firmware_dir via HTTP stream, HTTP copy, or SCP."""
    safe_filename = validate_package_filename(hop.package_filename)
    local_file = resolve_local_firmware_file(firmware_dir, policy, hop)
    has_external = _is_usable_external_url(external_base_url)
    chosen = resolve_transfer_mode(
        transfer_mode=transfer_mode,
        policy=policy,
        free_storage_mb=switch.free_storage_mb,
        local_file=local_file,
        external_base_url=external_base_url,
    )

    local_url = ""
    if local_file is not None and server is not None:
        rel_path = local_file.resolve().relative_to(firmware_dir.resolve()).as_posix()
        local_url = server.build_http_url(switch.management_ip, rel_path)
    elif has_external:
        q_family = quote(policy.family_dir, safe="")
        q_train = quote(hop.train, safe="")
        q_pkg = quote(safe_filename, safe="")
        local_url = f"{external_base_url.strip().rstrip('/')}/juniper/{q_family}/{q_train}/{q_pkg}"
    elif local_file is None:
        raise FileNotFoundError(
            f"Firmware package {safe_filename} not found in {firmware_dir} "
            "(and no non-placeholder firmware_server_base_url is configured)."
        )

    if local_url:
        validate_cli_target(local_url, "firmware URL")

    if chosen == "http-stream":
        if not local_url:
            raise RuntimeError(
                f"HTTP streaming for {safe_filename} requires an active UnifiedFirmwareServer "
                "or a non-placeholder firmware_server_base_url."
            )
        return TransferOutcome(
            mode_used="http-stream",
            software_add_target=local_url,
            uses_no_copy=True,
            details=f"Streaming directly via HTTP (`no-copy unlink`) from {local_url}",
        )

    remote_pkg = validate_cli_target(
        f"/var/tmp/{safe_filename}",  # nosec B108
        "remote package path",
    )
    if local_url and chosen in ("http", "external-http", "http-with-scp-fallback"):
        http_err = ""
        try:
            copy_out = transport.run_command(
                f"file copy {local_url} {remote_pkg}", read_timeout=300
            )
            if not _http_copy_failed(copy_out):
                return TransferOutcome(
                    mode_used="http-copy",
                    software_add_target=remote_pkg,
                    uses_no_copy=False,
                    remote_staged_path=remote_pkg,
                    details=f"Copied via HTTP to {remote_pkg}",
                )
            http_err = copy_out.strip() or "empty response"
        except Exception as exc:  # noqa: BLE001
            http_err = str(exc)

        _cleanup_remote_partial(transport, remote_pkg)
        if chosen in ("http", "external-http") or local_file is None:
            raise RuntimeError(f"HTTP file copy failed for {local_url}: {http_err}")
    elif chosen in ("http", "external-http"):
        raise RuntimeError(
            f"HTTP copy mode selected for {safe_filename}, but no HTTP server or external URL is available."
        )

    if local_file is None:
        raise FileNotFoundError(
            f"Firmware package {safe_filename} not found in {firmware_dir} for SCP transfer."
        )

    try:
        transport.scp_put(local_file, remote_pkg)
    except Exception:
        _cleanup_remote_partial(transport, remote_pkg)
        raise
    return TransferOutcome(
        mode_used="scp",
        software_add_target=remote_pkg,
        uses_no_copy=False,
        remote_staged_path=remote_pkg,
        details=f"Pushed via direct SCP from {local_file} to {remote_pkg}",
    )
