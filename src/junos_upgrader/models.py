# SPDX-License-Identifier: AGPL-3.0-or-later
"""Data models for switch inventory, topology dependencies, hardware triage, and upgrade state."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_UNSAFE_FAMILY_TOKENS = ("/", "\\", "..", "?", "[", "]", "\x00")


def validate_safe_path_segment(value: str, field_name: str = "value") -> str:
    """Validate that a string is safe to use as a single filesystem path segment."""
    clean = value.strip()
    if not clean or clean in (".", "..") or not _SAFE_SEGMENT_RE.match(clean):
        raise ValueError(f"Unsafe {field_name} for path construction: {value!r}")
    return clean


def sanitize_path_segment(value: str, fallback: str = "unknown") -> str:
    """Sanitize an untrusted string into a safe single filesystem path segment."""
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    clean = clean.replace("..", "_")
    clean = re.sub(r"_+", "_", clean).strip("._")
    return clean if clean and clean not in (".", "..") else fallback


def ensure_within_directory(base_dir: Path, target: Path) -> Path:
    """Verify that target resolves inside base_dir to prevent path traversal."""
    resolved_base = base_dir.resolve()
    resolved_target = target.resolve()
    if not resolved_target.is_relative_to(resolved_base):
        raise ValueError(f"Resolved path {resolved_target} escapes base directory {resolved_base}")
    return target


class SwitchState(str, Enum):
    """Lifecycle states for controlled site-scale switch upgrades."""

    NOT_READY = "not-ready"
    READY = "ready"
    STAGED = "staged"
    DOWNLOADED = "downloaded"
    INSTALLING = "installing"
    REBOOTING = "rebooting"
    VALIDATED = "validated"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled-back"
    FAILED = "failed"
    EXCLUDED = "excluded"
    REPLACE_RECOMMENDED = "replace-recommended"
    ANCESTOR_HOLD = "ancestor-hold"


class TriageVerdict(str, Enum):
    """Hardware & filesystem pre-flight triage outcome."""

    ELIGIBLE = "eligible"
    NEEDS_REMEDIATION = "needs-remediation"
    REPLACE_RECOMMENDED = "replace-recommended"


class CheckSeverity(str, Enum):
    """Severity level for pre-check, package validation, triage, and post-check results."""

    INFO = "info"
    WARN = "warn"
    REPLACE = "replace"
    FAIL = "fail"


_VALID_TRIAGE_VERDICTS = {v.value for v in TriageVerdict}
_VALID_CHECK_SEVERITIES = {s.value for s in CheckSeverity}


@dataclass
class HopSpec:
    """Single approved firmware hop for a platform."""

    train: str
    target_version: str
    package_filename: str
    checksum_type: str
    checksum: str
    install_options: list[str] = field(default_factory=list)
    release_notes_reviewed: bool = False
    bleeding_edge: bool = False
    notes: str = ""


@dataclass
class PlatformPolicy:
    """Upgrade policy and hop sequence matched by hardware model glob."""

    model_pattern: str
    vendor: str
    role_scope: str
    final_target: str
    package_family: str
    expected_arch: str
    min_free_storage_mb: int
    boot_timeout_seconds: int
    prefer_http_stream: bool = False
    download_portal_slug: str = ""
    bleeding_edge: bool = False
    jtac_baseline: str = ""
    known_advisories: list[str] = field(default_factory=list)
    hops: list[HopSpec] = field(default_factory=list)
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.model_pattern or not self.model_pattern.strip():
            raise ValueError("PlatformPolicy.model_pattern must not be empty")
        if self.min_free_storage_mb < 0:
            raise ValueError(
                f"PlatformPolicy.min_free_storage_mb must be >= 0, got {self.min_free_storage_mb}"
            )
        if self.boot_timeout_seconds <= 0:
            raise ValueError(
                f"PlatformPolicy.boot_timeout_seconds must be > 0, got {self.boot_timeout_seconds}"
            )

    @property
    def family_dir(self) -> str:
        """Canonical directory slug derived from pattern (e.g. 'ex3400', 'ex4300-48mp')."""
        raw = self.model_pattern.strip().lower()
        if any(tok in raw for tok in _UNSAFE_FAMILY_TOKENS):
            raise ValueError(
                f"Unsafe model_pattern for family_dir derivation: {self.model_pattern!r}"
            )
        slug = re.sub(r"[^a-z0-9_-]+", "-", raw.replace("*", ""))
        slug = re.sub(r"-{2,}", "-", slug).strip("-")
        if not slug or slug in (".", ".."):
            raise ValueError(
                f"Cannot derive valid family_dir from model_pattern: {self.model_pattern!r}"
            )
        return slug


@dataclass
class NeighborExpectation:
    """Expected LLDP/physical link to a neighboring device."""

    local_port: str
    remote_device: str
    remote_port: str
    remote_ip: str = ""
    remote_mac: str = ""
    is_upstream: bool = False


def _req_str(data: dict[str, Any], key: str) -> str:
    if key not in data or data[key] is None:
        raise ValueError(f"Missing required switch field {key!r}")
    if not isinstance(data[key], str):
        raise ValueError(f"Switch field {key!r} must be a string, got {type(data[key]).__name__}")
    return data[key]


def _opt_str(data: dict[str, Any], key: str, default: str = "") -> str:
    val = data.get(key)
    if val is None:
        return default
    return str(val)


def _opt_str_list(data: dict[str, Any], key: str) -> list[str]:
    val = data.get(key)
    if val is None:
        return []
    if not isinstance(val, list):
        raise ValueError(f"Switch field {key!r} must be a list, got {type(val).__name__}")
    return [str(item) for item in val]


def _parse_optional_int(val: Any, field_name: str) -> int | None:
    if val is None:
        return None
    if isinstance(val, bool):
        raise ValueError(f"Switch field {field_name!r} must be an integer, not bool")
    if isinstance(val, int):
        return val
    if isinstance(val, str) and val.strip():
        try:
            return int(val.strip())
        except ValueError as exc:
            raise ValueError(
                f"Switch field {field_name!r} is not a valid integer: {val!r}"
            ) from exc
    raise ValueError(f"Switch field {field_name!r} must be an integer or null, got {val!r}")


@dataclass
class SwitchRecord:
    """Per-switch manifest, topology, hardware triage, and upgrade state record."""

    site: str
    hostname: str
    management_ip: str
    model: str
    serial_number: str
    current_version: str
    role: str
    management_method: str
    mac_address: str = ""
    kernel_arch: str = ""
    final_target: str = ""
    next_hop: str = ""
    state: SwitchState = SwitchState.NOT_READY
    triage_verdict: str = ""
    triage_reasons: list[str] = field(default_factory=list)
    free_storage_mb: int | None = None
    tmpfs_free_mb: int | None = None
    recovery_snapshot: str = ""
    topology_depth: int = 0
    upstream_switch: str = ""
    upstream_local_port: str = ""
    upstream_remote_port: str = ""
    downstream_switches: list[str] = field(default_factory=list)
    console_port: str = ""
    previous_partition: str = ""
    backup_filename: str = ""
    staged_package: str = ""
    staged_checksum: str = ""
    change_number: str = ""
    operator: str = ""
    last_updated: str = ""
    exclusion_reason: str = ""
    last_error: str = ""
    expected_neighbors: list[NeighborExpectation] = field(default_factory=list)
    hop_history: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.hostname = validate_safe_path_segment(self.hostname, "hostname")
        if self.site:
            self.site = validate_safe_path_segment(self.site, "site")
        if isinstance(self.state, str) and not isinstance(self.state, SwitchState):
            self.state = SwitchState(self.state.strip().lower())
        if self.triage_verdict and self.triage_verdict not in _VALID_TRIAGE_VERDICTS:
            raise ValueError(f"Invalid triage_verdict: {self.triage_verdict!r}")
        if self.free_storage_mb is not None and (
            isinstance(self.free_storage_mb, bool) or not isinstance(self.free_storage_mb, int)
        ):
            raise ValueError(f"free_storage_mb must be int or None, got {self.free_storage_mb!r}")
        if self.tmpfs_free_mb is not None and (
            isinstance(self.tmpfs_free_mb, bool) or not isinstance(self.tmpfs_free_mb, int)
        ):
            raise ValueError(f"tmpfs_free_mb must be int or None, got {self.tmpfs_free_mb!r}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize record to a JSON-compatible deep-copied dictionary."""
        return {
            "site": self.site,
            "hostname": self.hostname,
            "management_ip": self.management_ip,
            "model": self.model,
            "serial_number": self.serial_number,
            "current_version": self.current_version,
            "role": self.role,
            "management_method": self.management_method,
            "mac_address": self.mac_address,
            "kernel_arch": self.kernel_arch,
            "final_target": self.final_target,
            "next_hop": self.next_hop,
            "state": self.state.value,
            "triage_verdict": self.triage_verdict,
            "triage_reasons": list(self.triage_reasons),
            "free_storage_mb": self.free_storage_mb,
            "tmpfs_free_mb": self.tmpfs_free_mb,
            "recovery_snapshot": self.recovery_snapshot,
            "topology_depth": self.topology_depth,
            "upstream_switch": self.upstream_switch,
            "upstream_local_port": self.upstream_local_port,
            "upstream_remote_port": self.upstream_remote_port,
            "downstream_switches": list(self.downstream_switches),
            "console_port": self.console_port,
            "previous_partition": self.previous_partition,
            "backup_filename": self.backup_filename,
            "staged_package": self.staged_package,
            "staged_checksum": self.staged_checksum,
            "change_number": self.change_number,
            "operator": self.operator,
            "last_updated": self.last_updated,
            "exclusion_reason": self.exclusion_reason,
            "last_error": self.last_error,
            "expected_neighbors": [
                {
                    "local_port": n.local_port,
                    "remote_device": n.remote_device,
                    "remote_port": n.remote_port,
                    "remote_ip": n.remote_ip,
                    "remote_mac": n.remote_mac,
                    "is_upstream": n.is_upstream,
                }
                for n in self.expected_neighbors
            ],
            "hop_history": [copy.deepcopy(entry) for entry in self.hop_history],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SwitchRecord:
        """Deserialize record from dictionary with schema validation and deep copying."""
        if not isinstance(data, dict):
            raise ValueError(f"Switch record must be a dict, got {type(data).__name__}")

        raw_neighbors = data.get("expected_neighbors")
        if raw_neighbors is None:
            raw_neighbors = []
        if not isinstance(raw_neighbors, list):
            raise ValueError(
                f"Switch field 'expected_neighbors' must be a list, got {type(raw_neighbors).__name__}"
            )
        neighbors: list[NeighborExpectation] = []
        for idx, n in enumerate(raw_neighbors):
            if not isinstance(n, dict):
                raise ValueError(f"expected_neighbors[{idx}] must be a dict")
            neighbors.append(
                NeighborExpectation(
                    local_port=_req_str(n, "local_port"),
                    remote_device=_req_str(n, "remote_device"),
                    remote_port=_req_str(n, "remote_port"),
                    remote_ip=_opt_str(n, "remote_ip"),
                    remote_mac=_opt_str(n, "remote_mac"),
                    is_upstream=bool(n.get("is_upstream", False)),
                )
            )

        raw_history = data.get("hop_history")
        if raw_history is None:
            raw_history = []
        if not isinstance(raw_history, list):
            raise ValueError(
                f"Switch field 'hop_history' must be a list, got {type(raw_history).__name__}"
            )
        hop_history: list[dict[str, Any]] = []
        for idx, entry in enumerate(raw_history):
            if not isinstance(entry, dict):
                raise ValueError(f"hop_history[{idx}] must be a dict")
            hop_history.append(copy.deepcopy(entry))

        raw_state = data.get("state")
        state = (
            SwitchState.NOT_READY
            if raw_state is None or str(raw_state).strip() == ""
            else SwitchState(str(raw_state).strip().lower())
        )

        raw_depth = data.get("topology_depth")
        depth = 0 if raw_depth is None else _parse_optional_int(raw_depth, "topology_depth")
        assert depth is not None

        role = _opt_str(data, "role", "Access").strip() or "Access"
        mgmt_method = _opt_str(data, "management_method", "SSH").strip() or "SSH"

        return cls(
            site=_req_str(data, "site"),
            hostname=_req_str(data, "hostname"),
            management_ip=_req_str(data, "management_ip"),
            model=_req_str(data, "model"),
            serial_number=_req_str(data, "serial_number"),
            current_version=_req_str(data, "current_version"),
            role=role,
            management_method=mgmt_method,
            mac_address=_opt_str(data, "mac_address"),
            kernel_arch=_opt_str(data, "kernel_arch"),
            final_target=_opt_str(data, "final_target"),
            next_hop=_opt_str(data, "next_hop"),
            state=state,
            triage_verdict=_opt_str(data, "triage_verdict"),
            triage_reasons=_opt_str_list(data, "triage_reasons"),
            free_storage_mb=_parse_optional_int(data.get("free_storage_mb"), "free_storage_mb"),
            tmpfs_free_mb=_parse_optional_int(data.get("tmpfs_free_mb"), "tmpfs_free_mb"),
            recovery_snapshot=_opt_str(data, "recovery_snapshot"),
            topology_depth=depth,
            upstream_switch=_opt_str(data, "upstream_switch"),
            upstream_local_port=_opt_str(data, "upstream_local_port"),
            upstream_remote_port=_opt_str(data, "upstream_remote_port"),
            downstream_switches=_opt_str_list(data, "downstream_switches"),
            console_port=_opt_str(data, "console_port"),
            previous_partition=_opt_str(data, "previous_partition"),
            backup_filename=_opt_str(data, "backup_filename"),
            staged_package=_opt_str(data, "staged_package"),
            staged_checksum=_opt_str(data, "staged_checksum"),
            change_number=_opt_str(data, "change_number"),
            operator=_opt_str(data, "operator"),
            last_updated=_opt_str(data, "last_updated"),
            exclusion_reason=_opt_str(data, "exclusion_reason"),
            last_error=_opt_str(data, "last_error"),
            expected_neighbors=neighbors,
            hop_history=hop_history,
        )


@dataclass
class CheckResult:
    """Result of a single pre-check, package validation, hardware triage, or post-check gate."""

    name: str
    passed: bool
    message: str
    hard_stop: bool = True
    severity: str = CheckSeverity.INFO.value  # info | warn | replace | fail
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.severity, CheckSeverity):
            self.severity = self.severity.value
        elif self.severity not in _VALID_CHECK_SEVERITIES:
            raise ValueError(f"Invalid CheckResult.severity: {self.severity!r}")
