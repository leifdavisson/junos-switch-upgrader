# SPDX-License-Identifier: AGPL-3.0-or-later
"""Release train parsing, glob-based platform matching, and multi-hop upgrade planning."""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from junos_upgrader.models import HopSpec, PlatformPolicy, SwitchRecord, SwitchState

_JUNOS_R_RE = re.compile(
    r"^(\d+)\.(\d+)(?:R(\d+)(?:[-.]S(\d+)(?:\.(\d+))?|[-.](\d+))?(?:-J(\d+))?)?$",
    re.IGNORECASE,
)
_JUNOS_X_RE = re.compile(
    r"^(\d+)\.(\d+)X(\d+)(?:[-.]D(\d+)(?:\.(\d+))?)?(?:-J(\d+))?$",
    re.IGNORECASE,
)
_SAFE_PACKAGE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.tgz$")


def is_safe_package_filename(filename: str) -> bool:
    """Return True if filename is a safe .tgz basename with no traversal or shell characters."""
    if not isinstance(filename, str) or not filename or ".." in filename:
        return False
    return bool(_SAFE_PACKAGE_FILENAME_RE.fullmatch(filename))


def parse_junos_train(version: str) -> tuple[int, int]:
    """Extract (major, minor) train tuple from a Junos version string.

    Examples:
        '18.1R3-S4.2' -> (18, 1)
        '23.4R2.13'   -> (23, 4)
        '23.4R2-S8'   -> (23, 4)
        '15.1X53-D59' -> (15, 1)
    """
    key = parse_junos_version_key(version)
    return key[0], key[1]


def parse_junos_version_key(version: str) -> tuple[int, int, int, int, int, int, int]:
    """Return a sortable key for classical Junos versions.

    Key layout: (major, minor, branch_kind, branch_num, service_num, maint_num, j_respin)
      - branch_kind: 0 = train-only ('23.4'), 1 = X-release ('15.1X53-D59'), 2 = R-release
    Raises ValueError on unrecognized formats, trailing garbage, or Junos OS Evolved (-EVO).
    """
    if not isinstance(version, str):
        raise ValueError(f"Junos version must be a string, got {type(version).__name__}")
    clean = version.strip()
    if not clean:
        raise ValueError(f"Unrecognized Junos version format: {version!r}")
    if "-evo" in clean.lower():
        raise ValueError(
            f"Junos OS Evolved (-EVO) version is not supported by classical planner: {version!r}"
        )

    m_r = _JUNOS_R_RE.fullmatch(clean)
    if m_r:
        major = int(m_r.group(1))
        minor = int(m_r.group(2))
        has_r = m_r.group(3) is not None
        branch_kind = 2 if has_r else 0
        r_num = int(m_r.group(3) or 0)
        s_num = int(m_r.group(4) or 0)
        sub_s = int(m_r.group(5) or 0)
        dot_maint = int(m_r.group(6) or 0)
        j_num = int(m_r.group(7) or 0)
        return (major, minor, branch_kind, r_num, s_num, sub_s or dot_maint, j_num)

    m_x = _JUNOS_X_RE.fullmatch(clean)
    if m_x:
        major = int(m_x.group(1))
        minor = int(m_x.group(2))
        x_num = int(m_x.group(3))
        d_num = int(m_x.group(4) or 0)
        sub_d = int(m_x.group(5) or 0)
        j_num = int(m_x.group(6) or 0)
        return (major, minor, 1, x_num, d_num, sub_d, j_num)

    raise ValueError(f"Unrecognized Junos version format: {version!r}")


def estimate_train_gap(train_a: tuple[int, int], train_b: tuple[int, int]) -> int:
    """Estimate quarterly Junos release distance between two (major, minor) trains."""
    return ((train_b[0] - train_a[0]) * 4) + (train_b[1] - train_a[1])


def _coerce_required_str(mapping: dict[str, Any], key: str, *, context: str) -> str:
    val = mapping.get(key)
    if val is None or isinstance(val, (bool, list, dict)):
        raise ValueError(f"Missing or invalid {key!r} in {context}")
    text = str(val).strip()
    if not text:
        raise ValueError(f"Empty {key!r} in {context}")
    return text


def _parse_hops(raw_hops: Any, manifest_bleeding: bool = False) -> list[HopSpec]:
    if raw_hops is None:
        return []
    if not isinstance(raw_hops, list):
        raise ValueError(f"Expected 'hops' to be a list, got {type(raw_hops).__name__}")

    parsed: list[HopSpec] = []
    for idx, h in enumerate(raw_hops):
        if not isinstance(h, dict):
            raise ValueError(f"Hop entry #{idx} must be a mapping, got {type(h).__name__}")
        ctx = f"hop #{idx}"
        train = _coerce_required_str(h, "train", context=ctx)
        target_version = _coerce_required_str(h, "target_version", context=ctx)
        package_filename = _coerce_required_str(h, "package_filename", context=ctx)
        checksum = _coerce_required_str(h, "checksum", context=ctx)

        # Validate version formats and safe package basename upfront
        parse_junos_train(train)
        parse_junos_version_key(target_version)
        if not is_safe_package_filename(package_filename):
            raise ValueError(
                f"Unsafe package_filename {package_filename!r} in {ctx} "
                "(must match ^[A-Za-z0-9][A-Za-z0-9._-]*\\.tgz$ without '..')."
            )

        checksum_type = str(h.get("checksum_type") or "md5").strip()
        raw_opts = h.get("install_options", [])
        if raw_opts is None:
            raw_opts = []
        if not isinstance(raw_opts, list):
            raise ValueError(f"'install_options' in {ctx} must be a list")
        install_options = [str(o).strip() for o in raw_opts if str(o).strip()]

        parsed.append(
            HopSpec(
                train=train,
                target_version=target_version,
                package_filename=package_filename,
                checksum_type=checksum_type,
                checksum=checksum,
                install_options=install_options,
                release_notes_reviewed=bool(h.get("release_notes_reviewed", False)),
                bleeding_edge=bool(h.get("bleeding_edge", manifest_bleeding)),
                notes=str(h.get("notes") or ""),
            )
        )
    return parsed


def load_release_catalog(
    manifest_path: Path,
) -> tuple[str, list[PlatformPolicy], list[dict[str, str]]]:
    """Load approved-releases.yml into ordered platform policies and exclusion rules."""
    raw: Any = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(
            f"Invalid release manifest {manifest_path}: expected top-level YAML mapping."
        )

    base_url = str(
        raw.get("firmware_server_base_url") or "http://firmware-cache.example.internal"
    ).rstrip("/")
    manifest_bleeding = bool(raw.get("bleeding_edge", False))
    platforms_raw = raw.get("platforms")

    items: list[dict[str, Any]] = []
    if platforms_raw is None:
        items = []
    elif isinstance(platforms_raw, list):
        for idx, entry in enumerate(platforms_raw):
            if not isinstance(entry, dict):
                raise ValueError(f"Platform entry #{idx} must be a mapping")
            items.append(entry)
    elif isinstance(platforms_raw, dict):
        for k, v in platforms_raw.items():
            if not isinstance(v, dict):
                raise ValueError(f"Platform entry {k!r} must be a mapping")
            items.append({"model_pattern": str(k), **v})
    else:
        raise ValueError(
            f"Expected 'platforms' to be a list or mapping, got {type(platforms_raw).__name__}"
        )

    policies: list[PlatformPolicy] = []
    for idx, cfg in enumerate(items):
        ctx = f"platform #{idx}"
        model_pattern = _coerce_required_str(cfg, "model_pattern", context=ctx).lower()
        final_target = _coerce_required_str(cfg, "final_target", context=ctx)
        parse_junos_version_key(final_target)

        min_free = int(cfg.get("min_free_storage_mb", 600))
        boot_timeout = int(cfg.get("boot_timeout_seconds", 600))
        if min_free < 0:
            raise ValueError(f"min_free_storage_mb must be >= 0 in {ctx}")
        if boot_timeout <= 0:
            raise ValueError(f"boot_timeout_seconds must be > 0 in {ctx}")

        raw_advisories = cfg.get("known_advisories", [])
        if raw_advisories is None:
            raw_advisories = []
        if not isinstance(raw_advisories, list):
            raise ValueError(f"known_advisories must be a list in {ctx}")

        plat_bleeding = bool(cfg.get("bleeding_edge", manifest_bleeding))
        policies.append(
            PlatformPolicy(
                model_pattern=model_pattern,
                vendor=str(cfg.get("vendor") or "juniper"),
                role_scope=str(cfg.get("role_scope") or "access"),
                final_target=final_target,
                package_family=str(cfg.get("package_family") or ""),
                expected_arch=str(cfg.get("expected_arch") or ""),
                min_free_storage_mb=min_free,
                boot_timeout_seconds=boot_timeout,
                prefer_http_stream=bool(cfg.get("prefer_http_stream", False)),
                download_portal_slug=str(cfg.get("download_portal_slug") or ""),
                bleeding_edge=plat_bleeding,
                jtac_baseline=str(cfg.get("jtac_baseline") or ""),
                known_advisories=[str(a) for a in raw_advisories],
                hops=_parse_hops(cfg.get("hops", []), manifest_bleeding=plat_bleeding),
                notes=str(cfg.get("notes") or ""),
            )
        )

    exclusions_raw = raw.get("excluded_families")
    if exclusions_raw is None:
        exclusions: list[dict[str, str]] = []
    elif isinstance(exclusions_raw, list):
        exclusions = []
        for idx, rule in enumerate(exclusions_raw):
            if not isinstance(rule, dict):
                raise ValueError(f"excluded_families entry #{idx} must be a mapping")
            exclusions.append({str(k): str(v) for k, v in rule.items() if v is not None})
    else:
        raise ValueError(
            f"Expected 'excluded_families' to be a list, got {type(exclusions_raw).__name__}"
        )

    return base_url, policies, exclusions


def match_platform_policy(model: str, policies: list[PlatformPolicy]) -> PlatformPolicy | None:
    """Return the first matching PlatformPolicy using case-insensitive glob matching."""
    model_norm = model.strip().lower()
    for policy in policies:
        if fnmatchcase(model_norm, policy.model_pattern.lower()):
            return policy
    return None


def compute_remaining_hops(current_version: str, policy: PlatformPolicy) -> list[HopSpec]:
    """Return ordered list of hops needed to move from current_version to final_target."""
    cur_str = current_version.strip()
    final_str = policy.final_target.strip()

    cur_train = parse_junos_train(cur_str)
    final_train = parse_junos_train(final_str)
    cur_key = parse_junos_version_key(cur_str)
    final_key = parse_junos_version_key(final_str)

    if cur_str.lower() == final_str.lower() or cur_train > final_train or cur_key >= final_key:
        return []

    by_train: dict[tuple[int, int], tuple[tuple[int, ...], HopSpec]] = {}
    ordered_trains: list[tuple[int, int]] = []

    for hop in policy.hops:
        hop_target = hop.target_version.strip()
        hop_train = parse_junos_train(hop.train)
        hop_key = parse_junos_version_key(hop_target)

        # Never schedule hops beyond final_target
        if hop_key > final_key:
            continue

        include = False
        if cur_train < hop_train:
            include = True
        elif cur_train == hop_train and cur_key < hop_key and hop_key == final_key:
            # Intra-train service upgrade (e.g. 23.4R2.13 -> 23.4R2-S8)
            include = True

        if include:
            existing = by_train.get(hop_train)
            if existing is None:
                ordered_trains.append(hop_train)
                by_train[hop_train] = (hop_key, hop)
            elif hop_key > existing[0]:
                # Keep the highest target within the same train to avoid redundant reboots
                by_train[hop_train] = (hop_key, hop)

    return [by_train[t][1] for t in ordered_trains]


def is_excluded_model(model: str, exclusions: list[dict[str, str]]) -> str | None:
    """Return exclusion policy reason if model matches an excluded/EOL family glob."""
    model_lower = model.strip().lower()
    for rule in exclusions:
        pattern = rule.get("pattern", "").strip().lower()
        if not pattern:
            continue
        if any(ch in pattern for ch in "*?["):
            matched = fnmatchcase(model_lower, pattern)
        else:
            matched = pattern in model_lower
        if matched:
            return rule.get("policy", "Excluded by policy.")
    return None


def refresh_switch_plan(
    switch: SwitchRecord,
    policies: list[PlatformPolicy],
    exclusions: list[dict[str, str]],
) -> SwitchRecord:
    """Update switch's final_target, next_hop, and exclusion/completion state."""
    reason = is_excluded_model(switch.model, exclusions)
    if reason:
        switch.state = SwitchState.EXCLUDED
        switch.exclusion_reason = reason
        switch.last_error = ""
        switch.final_target = "RETAIN"
        switch.next_hop = ""
        return switch

    policy = match_platform_policy(switch.model, policies)
    if not policy:
        switch.state = SwitchState.NOT_READY
        switch.exclusion_reason = ""
        switch.last_error = f"No upgrade policy defined for model {switch.model!r}"
        return switch

    switch.final_target = policy.final_target
    if not switch.role:
        switch.role = policy.role_scope.capitalize()

    try:
        hops = compute_remaining_hops(switch.current_version, policy)
        cur_key = parse_junos_version_key(switch.current_version)
        final_key = parse_junos_version_key(policy.final_target)
    except ValueError as exc:
        switch.next_hop = ""
        if switch.state not in (
            SwitchState.REPLACE_RECOMMENDED,
            SwitchState.FAILED,
            SwitchState.ANCESTOR_HOLD,
        ):
            switch.state = SwitchState.NOT_READY
        switch.last_error = f"Unparseable Junos version {switch.current_version!r}: {exc}"
        return switch

    protected_states = (
        SwitchState.REPLACE_RECOMMENDED,
        SwitchState.FAILED,
        SwitchState.ANCESTOR_HOLD,
    )
    if not hops:
        switch.next_hop = ""
        if cur_key >= final_key:
            if switch.state not in protected_states:
                switch.state = SwitchState.COMPLETED
                switch.exclusion_reason = ""
        else:
            if switch.state not in protected_states:
                switch.state = SwitchState.NOT_READY
            switch.last_error = (
                f"No upgrade hop path defined from {switch.current_version!r} "
                f"to {policy.final_target!r}"
            )
    else:
        switch.next_hop = hops[0].target_version
        if switch.state in (
            SwitchState.COMPLETED,
            SwitchState.EXCLUDED,
            SwitchState.NOT_READY,
        ):
            switch.state = SwitchState.READY
            switch.exclusion_reason = ""
            switch.last_error = ""
    return switch
