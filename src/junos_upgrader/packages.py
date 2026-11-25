# SPDX-License-Identifier: AGPL-3.0-or-later
"""Package architecture inspection, integrity hashing, and switch-to-image match validation."""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import re
import tarfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from junos_upgrader.models import CheckResult, HopSpec, PlatformPolicy, SwitchRecord
from junos_upgrader.planner import is_safe_package_filename, parse_junos_version_key

_TGZ_VERSION_RE = re.compile(
    r"(\d+\.\d+(?:R\d+(?:[-.]S\d+(?:\.\d+)?|\.\d+)?(?:-J\d+)?|X\d+(?:[-.]D\d+(?:\.\d+)?)?(?:-J\d+)?))",
    re.IGNORECASE,
)
_MODEL_LINE_RE = re.compile(r"(?im)^\s*Model:\s*(\S+)")
_HOSTNAME_LINE_RE = re.compile(r"(?im)^\s*Hostname:.*$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_FILENAME_ARCH_PREFIXES: list[tuple[str, str]] = [
    ("junos-install-ex-arm-64", "arm-64"),
    ("junos-install-ex-x86-64", "x86-64"),
    ("jinstall-host-ex-4300mp", "x86-64-vmhost"),
    ("jinstall-ex-4300", "powerpc"),
    ("jinstall-host-qfx-5e", "qfx-5e"),
    ("jinstall-host-qfx-5", "qfx-5"),
    ("jinstall-host-ex-4650", "ex-4650"),
    ("junos-arm-32", "arm-32"),
    ("junos-evo-install", "junos-evo"),
]

_CHECKSUM_LENGTHS: dict[str, tuple[str, int]] = {
    "md5": ("md5", 32),
    "sha1": ("sha1", 40),
    "sha-1": ("sha1", 40),
    "sha256": ("sha256", 64),
    "sha-256": ("sha256", 64),
}


@dataclass
class PackageMetadata:
    """Inspected metadata for a local Junos .tgz installer package."""

    path: Path
    filename: str
    size_bytes: int
    md5: str
    sha256: str
    valid_tgz: bool
    detected_arch: str = ""
    detected_version: str = ""
    comment: str = ""
    errors: list[str] = field(default_factory=list)
    sha1: str = ""


def extract_switch_arch(version_output: str) -> str:
    """Extract running Junos hardware/kernel architecture from `show version` output."""
    text = version_output.strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
            if "multi-routing-engine-results" in data:
                re_results = data["multi-routing-engine-results"]
                re_entry = re_results[0] if isinstance(re_results, list) and re_results else {}
                items = (
                    re_entry.get("multi-routing-engine-item", [])
                    if isinstance(re_entry, dict)
                    else []
                )
                first_item = (
                    items[0]
                    if isinstance(items, list) and items
                    else (items if isinstance(items, dict) else {})
                )
                sw_node = (
                    first_item.get("software-information", [{}])
                    if isinstance(first_item, dict)
                    else [{}]
                )
                sw_info = (
                    sw_node[0]
                    if isinstance(sw_node, list) and sw_node
                    else (sw_node if isinstance(sw_node, dict) else {})
                )
            else:
                sw_node = data.get("software-information", [{}])
                sw_info = (
                    sw_node[0]
                    if isinstance(sw_node, list) and sw_node
                    else (sw_node if isinstance(sw_node, dict) else {})
                )
            prod = sw_info.get("product-model", [{}])
            model_node = (
                prod[0]
                if isinstance(prod, list) and prod
                else (prod if isinstance(prod, dict) else {})
            )
            model = str(model_node.get("data", "")).lower()
            raw_pkgs = sw_info.get("package-information", [])
            if isinstance(raw_pkgs, dict):
                raw_pkgs = [raw_pkgs]
            pkgs = " ".join(
                str(p.get("package-name", [{}])[0].get("data", ""))
                + " "
                + str(p.get("comment", [{}])[0].get("data", ""))
                for p in raw_pkgs
                if isinstance(p, dict)
            ).lower()
            return _classify_arch(model, pkgs)
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            pass

    model_match = _MODEL_LINE_RE.search(text)
    model_hint = model_match.group(1).lower() if model_match else ""
    pkg_hint = _HOSTNAME_LINE_RE.sub("", text).lower()
    return _classify_arch(model_hint, pkg_hint)


def _classify_arch(model_hint: str, pkg_hint: str) -> str:
    # 1. Evolved must always take precedence over classical Junos families
    if "junos-evo" in pkg_hint or "junos os evolved" in pkg_hint:
        return "junos-evo"
    # 2. Specific platform models & package prefixes before generic CPU/VMHost tokens
    if "qfx5120" in model_hint or "qfx5200" in model_hint or "qfx-5e" in pkg_hint:
        return "qfx-5e"
    if "ex4650" in model_hint or "ex-4650" in pkg_hint:
        return "ex-4650"
    if "ex4600" in model_hint or "qfx-5" in pkg_hint:
        return "qfx-5"
    if "ex4300-48mp" in model_hint or "ex-4300mp" in pkg_hint or "4300mp" in pkg_hint:
        return "x86-64-vmhost"
    if "ex4100" in model_hint or "arm-64" in pkg_hint:
        return "arm-64"
    if "ex2300" in model_hint or "ex3400" in model_hint or "arm-32" in pkg_hint:
        return "arm-32"
    if "ex4400" in model_hint or "ex-x86-64" in pkg_hint:
        return "x86-64"
    if "ex4300" in model_hint or "powerpc" in pkg_hint:
        return "powerpc"
    # 3. Generic runtime/CPU tokens only when no specific model/package family matched
    if "vmhost" in pkg_hint:
        return "x86-64-vmhost"
    if "x86-64" in pkg_hint or "amd64" in pkg_hint:
        return "x86-64"
    return "unknown"


def infer_arch_from_filename(filename: str) -> str:
    """Infer architecture family from Juniper package filename."""
    lower = filename.lower()
    for prefix, arch in _FILENAME_ARCH_PREFIXES:
        if lower.startswith(prefix + "-") or lower == prefix:
            return arch
    return "unknown"


def _validate_tar_member(member: tarfile.TarInfo) -> str | None:
    """Return an error message if a tar member poses a path traversal or device-node hazard."""
    name = member.name
    if not name:
        return "Tar archive contains empty member name."
    if name.startswith("/") or "\\" in name:
        return f"Unsafe tar member path {name!r} (absolute or backslash path)."
    parts = PurePosixPath(name).parts
    if ".." in parts:
        return f"Unsafe tar member path {name!r} (parent directory traversal)."
    if member.isdev() or member.isfifo():
        return f"Unsafe tar member {name!r} (device/FIFO special file not permitted)."
    if member.issym() or member.islnk():
        link = member.linkname
        if "\\" in link or ".." in PurePosixPath(link).parts:
            return f"Unsafe tar link target {name!r} -> {link!r}."
    return None


def inspect_local_tgz(path: Path) -> PackageMetadata:
    """Validate full gzip/tar archive structure, compute MD5/SHA1/SHA256, and extract arch/version."""
    meta = PackageMetadata(
        path=path,
        filename=path.name,
        size_bytes=0,
        md5="",
        sha256="",
        valid_tgz=False,
        detected_arch=infer_arch_from_filename(path.name),
        sha1="",
    )

    ver_match = _TGZ_VERSION_RE.search(path.name)
    if ver_match:
        meta.detected_version = ver_match.group(1)

    # Check readability and 2-byte gzip magic header before hashing large files
    try:
        meta.size_bytes = path.stat().st_size
        with path.open("rb") as fh:
            magic = fh.read(2)
    except OSError as exc:
        meta.errors.append(f"Unable to read package file {path}: {exc}")
        return meta

    if magic != b"\x1f\x8b":
        meta.errors.append(
            "File is not a valid gzip stream (likely HTML/error response or corrupt download)."
        )
        return meta

    # Compute MD5, SHA1, and SHA256 in a single streaming pass
    md5_h = hashlib.md5()
    sha1_h = hashlib.sha1()
    sha256_h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                md5_h.update(chunk)
                sha1_h.update(chunk)
                sha256_h.update(chunk)
    except OSError as exc:
        meta.errors.append(f"I/O error hashing package {path}: {exc}")
        return meta

    meta.md5 = md5_h.hexdigest()
    meta.sha1 = sha1_h.hexdigest()
    meta.sha256 = sha256_h.hexdigest()

    # Stream-decompress the entire gzip archive to EOF (verifying CRC32 + ISIZE)
    # and inspect all tar members without early break.
    try:
        with gzip.open(path, mode="rb") as gz:
            names: list[str] = []
            member_count = 0
            unsafe_errors: list[str] = []
            with tarfile.open(fileobj=gz, mode="r|") as tf:
                for member in tf:
                    member_count += 1
                    if len(names) < 100:
                        names.append(member.name)
                    hazard = _validate_tar_member(member)
                    if hazard and len(unsafe_errors) < 5:
                        unsafe_errors.append(hazard)
                    if not meta.comment and member.name.endswith("+COMMENT") and member.isfile():
                        extracted = tf.extractfile(member)
                        if extracted is not None:
                            meta.comment = (
                                extracted.read(2048).decode("utf-8", errors="replace").strip()
                            )
            # Drain remaining gzip bytes past tar EOF blocks so gzip verifies CRC32 & ISIZE
            while gz.read(1024 * 1024):
                pass

            if unsafe_errors:
                meta.errors.extend(unsafe_errors)
                meta.valid_tgz = False
                return meta

            joined = " ".join(names).lower() + " " + meta.comment.lower()
            if meta.detected_arch == "unknown":
                meta.detected_arch = _classify_arch(joined, joined)
            meta.valid_tgz = member_count > 0
            if member_count == 0:
                meta.errors.append("Archive contains zero tar entries.")
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        meta.errors.append(f"Corrupt .tgz archive: {exc}")
        meta.valid_tgz = False
    return meta


def validate_package_match(
    switch: SwitchRecord,
    policy: PlatformPolicy,
    hop: HopSpec,
    local_file: Path | None = None,
    chassis_firmware_out: str = "",
    allow_unverified_checksums: bool = False,
) -> list[CheckResult]:
    """Perform 4-way switch-to-package validation before transferring or installing."""
    results: list[CheckResult] = []

    # 1. Filename safety, format, and family prefix (requiring '-' delimiter to avoid qfx-5 vs qfx-5e collision)
    pkg_name = hop.package_filename.strip()
    pkg_lower = pkg_name.lower()
    safe_name = is_safe_package_filename(pkg_name)
    is_tgz = pkg_lower.endswith(".tgz")
    is_usb_media = "install-media" in pkg_lower or pkg_lower.endswith((".img", ".img.gz"))
    fam_lower = policy.package_family.strip().lower()
    prefix_ok = bool(fam_lower) and pkg_lower.startswith(fam_lower + "-")
    family_passed = safe_name and is_tgz and not is_usb_media and prefix_ok
    results.append(
        CheckResult(
            name="package_family_match",
            passed=family_passed,
            severity="info" if family_passed else "fail",
            message=(
                f"Package {hop.package_filename} matches family {policy.package_family}."
                if family_passed
                else (
                    f"Package mismatch: {hop.package_filename} does not match expected "
                    f"family {policy.package_family} (safe .tgz runtime/host package required)."
                )
            ),
        )
    )

    # 2. Live switch kernel architecture vs policy expected_arch (+ Evolved check)
    live_arch = switch.kernel_arch or "unknown"
    arch_ok = True
    arch_hard_stop = True
    arch_sev = "info"
    arch_msg = f"Switch architecture {live_arch} aligns with policy ({policy.expected_arch})."
    if live_arch == "junos-evo" and not pkg_lower.startswith("junos-evo"):
        arch_ok = False
        arch_sev = "fail"
        arch_msg = (
            f"CRITICAL MISMATCH: {switch.hostname} runs Junos OS Evolved (`junos-evo`), "
            f"cannot install classical package {hop.package_filename}."
        )
    elif live_arch == "unknown":
        arch_ok = True
        arch_hard_stop = False
        arch_sev = "warn"
        arch_msg = (
            f"Switch architecture is unknown for {switch.hostname} ({switch.model}); "
            f"cannot verify against policy ({policy.expected_arch})."
        )
    elif policy.expected_arch and live_arch != policy.expected_arch:
        arch_ok = False
        arch_sev = "fail"
        arch_msg = (
            f"CRITICAL ARCH MISMATCH: {switch.hostname} ({switch.model}) reports arch "
            f"{live_arch!r}, but policy expects {policy.expected_arch!r}!"
        )
    results.append(
        CheckResult(
            name="switch_arch_match",
            passed=arch_ok,
            hard_stop=arch_hard_stop,
            severity=arch_sev,
            message=arch_msg,
        )
    )

    # 3. Multi-Gig (-MP) & platform advisories
    is_mgig = "-mp" in switch.model.lower()
    if is_mgig or policy.known_advisories:
        adv_text = "; ".join(policy.known_advisories)
        if is_mgig and chassis_firmware_out:
            adv_text += " [chassis firmware captured]"
        results.append(
            CheckResult(
                name="platform_mgig_advisory",
                passed=True,
                hard_stop=False,
                severity="warn" if is_mgig else "info",
                message=adv_text or f"Multi-gig checks noted for {switch.model}.",
            )
        )

    # 4. Local file integrity, embedded arch, version match, and manifest checksum check
    if local_file is None:
        results.append(
            CheckResult(
                name="local_tgz_present",
                passed=False,
                hard_stop=False,
                severity="warn",
                message=(
                    f"Local package {hop.package_filename} not found in firmware directory "
                    "(run `junos-upgrader firmware scan` before staging/upgrading)."
                ),
            )
        )
    else:
        meta = inspect_local_tgz(local_file)
        if not meta.valid_tgz:
            results.append(
                CheckResult(
                    name="local_tgz_integrity",
                    passed=False,
                    hard_stop=True,
                    severity="fail",
                    message=f"Invalid local package {local_file}: {'; '.join(meta.errors)}",
                )
            )
        else:
            arch_unknown = meta.detected_arch == "unknown"
            inner_arch_ok = (
                arch_unknown
                or not policy.expected_arch
                or meta.detected_arch == policy.expected_arch
            )

            # Verify embedded/filename version matches hop.target_version when present
            version_ok = True
            if meta.detected_version and hop.target_version:
                try:
                    version_ok = parse_junos_version_key(
                        meta.detected_version
                    ) == parse_junos_version_key(hop.target_version)
                except ValueError:
                    version_ok = (
                        meta.detected_version.strip().lower() == hop.target_version.strip().lower()
                    )

            # Resolve supported checksum algorithm
            chk_key = hop.checksum_type.strip().lower()
            algo_spec = _CHECKSUM_LENGTHS.get(chk_key)
            if algo_spec is None:
                results.append(
                    CheckResult(
                        name="local_tgz_integrity",
                        passed=False,
                        hard_stop=True,
                        severity="fail",
                        message=(
                            f"Unsupported checksum_type {hop.checksum_type!r} for "
                            f"{hop.package_filename} (supported: md5, sha1, sha256/sha-256)."
                        ),
                    )
                )
                return results

            attr_name, expected_len = algo_spec
            actual_hash = str(getattr(meta, attr_name))
            expected_chk = hop.checksum.strip()
            is_placeholder = (not expected_chk) or ("REPLACE" in expected_chk.upper())

            if not inner_arch_ok or not version_ok:
                results.append(
                    CheckResult(
                        name="local_tgz_integrity",
                        passed=False,
                        hard_stop=True,
                        severity="fail",
                        message=(
                            f"Local package validation failed: arch_ok={inner_arch_ok} "
                            f"({meta.detected_arch} vs {policy.expected_arch}), "
                            f"version_ok={version_ok} "
                            f"({meta.detected_version} vs {hop.target_version})"
                        ),
                    )
                )
            elif is_placeholder:
                if allow_unverified_checksums:
                    arch_note = " (archive arch unknown)" if arch_unknown else ""
                    results.append(
                        CheckResult(
                            name="local_tgz_integrity",
                            passed=True,
                            hard_stop=False,
                            severity="warn",
                            message=(
                                f"UNVERIFIED: placeholder checksum skipped for {meta.filename} "
                                f"({meta.size_bytes // (1024 * 1024)} MB, "
                                f"{hop.checksum_type}={actual_hash}){arch_note}."
                            ),
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            name="local_tgz_integrity",
                            passed=False,
                            hard_stop=True,
                            severity="fail",
                            message=(
                                f"Unverified placeholder/empty checksum for {hop.package_filename} "
                                "(populate manifest checksum via `junos-upgrader firmware scan` or "
                                "pass --allow-unverified-checksums)."
                            ),
                        )
                    )
            else:
                format_ok = len(expected_chk) == expected_len and bool(
                    _HEX_RE.fullmatch(expected_chk)
                )
                hash_ok = format_ok and hmac.compare_digest(
                    actual_hash.lower(), expected_chk.lower()
                )
                if not hash_ok:
                    results.append(
                        CheckResult(
                            name="local_tgz_integrity",
                            passed=False,
                            hard_stop=True,
                            severity="fail",
                            message=(
                                f"Local package checksum mismatch for {meta.filename}: "
                                f"got {hop.checksum_type}={actual_hash}, "
                                f"expected {expected_chk!r} (expected {expected_len}-char hex)."
                            ),
                        )
                    )
                elif arch_unknown:
                    results.append(
                        CheckResult(
                            name="local_tgz_integrity",
                            passed=True,
                            hard_stop=False,
                            severity="warn",
                            message=(
                                f"Verified local .tgz checksum ({meta.size_bytes // (1024 * 1024)} MB, "
                                f"{hop.checksum_type}={actual_hash}), but archive architecture is unknown."
                            ),
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            name="local_tgz_integrity",
                            passed=True,
                            hard_stop=True,
                            severity="info",
                            message=(
                                f"Verified local .tgz ({meta.size_bytes // (1024 * 1024)} MB, "
                                f"{hop.checksum_type}={actual_hash})."
                            ),
                        )
                    )

    return results
