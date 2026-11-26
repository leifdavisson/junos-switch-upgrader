# SPDX-License-Identifier: AGPL-3.0-or-later
"""Firmware shopping-list generation, directory scanning/ingestion, and portal assistance."""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from junos_upgrader import __version__
from junos_upgrader.models import HopSpec, PlatformPolicy, SwitchRecord, SwitchState
from junos_upgrader.packages import infer_arch_from_filename, inspect_local_tgz
from junos_upgrader.planner import (
    compute_remaining_hops,
    estimate_train_gap,
    is_safe_package_filename,
    match_platform_policy,
    parse_junos_train,
    parse_junos_version_key,
)
from junos_upgrader.transfer import resolve_local_firmware_file

logger = logging.getLogger(__name__)

JUNIPER_DOWNLOAD_PORTAL = "https://support.juniper.net/support/downloads/"
USER_AGENT = f"junos-switch-upgrader/{__version__}"
DEFAULT_MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB


@dataclass
class ShoppingListItem:
    """Unique firmware package needed by one or more switches."""

    family_dir: str
    portal_slug: str
    train: str
    target_version: str
    package_filename: str
    expected_arch: str
    checksum_type: str
    expected_checksum: str
    switch_count: int
    present_locally: bool
    local_path: str = ""

    @property
    def portal_url(self) -> str:
        if self.portal_slug:
            slug = urllib.parse.quote(self.portal_slug.strip(), safe="")
            return f"{JUNIPER_DOWNLOAD_PORTAL}?p={slug}"
        return JUNIPER_DOWNLOAD_PORTAL


def _atomic_write_text(path: Path, content: str) -> None:
    """Write text atomically via a sibling temporary file + fsync + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as fh:
            tmp_path = fh.name
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _is_forbidden_ip(ip_str: str) -> bool:
    """Reject non-global, loopback, private, link-local, reserved, multicast, and unspecified IPs."""
    addr = ipaddress.ip_address(ip_str)
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return bool(
        not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _validate_https_url_and_host(url: str) -> urllib.parse.SplitResult:
    """Enforce https:// scheme and verify every DNS-resolved IP is globally routable."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(
            f"Rejected non-HTTPS download URL scheme {parsed.scheme!r}; only 'https' is permitted."
        )
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Download URL is missing a hostname: {url!r}")

    port = parsed.port or 443
    try:
        addr_infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {hostname!r}: {exc}") from exc

    if not addr_infos:
        raise ValueError(f"No IP addresses resolved for {hostname!r}")

    for info in addr_infos:
        ip_str = str(info[4][0])
        if _is_forbidden_ip(ip_str):
            raise ValueError(
                f"SSRF protection blocked download from {hostname!r} (resolved to disallowed IP {ip_str})."
            )
    return parsed


def _extract_safe_url_filename(parsed: urllib.parse.SplitResult) -> str:
    """Derive and validate a safe .tgz basename from a parsed HTTPS URL path."""
    decoded_path = urllib.parse.unquote(parsed.path)
    if "\\" in decoded_path:
        raise ValueError(f"Unsafe backslash in URL path: {parsed.path!r}")
    raw_name = PurePosixPath(decoded_path).name
    if not raw_name or raw_name in (".", ".."):
        raise ValueError(f"URL path does not contain a valid package filename: {parsed.path!r}")
    fname = raw_name if raw_name.lower().endswith(".tgz") else f"{raw_name}.tgz"
    if not is_safe_package_filename(fname):
        raise ValueError(
            f"Unsafe filename {fname!r} derived from URL (must match ^[A-Za-z0-9][A-Za-z0-9._-]*\\.tgz$)."
        )
    return fname


class _SafeHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Block HTTPS->HTTP downgrades and SSRF redirects to non-public IP addresses."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        _validate_https_url_and_host(resolved)
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def _iter_platform_dicts(raw: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return list of (model_pattern, platform_dict) supporting both v2 list and v1 dict."""
    platforms_raw = raw.get("platforms")
    if isinstance(platforms_raw, list):
        return [(str(p.get("model_pattern", "")), p) for p in platforms_raw if isinstance(p, dict)]
    if isinstance(platforms_raw, dict):
        return [(str(k), v) for k, v in platforms_raw.items() if isinstance(v, dict)]
    return []


def build_shopping_list(
    switches: list[SwitchRecord],
    policies: list[PlatformPolicy],
    firmware_dir: Path,
) -> list[ShoppingListItem]:
    """Deduplicate all firmware packages required across eligible switches."""
    grouped: dict[tuple[str, str], tuple[PlatformPolicy, HopSpec, int]] = {}
    for sw in switches:
        if sw.state in (
            SwitchState.EXCLUDED,
            SwitchState.COMPLETED,
            SwitchState.REPLACE_RECOMMENDED,
        ):
            continue
        policy = match_platform_policy(sw.model, policies)
        if not policy:
            continue
        try:
            hops = compute_remaining_hops(sw.current_version, policy)
        except ValueError as exc:
            logger.warning(
                "Skipping switch %s (%s) in shopping list due to unparseable version %r: %s",
                sw.hostname,
                sw.model,
                sw.current_version,
                exc,
            )
            continue
        for hop in hops:
            key = (policy.expected_arch.lower(), hop.package_filename)
            if key in grouped:
                p, h, count = grouped[key]
                grouped[key] = (p, h, count + 1)
            else:
                grouped[key] = (policy, hop, 1)

    items: list[ShoppingListItem] = []
    for (_, _), (policy, hop, count) in sorted(
        grouped.items(), key=lambda kv: (kv[1][0].family_dir, kv[0][1])
    ):
        found = resolve_local_firmware_file(firmware_dir, policy, hop)
        items.append(
            ShoppingListItem(
                family_dir=policy.family_dir,
                portal_slug=policy.download_portal_slug,
                train=hop.train,
                target_version=hop.target_version,
                package_filename=hop.package_filename,
                expected_arch=policy.expected_arch,
                checksum_type=hop.checksum_type,
                expected_checksum=hop.checksum,
                switch_count=count,
                present_locally=found is not None,
                local_path=str(found) if found else "",
            )
        )
    return items


def _update_manifest_checksum(
    releases_path: Path,
    expected_arch: str,
    hop_train: str,
    md5_hex: str,
    actual_filename: str,
    actual_version: str,
) -> bool:
    """Update all platform policies matching (arch, train) with exact filename, version, and MD5.

    Never downgrades an existing hop target_version to an older release within the same train.
    """
    raw: dict[str, Any] = yaml.safe_load(releases_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return False
    updated = False
    target_train = parse_junos_train(hop_train)
    new_key = parse_junos_version_key(actual_version) if actual_version else None

    for _, plat in _iter_platform_dicts(raw):
        if str(plat.get("expected_arch", "")).lower() != expected_arch.lower():
            continue
        hops = plat.get("hops", [])
        if not isinstance(hops, list):
            continue
        for idx, hop in enumerate(hops):
            if not isinstance(hop, dict) or "train" not in hop:
                continue
            if parse_junos_train(str(hop["train"])) != target_train:
                continue

            existing_ver = str(hop.get("target_version", "")).strip()
            if new_key is not None and existing_ver:
                try:
                    existing_key = parse_junos_version_key(existing_ver)
                    if new_key < existing_key:
                        # Refuse to downgrade manifest to an older release in the same train
                        continue
                except ValueError:
                    pass

            hop["checksum_type"] = "md5"
            hop["checksum"] = md5_hex
            hop["package_filename"] = actual_filename
            if actual_version:
                hop["target_version"] = actual_version
                # Keep full-version train labels synchronized when bumping service releases
                prev_train_str = str(hop["train"])
                if any(ch in prev_train_str.upper() for ch in ("R", "X")):
                    hop["train"] = actual_version
                if idx == len(hops) - 1:
                    plat["final_target"] = actual_version
            updated = True

    if updated:
        _atomic_write_text(
            releases_path,
            yaml.safe_dump(raw, sort_keys=False, default_flow_style=False),
        )
    return updated


def _is_install_media_filename(name: str) -> bool:
    lower = name.lower()
    return "install-media" in lower or lower.endswith((".img", ".img.gz"))


def _ingest_single_file(
    candidate: Path,
    firmware_dir: Path,
    releases_path: Path,
    policies: list[PlatformPolicy],
    update_manifest: bool = True,
) -> dict[str, str]:
    """Validate and ingest a single candidate .tgz into firmware_dir and optionally releases_path."""
    if not is_safe_package_filename(candidate.name):
        return {
            "file": str(candidate),
            "status": "rejected",
            "reason": f"Unsafe package filename {candidate.name!r}.",
        }
    if _is_install_media_filename(candidate.name):
        return {
            "file": str(candidate),
            "status": "rejected",
            "reason": "Install-media image rejected; runtime/host .tgz package required.",
        }

    meta = inspect_local_tgz(candidate)
    if not meta.valid_tgz:
        return {
            "file": str(candidate),
            "status": "rejected",
            "reason": "; ".join(meta.errors),
        }

    file_arch = (
        meta.detected_arch
        if meta.detected_arch and meta.detected_arch != "unknown"
        else infer_arch_from_filename(candidate.name)
    )
    file_train: tuple[int, int] | None = None
    if meta.detected_version:
        try:
            file_train = parse_junos_train(meta.detected_version)
        except ValueError:
            file_train = None

    matched_entries: list[tuple[PlatformPolicy, HopSpec]] = []
    for policy in policies:
        if file_arch == "unknown":
            # Unknown arch may only match an exact configured package filename, never broad train_match
            for hop in policy.hops:
                if candidate.name == hop.package_filename:
                    matched_entries.append((policy, hop))
                    break
            continue

        if policy.expected_arch.lower() != file_arch.lower():
            continue
        for hop in policy.hops:
            exact_name = candidate.name == hop.package_filename
            train_match = file_train is not None and file_train == parse_junos_train(hop.train)
            if exact_name or train_match:
                matched_entries.append((policy, hop))
                break

    if not matched_entries:
        return {
            "file": str(candidate),
            "status": "unmatched",
            "arch": file_arch,
            "md5": meta.md5,
        }

    actual_ver = meta.detected_version or matched_entries[0][1].target_version
    primary_dest: Path | None = None
    for policy, hop in matched_entries:
        dest_train = hop.train
        if actual_ver and any(ch in hop.train.upper() for ch in ("R", "X")):
            dest_train = actual_ver
        dest_dir = firmware_dir / "juniper" / policy.family_dir / dest_train
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / candidate.name
        if candidate.resolve() != dest_file.resolve():
            shutil.copy2(candidate, dest_file)
        if primary_dest is None:
            primary_dest = dest_file

    if update_manifest:
        # Update every distinct (arch, train) pair represented in matched_entries
        updated_pairs: set[tuple[str, tuple[int, int]]] = set()
        for pol, hop in matched_entries:
            pair = (pol.expected_arch.lower(), parse_junos_train(hop.train))
            if pair in updated_pairs:
                continue
            updated_pairs.add(pair)
            _update_manifest_checksum(
                releases_path,
                expected_arch=pol.expected_arch,
                hop_train=hop.train,
                md5_hex=meta.md5,
                actual_filename=candidate.name,
                actual_version=meta.detected_version or hop.target_version,
            )

    return {
        "file": str(primary_dest),
        "status": "ingested",
        "arch": file_arch,
        "version": actual_ver,
        "md5": meta.md5,
        "platforms_updated": str(len(matched_entries)),
    }


def _candidate_sort_key(path: Path) -> tuple[int, tuple[int, ...], str]:
    """Sort candidates by parsed Junos version ascending so newer releases win over older ones."""
    from junos_upgrader.packages import _TGZ_VERSION_RE

    m = _TGZ_VERSION_RE.search(path.name)
    if m:
        try:
            return (1, parse_junos_version_key(m.group(1)), path.name)
        except ValueError:
            pass
    return (0, (), path.name)


def scan_and_ingest_directory(
    scan_dir: Path,
    firmware_dir: Path,
    releases_path: Path,
    policies: list[PlatformPolicy],
    update_manifest: bool = True,
) -> list[dict[str, str]]:
    """Inspect .tgz packages in scan_dir, place valid images into firmware_dir, and record MD5s."""
    resolved_scan = scan_dir.resolve()
    resolved_fw = firmware_dir.resolve()
    skip_fw_dir = resolved_fw != resolved_scan and resolved_fw.is_relative_to(resolved_scan)

    candidates = [
        p
        for p in scan_dir.rglob("*.tgz")
        if p.is_file()
        and "contents" not in p.parts
        and not (skip_fw_dir and p.resolve().is_relative_to(resolved_fw))
    ]
    candidates.sort(key=_candidate_sort_key)

    ingested: list[dict[str, str]] = []
    for candidate in candidates:
        ingested.append(
            _ingest_single_file(
                candidate=candidate,
                firmware_dir=firmware_dir,
                releases_path=releases_path,
                policies=policies,
                update_manifest=update_manifest,
            )
        )
    return ingested


def pull_signed_urls(
    urls: list[str],
    firmware_dir: Path,
    releases_path: Path,
    policies: list[PlatformPolicy],
    *,
    max_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    timeout: int = 120,
) -> list[dict[str, str]]:
    """Download HTTPS signed direct-download URLs safely into an isolated temp dir and ingest."""
    staging_parent = firmware_dir / "_incoming"
    staging_parent.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, str]] = []

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _SafeHTTPSRedirectHandler(),
    )

    with tempfile.TemporaryDirectory(prefix="pull_", dir=staging_parent) as run_tmp:
        run_dir = Path(run_tmp).resolve()
        for url in urls:
            clean_url = url.strip()
            if not clean_url:
                continue
            try:
                parsed = _validate_https_url_and_host(clean_url)
                fname = _extract_safe_url_filename(parsed)
                dest = (run_dir / fname).resolve()
                if not dest.is_relative_to(run_dir):
                    raise ValueError(f"Path traversal blocked for filename {fname!r}")

                req = urllib.request.Request(clean_url, headers={"User-Agent": USER_AGENT})
                part_path = run_dir / f".{fname}.part"
                try:
                    with opener.open(req, timeout=timeout) as resp:
                        status = getattr(resp, "status", None)
                        if status is not None and not (200 <= int(status) < 300):
                            raise ValueError(f"Unexpected HTTP status {status}")
                        ctype = str(resp.headers.get("Content-Type", "")).lower()
                        if "text/html" in ctype or "application/xhtml" in ctype:
                            raise ValueError(
                                f"Refused HTML response (Content-Type: {ctype}; likely expired SSO link)."
                            )

                        first_chunk = resp.read(65536)
                        if not first_chunk.startswith(b"\x1f\x8b"):
                            raise ValueError(
                                "Response body is not a valid gzip stream (likely HTML login/error page)."
                            )
                        total = len(first_chunk)
                        if total > max_bytes:
                            raise ValueError(
                                f"Download exceeds maximum allowed size ({max_bytes} bytes)."
                            )

                        with part_path.open("wb") as out:
                            out.write(first_chunk)
                            while True:
                                chunk = resp.read(1024 * 1024)
                                if not chunk:
                                    break
                                total += len(chunk)
                                if total > max_bytes:
                                    raise ValueError(
                                        f"Download exceeds maximum allowed size ({max_bytes} bytes)."
                                    )
                                out.write(chunk)
                            out.flush()
                            os.fsync(out.fileno())
                    os.replace(part_path, dest)
                except Exception:
                    if part_path.exists():
                        try:
                            part_path.unlink()
                        except OSError:
                            pass
                    raise
            except (ValueError, urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
                results.append(
                    {
                        "url": clean_url,
                        "status": "rejected",
                        "reason": str(exc),
                    }
                )
                continue

        results.extend(scan_and_ingest_directory(run_dir, firmware_dir, releases_path, policies))

    return results


def _open_portal_browser(target_url: str) -> None:
    """Open target_url in the user's browser without leaking zombie processes."""
    xdg = shutil.which("xdg-open")
    if xdg:
        try:
            proc = subprocess.Popen(
                [xdg, target_url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                rc = proc.wait(timeout=2.0)
                if rc == 0:
                    return
            except subprocess.TimeoutExpired:
                # xdg-open kept running (browser open in foreground); treat as launched
                return
        except OSError:
            pass
    webbrowser.open(target_url)


def interactive_portal_session(
    shopping_list: list[ShoppingListItem],
    firmware_dir: Path,
    releases_path: Path,
    policies: list[PlatformPolicy],
    watch_dir: Path | None = None,
    timeout_seconds: int = 900,
    *,
    poll_interval: float = 3.0,
) -> list[dict[str, str]]:
    """Open visible Juniper/HPE Support Portal in browser for manual SSO + watch downloads."""
    missing = [item for item in shopping_list if not item.present_locally]
    if not missing:
        return []

    watch_path = watch_dir or (Path.home() / "Downloads")
    if not watch_path.exists() or not watch_path.is_dir():
        raise FileNotFoundError(f"Watch directory does not exist: {watch_path}")

    _open_portal_browser(missing[0].portal_url)

    deadline = time.monotonic() + timeout_seconds
    seen: set[Path] = set()
    size_snapshots: dict[Path, int] = {}
    all_ingested: list[dict[str, str]] = []
    remaining_keys = {(i.expected_arch.lower(), parse_junos_train(i.train)) for i in missing}

    while time.monotonic() < deadline and remaining_keys:
        # Ignore active .crdownload / .part temp files until browser finishes rename to .tgz
        candidate_files = [
            p
            for p in sorted(watch_path.glob("*.tgz"))
            if p.is_file()
            and p not in seen
            and not (watch_path / f"{p.name}.part").exists()
            and not (watch_path / f"{p.name}.crdownload").exists()
        ]
        ready_files: list[Path] = []
        for p in candidate_files:
            try:
                sz = p.stat().st_size
            except OSError:
                continue
            prev_sz = size_snapshots.get(p)
            if prev_sz is not None and prev_sz == sz and sz > 0:
                ready_files.append(p)
            else:
                size_snapshots[p] = sz

        for p in sorted(ready_files, key=_candidate_sort_key):
            res = _ingest_single_file(p, firmware_dir, releases_path, policies)
            seen.add(p)
            size_snapshots.pop(p, None)
            if res.get("status") == "ingested":
                all_ingested.append(res)
                ver = res.get("version", "")
                if ver:
                    try:
                        remaining_keys.discard(
                            (res.get("arch", "").lower(), parse_junos_train(ver))
                        )
                    except ValueError:
                        pass
        if not remaining_keys:
            break
        if poll_interval > 0:
            time.sleep(poll_interval)
    return all_ingested


def generate_bleeding_edge_manifest(
    scan_dirs: list[Path],
    base_releases_path: Path,
    firmware_dir: Path,
    output_manifest_path: Path,
    max_train_gap: int = 4,
) -> dict[str, Any]:
    """Build a non-JTAC bleeding-edge manifest from local .tgz images newer than JTAC baseline."""
    raw: dict[str, Any] = yaml.safe_load(base_releases_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Invalid base release manifest: {base_releases_path}")

    # Collect valid non-install-media candidate .tgz packages with safe filenames
    candidates: list[tuple[str, str, Path, str]] = []  # (arch, version, path, md5)
    seen_files: set[Path] = set()
    for sdir in scan_dirs:
        if not sdir.exists():
            continue
        for cand in sorted(sdir.rglob("*.tgz")):
            if not cand.is_file() or "contents" in cand.parts:
                continue
            if not is_safe_package_filename(cand.name) or _is_install_media_filename(cand.name):
                continue
            resolved = cand.resolve()
            if resolved in seen_files:
                continue
            seen_files.add(resolved)
            meta = inspect_local_tgz(cand)
            if not meta.valid_tgz or not meta.detected_version:
                continue
            arch = (
                meta.detected_arch
                if meta.detected_arch and meta.detected_arch != "unknown"
                else infer_arch_from_filename(cand.name)
            )
            if arch == "unknown":
                continue
            try:
                parse_junos_version_key(meta.detected_version)
            except ValueError:
                continue
            candidates.append((arch.lower(), meta.detected_version, cand, meta.md5))

    # Deduplicate to the highest version per (arch, train)
    best_per_train: dict[tuple[str, tuple[int, int]], tuple[str, str, Path, str]] = {}
    for item in candidates:
        arch, ver, _, _ = item
        train = parse_junos_train(ver)
        key = (arch, train)
        prev = best_per_train.get(key)
        if prev is None or parse_junos_version_key(ver) > parse_junos_version_key(prev[1]):
            best_per_train[key] = item

    deduped_candidates = sorted(
        best_per_train.values(),
        key=lambda item: parse_junos_version_key(item[1]),
    )

    added_hops: list[dict[str, str]] = []
    gap_warnings: list[str] = []

    for pat_name, plat in _iter_platform_dicts(raw):
        plat_arch = str(plat.get("expected_arch", "")).lower()
        jtac_final = str(plat.get("final_target", "")).strip()
        if not plat_arch or not jtac_final:
            continue
        jtac_key = parse_junos_version_key(jtac_final)
        family_dir = pat_name.replace("*", "").strip("-").lower()

        newer = [
            c
            for c in deduped_candidates
            if c[0] == plat_arch and parse_junos_version_key(c[1]) > jtac_key
        ]
        if not newer:
            continue

        plat["bleeding_edge"] = True
        plat["jtac_baseline"] = jtac_final
        hops: list[dict[str, Any]] = [dict(h) for h in plat.get("hops", []) if isinstance(h, dict)]
        base_install_options = list(hops[-1].get("install_options", [])) if hops else []

        for _, ver, src_path, md5_hex in newer:
            new_train = parse_junos_train(ver)
            new_key = parse_junos_version_key(ver)

            # Check if an existing hop already occupies this exact train
            same_train_idx = next(
                (i for i, h in enumerate(hops) if parse_junos_train(str(h["train"])) == new_train),
                None,
            )
            if same_train_idx is not None:
                existing_key = parse_junos_version_key(str(hops[same_train_idx]["target_version"]))
                if new_key <= existing_key:
                    continue

            dest_dir = firmware_dir / "juniper" / family_dir / ver
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_file = dest_dir / src_path.name
            if src_path.resolve() != dest_file.resolve():
                shutil.copy2(src_path, dest_file)

            # Calculate train gap against the preceding hop
            if same_train_idx is not None:
                prev_hop = hops[same_train_idx - 1] if same_train_idx > 0 else None
            else:
                prev_hop = hops[-1] if hops else None
            prev_train = (
                parse_junos_train(str(prev_hop["train"]))
                if prev_hop is not None
                else parse_junos_train(jtac_final)
            )
            gap = estimate_train_gap(prev_train, new_train)
            if gap > max_train_gap:
                prev_label = str(prev_hop["target_version"]) if prev_hop is not None else jtac_final
                gap_warnings.append(
                    f"{pat_name}: hop {prev_label} -> {ver} "
                    f"jumps ~{gap} quarterly releases (>{max_train_gap}); verify intermediate upgrade path."
                )

            hop_entry: dict[str, Any] = {
                "train": ver,
                "target_version": ver,
                "package_filename": src_path.name,
                "checksum_type": "md5",
                "checksum": md5_hex,
                "install_options": list(
                    hops[same_train_idx].get("install_options", base_install_options)
                    if same_train_idx is not None
                    else base_install_options
                ),
                "release_notes_reviewed": False,
                "bleeding_edge": True,
                "notes": f"Dynamic bleeding-edge release past JTAC {jtac_final}",
            }
            if same_train_idx is not None:
                hops[same_train_idx] = hop_entry
            else:
                hops.append(hop_entry)

            added_hops.append(
                {
                    "platform": pat_name,
                    "jtac_baseline": jtac_final,
                    "version": ver,
                    "package": src_path.name,
                    "md5": md5_hex,
                }
            )

        plat["hops"] = hops
        if hops:
            plat["final_target"] = hops[-1]["target_version"]

    if added_hops:
        raw["bleeding_edge"] = True
        raw["jtac_recommended"] = False
        raw["warning"] = (
            "BLEEDING-EDGE MANIFEST: Contains releases newer than JTAC-recommended baseline. "
            "Lab-certify before campus deployment."
        )
        _atomic_write_text(
            output_manifest_path,
            yaml.safe_dump(raw, sort_keys=False, default_flow_style=False),
        )

    return {
        "output": str(output_manifest_path) if added_hops else "",
        "added_hops": added_hops,
        "gap_warnings": gap_warnings,
    }
