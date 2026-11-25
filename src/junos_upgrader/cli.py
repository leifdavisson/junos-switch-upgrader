# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI entry point for junos-switch-upgrader."""

from __future__ import annotations

import contextlib
import importlib.resources
import ipaddress
import json
import threading
import time
import urllib.error
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table

from junos_upgrader import __version__
from junos_upgrader.checks import (
    backup_configuration,
    collect_baseline,
    generate_recovery_sheet,
    run_prechecks,
)
from junos_upgrader.firmware_fetcher import (
    build_shopping_list,
    generate_bleeding_edge_manifest,
    interactive_portal_session,
    pull_signed_urls,
    scan_and_ingest_directory,
)
from junos_upgrader.inventory import (
    discover_live_targets,
    expand_targets,
    import_from_crawler,
    load_inventory,
    save_inventory,
    scaffold_firmware_repo,
)
from junos_upgrader.junos_client import (
    CredentialSet,
    NetmikoJunosTransport,
    SwitchTransport,
    load_credentials,
)
from junos_upgrader.models import (
    PlatformPolicy,
    SwitchRecord,
    SwitchState,
    ensure_within_directory,
    validate_safe_path_segment,
)
from junos_upgrader.orchestrator import UpgradeOptions, run_upgrade_batches
from junos_upgrader.planner import (
    compute_remaining_hops,
    load_release_catalog,
    match_platform_policy,
    refresh_switch_plan,
)
from junos_upgrader.topology import (
    build_topology_graph,
    compute_topology_waves,
    redact_topology_graph,
)
from junos_upgrader.transfer import UnifiedFirmwareServer, resolve_local_firmware_file
from junos_upgrader.web_ui import (
    export_topology_markdown,
    render_rich_topology_tree,
    render_topology_html,
)

console = Console()
DEFAULT_MANIFEST = Path("deliverables/site-inventory.json")
DEFAULT_RELEASES = Path("manifests/approved-releases.yml")
DEFAULT_FIRMWARE_DIR = Path("firmware")


def resolve_default_releases_path() -> Path:
    """Resolve approved-releases.yml: ./manifests -> repo root -> bundled package data."""
    if DEFAULT_RELEASES.is_file():
        return DEFAULT_RELEASES

    repo_candidate = Path(__file__).resolve().parents[2] / "manifests" / "approved-releases.yml"
    if repo_candidate.is_file():
        return repo_candidate

    try:
        data_ref = importlib.resources.files("junos_upgrader").joinpath(
            "data/approved-releases.yml"
        )
        if data_ref.is_file():
            if isinstance(data_ref, Path):
                return data_ref
            candidate = Path(str(data_ref))
            if candidate.is_file():
                return candidate
    except (ModuleNotFoundError, FileNotFoundError, TypeError, AttributeError):
        pass

    return DEFAULT_RELEASES


def _resolve_releases_arg(releases: Path | None) -> Path:
    resolved = releases if releases is not None else resolve_default_releases_path()
    if not resolved.is_file():
        raise click.ClickException(f"Release catalog not found: {resolved}")
    return resolved


def _load_inventory_or_exit(manifest: Path) -> list[SwitchRecord]:
    try:
        return load_inventory(manifest)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise click.ClickException(f"Failed to load manifest {manifest}: {exc}") from exc


def _resolve_password(password: str | None, password_stdin: bool) -> str | None:
    ctx = click.get_current_context(silent=True)
    pwd_from_cli = (
        ctx is not None
        and ctx.get_parameter_source("password") == click.core.ParameterSource.COMMANDLINE
    )
    if password_stdin:
        if pwd_from_cli:
            raise click.ClickException("Cannot combine --password and --password-stdin.")
        return click.get_text_stream("stdin").readline().rstrip("\r\n")
    if pwd_from_cli:
        console.print(
            "[yellow]WARN:[/yellow] Passing --password on the command line may expose credentials "
            "in process lists/shell history; prefer --credentials-file, JUNOS_PASSWORD, or --password-stdin."
        )
    return password


def _load_creds_or_exit(
    credentials_file: Path | None,
    username: str | None,
    password: str | None,
    password_stdin: bool,
    key_file: str | None,
) -> list[CredentialSet]:
    resolved_password = _resolve_password(password, password_stdin)
    try:
        return load_credentials(credentials_file, username, resolved_password, key_file)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"Credential error: {exc}") from exc


def _filter_switches(
    switches: list[SwitchRecord],
    site: str | None,
    model: str | None,
    hosts: tuple[str, ...],
    include_excluded: bool = False,
) -> list[SwitchRecord]:
    host_set = {part.strip().lower() for h in hosts for part in h.split(",") if part.strip()}
    selected: list[SwitchRecord] = []
    for sw in switches:
        if not include_excluded and sw.state in (
            SwitchState.EXCLUDED,
            SwitchState.COMPLETED,
            SwitchState.REPLACE_RECOMMENDED,
        ):
            continue
        if site and sw.site.upper() != site.upper():
            continue
        if model and model.lower() not in sw.model.lower():
            continue
        if (
            host_set
            and sw.hostname.lower() not in host_set
            and sw.management_ip.lower() not in host_set
        ):
            continue
        selected.append(sw)
    return selected


def _make_transport_factory(creds: list[CredentialSet]):
    def factory(sw: SwitchRecord) -> SwitchTransport:
        return NetmikoJunosTransport(host=sw.management_ip, credentials=creds)

    return factory


def _resolve_restricted_firmware_clients(targets: list[SwitchRecord]) -> set[str]:
    """Extract normalized IP addresses from targets for opt-in HTTP firmware allowlisting."""
    clients: set[str] = set()
    for sw in targets:
        raw = sw.management_ip.strip()
        if not raw:
            continue
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            continue
        mapped = getattr(addr, "ipv4_mapped", None)
        clients.add(str(mapped or addr))
    if not clients:
        raise click.ClickException(
            "--restrict-firmware-clients requires at least one target with a literal IP address."
        )
    return clients


def _warn_if_bleeding_edge(
    policies: list[PlatformPolicy],
    accept_bleeding_edge: bool = False,
    require_accept: bool = False,
    batch_size: int = 1,
    targets: list[SwitchRecord] | None = None,
) -> None:
    """Display bleeding-edge warning banner and enforce --accept-bleeding-edge bumper."""
    bleeding_plats: list[PlatformPolicy] = []
    if targets is not None:
        seen_patterns: set[str] = set()
        for sw in targets:
            pol = match_platform_policy(sw.model, policies)
            if pol is None or pol.model_pattern in seen_patterns:
                continue
            try:
                hops = compute_remaining_hops(sw.current_version, pol)
            except ValueError:
                hops = pol.hops
            if hops and (pol.bleeding_edge or any(h.bleeding_edge for h in hops)):
                bleeding_plats.append(pol)
                seen_patterns.add(pol.model_pattern)
    else:
        bleeding_plats = [
            p for p in policies if p.bleeding_edge or any(h.bleeding_edge for h in p.hops)
        ]

    if not bleeding_plats:
        return

    summary = ", ".join(
        f"{rich_escape(p.family_dir)}: {rich_escape(p.jtac_baseline or 'JTAC')} -> "
        f"{rich_escape(p.final_target)}"
        for p in bleeding_plats
    )
    msg = (
        f"[bold yellow]NON-JTAC BLEEDING-EDGE MANIFEST ACTIVE[/bold yellow]\n"
        f"Targets beyond JTAC-recommended baseline: {summary}\n"
        "• Lab-certify on a spare switch before any campus deployment.\n"
        "• Verify release notes, boot loader, and flash headroom for every hop."
    )
    if batch_size > 1:
        msg += (
            "\n• [bold red]WARNING:[/bold red] --batch-size > 1 with bleeding-edge firmware; "
            "prefer --batch-size 1 canary."
        )
    console.print(Panel(msg, title="BLEEDING-EDGE GUARDRAIL", border_style="yellow"))

    if require_accept and not accept_bleeding_edge:
        raise click.ClickException(
            "Bleeding-edge bumper: pass --accept-bleeding-edge to acknowledge non-JTAC firmware."
        )


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """Site-generic, topology-aware Juniper EX/QFX firmware upgrade orchestrator."""


@main.command("init-repo")
@click.argument("repo_root", type=click.Path(path_type=Path))
def init_repo_cmd(repo_root: Path) -> None:
    """Scaffold the runbook firmware service directory structure."""
    rel = resolve_default_releases_path()
    created = scaffold_firmware_repo(repo_root, releases_path=rel if rel.is_file() else None)
    console.print(
        f"[green]Scaffolded {len(created)} directories under {rich_escape(str(repo_root))}[/green]"
    )


@main.command("discover")
@click.argument("pos_targets", nargs=-1)
@click.option(
    "--target",
    "--targets",
    "targets",
    multiple=True,
    help="Target IP, hostname, or CIDR (repeatable or comma-separated)",
)
@click.option(
    "--targets-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option(
    "--site", default=None, help="Site code label (inferred from hostname prefix if omitted)"
)
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--output", type=click.Path(path_type=Path), default=DEFAULT_MANIFEST)
@click.option(
    "--credentials-file",
    "--creds",
    "credentials_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--username", default=None)
@click.option(
    "--password",
    default=None,
    envvar="JUNOS_PASSWORD",
    help="SSH password (prefer --credentials-file, JUNOS_PASSWORD, or --password-stdin)",
)
@click.option("--password-stdin", is_flag=True, help="Read SSH password from stdin")
@click.option("--key-file", default=None)
@click.option("--ssh-port", type=click.IntRange(1, 65535), default=22, show_default=True)
@click.option("--tcp-timeout", type=click.FloatRange(min=0.1), default=3.0, show_default=True)
def discover_cmd(
    pos_targets: tuple[str, ...],
    targets: tuple[str, ...],
    targets_file: Path | None,
    site: str | None,
    releases: Path | None,
    output: Path,
    credentials_file: Path | None,
    username: str | None,
    password: str | None,
    password_stdin: bool,
    key_file: str | None,
    ssh_port: int,
    tcp_timeout: float,
) -> None:
    """Discover Juniper switches live via SSH from IPs, hostnames, CIDRs, or file."""
    releases_path = _resolve_releases_arg(releases)
    try:
        host_list = expand_targets((*pos_targets, *targets), targets_file)
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    if not host_list:
        raise click.ClickException("Specify at least one --target or --targets-file.")
    creds = _load_creds_or_exit(credentials_file, username, password, password_stdin, key_file)
    records = discover_live_targets(
        host_list,
        creds,
        releases_path,
        output,
        site_name=site or "",
        ssh_port=ssh_port,
        tcp_timeout=tcp_timeout,
    )
    if not records:
        raise click.ClickException(
            f"Discovered 0 switches across {len(host_list)} target(s); "
            "existing manifest (if any) was preserved."
        )
    console.print(
        f"[green]Discovered {len(records)} switch(es) -> {rich_escape(str(output))}[/green]"
    )
    for r in records:
        console.print(
            f"  {rich_escape(r.hostname)} ({rich_escape(r.management_ip)}): "
            f"{rich_escape(r.model)}, {rich_escape(r.current_version)}, "
            f"arch={rich_escape(r.kernel_arch)}, free={r.free_storage_mb}MB, "
            f"next={rich_escape(r.next_hop or 'current')}, state={rich_escape(r.state.value)}"
        )


@main.command("init-from-crawler")
@click.argument("deliverable_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--output", type=click.Path(path_type=Path), default=DEFAULT_MANIFEST)
def init_from_crawler_cmd(deliverable_dir: Path, releases: Path | None, output: Path) -> None:
    """Import net-docu-crawler asset_inventory.csv & neighbors.csv into site manifest."""
    releases_path = _resolve_releases_arg(releases)
    try:
        records = import_from_crawler(deliverable_dir, releases_path, output)
    except (FileNotFoundError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    by_state: dict[str, int] = {}
    for r in records:
        by_state[r.state.value] = by_state.get(r.state.value, 0) + 1
    console.print(f"[green]Imported {len(records)} switches to {rich_escape(str(output))}[/green]")
    for st, count in sorted(by_state.items()):
        console.print(f"  {rich_escape(st)}: {count}")


@main.command("topology")
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_MANIFEST,
)
@click.option("--batch-size", type=click.IntRange(min=1), default=1, show_default=True)
@click.option("--include-cores", is_flag=True)
@click.option(
    "--markdown", type=click.Path(path_type=Path), default=None, help="Export Mermaid diagram"
)
@click.option("--redact", is_flag=True, help="Sanitize hostnames and IPs in topology output")
@click.option(
    "--write-manifest", is_flag=True, help="Persist recomputed topology fields back to manifest"
)
@click.option("--serve", is_flag=True, help="Start live browser topology & firmware HTTP server")
@click.option(
    "--bind-host", default="127.0.0.1", show_default=True, help="HTTP server bind address"
)
@click.option("--port", type=click.IntRange(0, 65535), default=8080, show_default=True)
@click.option(
    "--allow-remote-ui", is_flag=True, help="Allow non-loopback clients to access topology UI"
)
@click.option("--firmware-dir", type=click.Path(path_type=Path), default=DEFAULT_FIRMWARE_DIR)
def topology_cmd(
    manifest: Path,
    batch_size: int,
    include_cores: bool,
    markdown: Path | None,
    redact: bool,
    write_manifest: bool,
    serve: bool,
    bind_host: str,
    port: int,
    allow_remote_ui: bool,
    firmware_dir: Path,
) -> None:
    """Display live dependency graph, leaf-first wave order, and optional web dashboard."""
    switches = _load_inventory_or_exit(manifest)
    graph = build_topology_graph(switches)
    if write_manifest:
        save_inventory(switches, manifest)
    display_graph = redact_topology_graph(graph) if redact else graph
    render_rich_topology_tree(display_graph, console)

    waves = compute_topology_waves(
        switches, graph, batch_size=batch_size, include_cores=include_cores
    )
    name_map: dict[str, str] = {}
    if redact:
        redaction_map = getattr(display_graph, "redaction_map", None) or {}
        if redaction_map:
            name_map = dict(redaction_map)
        else:
            orig_ids = [nid for nid in graph.nodes if nid != "__runner__"]
            red_ids = [nid for nid in display_graph.nodes if nid != "__runner__"]
            name_map = dict(zip(orig_ids, red_ids))

    console.print(f"\n[bold]Leaf-First Wave Schedule ({len(waves)} wave(s)):[/bold]")
    for idx, w in enumerate(waves, start=1):
        names = ", ".join(
            f"{rich_escape(name_map.get(s.hostname, s.hostname))} (d={s.topology_depth})" for s in w
        )
        console.print(f"  Wave {idx}: {names}")

    if markdown:
        out = export_topology_markdown(display_graph, markdown)
        console.print(f"[green]Exported Mermaid topology to {rich_escape(str(out))}[/green]")

    if serve:
        last_good_api: dict[str, Any] = display_graph.to_api_dict()

        def _live_topology_provider() -> dict[str, Any]:
            nonlocal last_good_api
            try:
                fresh = build_topology_graph(load_inventory(manifest), origin=graph.origin)
                if redact:
                    fresh = redact_topology_graph(fresh)
                last_good_api = fresh.to_api_dict()
            except (OSError, json.JSONDecodeError, ValueError):
                pass
            return last_good_api

        try:
            with UnifiedFirmwareServer(
                firmware_dir=firmware_dir,
                bind_host=bind_host,
                port=port,
                topology_provider=_live_topology_provider,
                html_provider=render_topology_html,
                allow_remote_ui=allow_remote_ui,
            ) as srv:
                console.print(
                    f"[cyan]Live Topology & Firmware Server running at "
                    f"http://{rich_escape(bind_host)}:{srv.port}/ (Ctrl+C to stop)[/cyan]"
                )
                try:
                    while True:
                        time.sleep(1.0)
                except KeyboardInterrupt:
                    pass
        except OSError as exc:
            raise click.ClickException(
                f"Unable to bind HTTP server on {bind_host}:{port}: {exc}"
            ) from exc


@main.group("firmware")
def firmware_group() -> None:
    """Manage local firmware folder, portal shopping list, and package ingestion."""


@firmware_group.command("shopping-list")
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_MANIFEST,
)
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--firmware-dir", type=click.Path(path_type=Path), default=DEFAULT_FIRMWARE_DIR)
def shopping_list_cmd(manifest: Path, releases: Path | None, firmware_dir: Path) -> None:
    """Show deduplicated Juniper packages required across all eligible switches."""
    releases_path = _resolve_releases_arg(releases)
    _, policies, _ = load_release_catalog(releases_path)
    switches = _load_inventory_or_exit(manifest)
    items = build_shopping_list(switches, policies, firmware_dir)
    table = Table(title=f"Firmware Shopping List ({len(items)} unique packages)")
    for col in ("Family", "Version", "Package", "Arch", "Switches", "Local", "Portal URL"):
        table.add_column(col)
    for it in items:
        table.add_row(
            rich_escape(it.family_dir),
            rich_escape(it.target_version),
            rich_escape(it.package_filename),
            rich_escape(it.expected_arch),
            str(it.switch_count),
            "[green]YES[/green]" if it.present_locally else "[yellow]MISSING[/yellow]",
            rich_escape(it.portal_url),
        )
    console.print(table)


@firmware_group.command("scan")
@click.argument("scan_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--firmware-dir", type=click.Path(path_type=Path), default=DEFAULT_FIRMWARE_DIR)
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
def scan_cmd(scan_dir: Path, firmware_dir: Path, releases: Path | None) -> None:
    """Scan a directory for .tgz images, validate archives, ingest, and update MD5s."""
    releases_path = _resolve_releases_arg(releases)
    _, policies, _ = load_release_catalog(releases_path)
    results = scan_and_ingest_directory(scan_dir, firmware_dir, releases_path, policies)
    for res in results:
        console.print(res)
    ingested = [r for r in results if r.get("status") == "ingested"]
    rejected = [r for r in results if r.get("status") in ("rejected", "error")]
    if not results:
        raise click.ClickException(f"No .tgz packages found in {scan_dir}.")
    if rejected and not ingested:
        raise click.ClickException(f"All {len(rejected)} scanned package(s) were rejected.")


@firmware_group.command("pull")
@click.option(
    "--url", "urls", multiple=True, required=True, help="Signed HTTPS CDN URL from Juniper portal"
)
@click.option("--firmware-dir", type=click.Path(path_type=Path), default=DEFAULT_FIRMWARE_DIR)
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
def pull_cmd(urls: tuple[str, ...], firmware_dir: Path, releases: Path | None) -> None:
    """Download signed Juniper direct-download URLs, verify .tgz integrity, and ingest."""
    releases_path = _resolve_releases_arg(releases)
    _, policies, _ = load_release_catalog(releases_path)
    try:
        results = pull_signed_urls(list(urls), firmware_dir, releases_path, policies)
    except (ValueError, OSError, urllib.error.URLError) as exc:
        raise click.ClickException(f"Download failed: {exc}") from exc
    for res in results:
        console.print(res)
    ingested = [r for r in results if r.get("status") == "ingested"]
    if not ingested:
        raise click.ClickException(
            "No valid firmware packages were ingested from the supplied URL(s)."
        )


@firmware_group.command("login")
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_MANIFEST,
)
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--firmware-dir", type=click.Path(path_type=Path), default=DEFAULT_FIRMWARE_DIR)
@click.option("--watch-dir", type=click.Path(file_okay=False, path_type=Path), default=None)
def login_cmd(
    manifest: Path,
    releases: Path | None,
    firmware_dir: Path,
    watch_dir: Path | None,
) -> None:
    """Open Juniper/HPE Support Portal in browser for manual SSO and auto-ingest downloads."""
    releases_path = _resolve_releases_arg(releases)
    resolved_watch = watch_dir if watch_dir is not None else (Path.home() / "Downloads")
    if not resolved_watch.is_dir():
        raise click.ClickException(f"Watch directory does not exist: {resolved_watch}")
    _, policies, _ = load_release_catalog(releases_path)
    switches = _load_inventory_or_exit(manifest)
    items = build_shopping_list(switches, policies, firmware_dir)
    if not any(not it.present_locally for it in items):
        console.print("[green]All required firmware packages are already present locally.[/green]")
        return
    console.print(
        f"[cyan]Watching {rich_escape(str(resolved_watch))} for downloaded .tgz images...[/cyan]"
    )
    ingested = interactive_portal_session(
        items, firmware_dir, releases_path, policies, watch_dir=resolved_watch
    )
    console.print(f"[green]Ingested {len(ingested)} package(s).[/green]")


@firmware_group.command("create-latest")
@click.option(
    "--scan-dir",
    "scan_dirs",
    multiple=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Directory to scan for newer .tgz images (defaults to ~/Downloads and firmware/)",
)
@click.option(
    "--base-releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--firmware-dir", type=click.Path(path_type=Path), default=DEFAULT_FIRMWARE_DIR)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    default=Path("deliverables/bleeding-edge-releases.yml"),
    show_default=True,
)
def create_latest_cmd(
    scan_dirs: tuple[Path, ...],
    base_releases: Path | None,
    firmware_dir: Path,
    output: Path,
) -> None:
    """Dynamically build a non-JTAC bleeding-edge manifest from local newer .tgz images."""
    base_releases_path = _resolve_releases_arg(base_releases)
    dirs = list(scan_dirs) if scan_dirs else [Path.home() / "Downloads", firmware_dir]
    summary = generate_bleeding_edge_manifest(dirs, base_releases_path, firmware_dir, output)

    added = summary["added_hops"]
    if not added:
        console.print("[yellow]No valid .tgz images newer than JTAC baseline were found.[/yellow]")
        return

    console.print(
        Panel(
            f"[bold yellow]Created BLEEDING-EDGE manifest:[/bold yellow] "
            f"{rich_escape(str(summary['output']))}\n"
            f"JTAC default ({rich_escape(str(base_releases_path))}) was NOT modified.\n"
            f"Use `--releases {rich_escape(str(summary['output']))}` "
            "with `--accept-bleeding-edge` to deploy.",
            title="BLEEDING-EDGE MANIFEST GENERATED",
            border_style="yellow",
        )
    )
    for item in added:
        console.print(
            f"  {rich_escape(item['platform'])}: JTAC {rich_escape(item['jtac_baseline'])} -> "
            f"[yellow]{rich_escape(item['version'])}[/yellow] "
            f"({rich_escape(item['package'])}, md5={rich_escape(item['md5'])})"
        )
    for warn in summary["gap_warnings"]:
        console.print(f"[bold red]HOP GAP WARNING:[/bold red] {rich_escape(warn)}")


@main.command("status")
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_MANIFEST,
)
@click.option("--site", default=None)
@click.option("--model", default=None)
def status_cmd(manifest: Path, site: str | None, model: str | None) -> None:
    """Display current switch inventory, topology depth, triage verdict, and state."""
    switches = _load_inventory_or_exit(manifest)
    filtered = _filter_switches(switches, site, model, (), include_excluded=True)
    table = Table(title=f"Switch Upgrade Status ({len(filtered)} devices)")
    for col in (
        "Site",
        "Depth",
        "Hostname",
        "IP",
        "Model",
        "Current",
        "Next Hop",
        "FreeMB",
        "Triage",
        "State",
    ):
        table.add_column(col)
    for sw in filtered:
        table.add_row(
            rich_escape(sw.site),
            str(sw.topology_depth),
            rich_escape(sw.hostname),
            rich_escape(sw.management_ip),
            rich_escape(sw.model),
            rich_escape(sw.current_version),
            rich_escape(sw.next_hop or "-"),
            str(sw.free_storage_mb) if sw.free_storage_mb is not None else "-",
            rich_escape(sw.triage_verdict or "-"),
            rich_escape(sw.state.value),
        )
    console.print(table)


@main.command("plan")
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_MANIFEST,
)
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--site", default=None)
@click.option("--model", default=None)
@click.option(
    "--host",
    "--hosts",
    "hosts",
    multiple=True,
    help="Target hostname or IP (repeatable or comma-separated)",
)
def plan_cmd(
    manifest: Path,
    releases: Path | None,
    site: str | None,
    model: str | None,
    hosts: tuple[str, ...],
) -> None:
    """Show exact multi-hop upgrade path for targeted switches."""
    releases_path = _resolve_releases_arg(releases)
    _, policies, _ = load_release_catalog(releases_path)
    switches = _load_inventory_or_exit(manifest)
    targets = _filter_switches(switches, site, model, hosts)
    if hosts and not targets:
        raise click.ClickException("No eligible switches matched the specified --host filter(s).")
    _warn_if_bleeding_edge(policies, targets=targets)

    table = Table(title=f"Multi-Hop Upgrade Plan ({len(targets)} eligible switches)")
    table.add_column("Depth")
    table.add_column("Hostname")
    table.add_column("Model")
    table.add_column("Current")
    table.add_column("Remaining Hops")
    for sw in sorted(targets, key=lambda s: (-s.topology_depth, s.hostname)):
        policy = match_platform_policy(sw.model, policies)
        if policy is None:
            hop_str = "(no matching policy)"
        else:
            try:
                hops = compute_remaining_hops(sw.current_version, policy)
                hop_str = " -> ".join(h.target_version for h in hops) if hops else "(current)"
            except ValueError:
                hop_str = f"(unparseable version: {sw.current_version})"
        table.add_row(
            str(sw.topology_depth),
            rich_escape(sw.hostname),
            rich_escape(sw.model),
            rich_escape(sw.current_version),
            rich_escape(hop_str),
        )
    console.print(table)


@main.command("precheck")
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_MANIFEST,
)
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--firmware-dir", type=click.Path(path_type=Path), default=DEFAULT_FIRMWARE_DIR)
@click.option("--site", default=None)
@click.option("--model", default=None)
@click.option(
    "--host",
    "--hosts",
    "hosts",
    multiple=True,
    help="Target hostname or IP (repeatable or comma-separated)",
)
@click.option(
    "--evidence-dir", type=click.Path(path_type=Path), default=Path("deliverables/evidence")
)
@click.option("--config-dir", type=click.Path(path_type=Path), default=Path("deliverables/configs"))
@click.option(
    "--credentials-file",
    "--creds",
    "credentials_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--username", default=None)
@click.option(
    "--password",
    default=None,
    envvar="JUNOS_PASSWORD",
    help="SSH password (prefer --credentials-file, JUNOS_PASSWORD, or --password-stdin)",
)
@click.option("--password-stdin", is_flag=True, help="Read SSH password from stdin")
@click.option("--key-file", default=None)
@click.option("--skip-release-notes-gate", is_flag=True)
@click.option("--ignore-old-cores", is_flag=True)
@click.option("--allow-no-console", is_flag=True, help="Allow Core precheck without console_port")
@click.option(
    "--allow-unverified-checksums",
    is_flag=True,
    help="Allow placeholder/unverified package checksums (lab use only)",
)
def precheck_cmd(
    manifest: Path,
    releases: Path | None,
    firmware_dir: Path,
    site: str | None,
    model: str | None,
    hosts: tuple[str, ...],
    evidence_dir: Path,
    config_dir: Path,
    credentials_file: Path | None,
    username: str | None,
    password: str | None,
    password_stdin: bool,
    key_file: str | None,
    skip_release_notes_gate: bool,
    ignore_old_cores: bool,
    allow_no_console: bool,
    allow_unverified_checksums: bool,
) -> None:
    """Run live read-only pre-upgrade health/FS triage, landmine scan, and recovery.txt export."""
    releases_path = _resolve_releases_arg(releases)
    _, policies, exclusions = load_release_catalog(releases_path)
    switches = _load_inventory_or_exit(manifest)
    if switches:
        build_topology_graph(switches)
    targets = _filter_switches(switches, site, model, hosts)
    if not targets:
        if hosts:
            raise click.ClickException(
                "No eligible switches matched the specified --host filter(s)."
            )
        console.print("[yellow]No eligible switches matched your filters.[/yellow]")
        return

    _warn_if_bleeding_edge(policies, targets=targets)
    creds = _load_creds_or_exit(credentials_file, username, password, password_stdin, key_file)
    factory = _make_transport_factory(creds)

    failures = 0
    checked = 0
    for sw in targets:
        policy = match_platform_policy(sw.model, policies)
        if not policy:
            console.print(
                f"[yellow]SKIP[/yellow] {rich_escape(sw.hostname)}: "
                f"no policy matched model {rich_escape(sw.model)}"
            )
            continue
        try:
            hops = compute_remaining_hops(sw.current_version, policy)
        except ValueError as exc:
            failures += 1
            sw.last_error = f"Unparseable version during precheck: {exc}"
            console.print(
                f"[red]FAIL (version)[/red] {rich_escape(sw.hostname)}: {rich_escape(str(exc))}"
            )
            save_inventory(switches, manifest)
            continue
        if not hops:
            continue

        checked += 1
        local_pkg = resolve_local_firmware_file(firmware_dir, policy, hops[0])
        transport = factory(sw)
        try:
            transport.connect()
        except Exception as exc:  # noqa: BLE001
            failures += 1
            sw.last_error = f"SSH connection failed during precheck: {exc}"
            console.print(
                f"[red]FAIL (unreachable)[/red] {rich_escape(sw.hostname)}: {rich_escape(str(exc))}"
            )
            save_inventory(switches, manifest)
            continue

        rec_path: Path | None = None
        try:
            site_seg = validate_safe_path_segment(sw.site or "SITE", "site")
            host_seg = validate_safe_path_segment(sw.hostname, "hostname")
            ev = ensure_within_directory(
                evidence_dir, evidence_dir / site_seg / "precheck" / host_seg
            )
            pre_ver = sw.current_version
            checks = run_prechecks(
                transport,
                sw,
                policy,
                hops[0],
                evidence_dir=ev,
                config_root=config_dir,
                local_pkg_file=local_pkg,
                require_release_notes=not skip_release_notes_gate,
                execute_cleanup=False,
                ignore_old_cores=ignore_old_cores,
                allow_no_console=allow_no_console,
                allow_unverified_checksums=allow_unverified_checksums,
            )
            if sw.current_version != pre_ver:
                try:
                    refresh_switch_plan(sw, policies, exclusions)
                except ValueError as exc:
                    sw.last_error = f"Version refresh plan error: {exc}"

            identity_failed = any(
                c.name == "identity_and_version" and not c.passed and c.hard_stop for c in checks
            )
            if not identity_failed:
                baseline = collect_baseline(transport, ev)
                cfg_dir = ensure_within_directory(
                    config_dir, config_dir / site_seg / host_seg / "precheck"
                )
                backup_configuration(transport, cfg_dir, baseline, save_rescue=False)
                rec_target = ensure_within_directory(
                    config_dir, config_dir / site_seg / host_seg / "recovery.txt"
                )
                rec_path = generate_recovery_sheet(sw, policy, baseline, rec_target)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            sw.last_error = f"Precheck command error: {exc}"
            console.print(
                f"[red]FAIL (error)[/red] {rich_escape(sw.hostname)}: {rich_escape(str(exc))}"
            )
            save_inventory(switches, manifest)
            continue
        finally:
            transport.disconnect()

        for warn_chk in [c for c in checks if not c.passed and not c.hard_stop]:
            console.print(
                f"[yellow]WARN[/yellow] {rich_escape(sw.hostname)}: {rich_escape(warn_chk.message)}"
            )

        bad = [c for c in checks if not c.passed and c.hard_stop]
        if bad:
            failures += 1
            sw.last_error = "; ".join(c.message for c in bad)
            console.print(
                f"[red]FAIL ({rich_escape(sw.triage_verdict or 'blocked')})[/red] "
                f"{rich_escape(sw.hostname)}: " + rich_escape("; ".join(c.message for c in bad))
            )
        else:
            if sw.state == SwitchState.FAILED:
                sw.state = SwitchState.READY
            sw.last_error = ""
            next_label = sw.next_hop or hops[0].target_version
            mode_hint = "http-stream (no-copy)" if policy.prefer_http_stream else "http/scp"
            console.print(
                f"[green]PASS[/green] {rich_escape(sw.hostname)} "
                f"[{rich_escape(sw.triage_verdict)}] "
                f"(free={sw.free_storage_mb}MB, snap={rich_escape(sw.recovery_snapshot or 'none')}, "
                f"next={rich_escape(next_label)}, transfer={mode_hint}, "
                f"recovery={rich_escape(str(rec_path or '-'))})"
            )
        save_inventory(switches, manifest)

    save_inventory(switches, manifest)
    if hosts and checked == 0 and failures == 0:
        raise click.ClickException(
            "0 targeted switches required precheck (no policy or already current)."
        )
    if failures:
        raise click.ClickException(f"{failures} switch(es) failed pre-checks.")


@main.command("stage")
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_MANIFEST,
)
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--firmware-dir", type=click.Path(path_type=Path), default=DEFAULT_FIRMWARE_DIR)
@click.option("--site", default=None)
@click.option("--model", default=None)
@click.option(
    "--host",
    "--hosts",
    "hosts",
    multiple=True,
    help="Target hostname or IP (repeatable or comma-separated)",
)
@click.option("--batch-size", type=click.IntRange(min=1), default=2, show_default=True)
@click.option("--include-cores", is_flag=True)
@click.option("--auto-cleanup/--no-auto-cleanup", default=True, show_default=True)
@click.option("--ignore-old-cores", is_flag=True)
@click.option(
    "--transfer-mode",
    type=click.Choice(["auto", "http", "http-stream", "scp"]),
    default="auto",
)
@click.option(
    "--bind-host",
    default="0.0.0.0",  # nosec B104
    show_default=True,
    help="HTTP server bind address",
)
@click.option("--http-port", type=click.IntRange(0, 65535), default=8080, show_default=True)
@click.option(
    "--allow-remote-ui", is_flag=True, help="Allow non-loopback clients to access topology UI"
)
@click.option(
    "--restrict-firmware-clients",
    is_flag=True,
    help="Restrict HTTP /firmware/ fetches strictly to targeted switches' literal management IPs",
)
@click.option("--change-number", default="PRE-STAGE", show_default=True)
@click.option("--operator", default="netops", show_default=True)
@click.option(
    "--evidence-dir", type=click.Path(path_type=Path), default=Path("deliverables/evidence")
)
@click.option("--config-dir", type=click.Path(path_type=Path), default=Path("deliverables/configs"))
@click.option(
    "--credentials-file",
    "--creds",
    "credentials_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--username", default=None)
@click.option(
    "--password",
    default=None,
    envvar="JUNOS_PASSWORD",
    help="SSH password (prefer --credentials-file, JUNOS_PASSWORD, or --password-stdin)",
)
@click.option("--password-stdin", is_flag=True, help="Read SSH password from stdin")
@click.option("--key-file", default=None)
@click.option("--allow-no-console", is_flag=True)
@click.option(
    "--accept-bleeding-edge", is_flag=True, help="Acknowledge non-JTAC bleeding-edge firmware"
)
@click.option("--skip-release-notes-gate", is_flag=True)
@click.option(
    "--allow-unverified-checksums",
    is_flag=True,
    help="Allow placeholder/unverified package checksums (lab use only)",
)
def stage_cmd(
    manifest: Path,
    releases: Path | None,
    firmware_dir: Path,
    site: str | None,
    model: str | None,
    hosts: tuple[str, ...],
    batch_size: int,
    include_cores: bool,
    auto_cleanup: bool,
    ignore_old_cores: bool,
    transfer_mode: str,
    bind_host: str,
    http_port: int,
    allow_remote_ui: bool,
    restrict_firmware_clients: bool,
    change_number: str,
    operator: str,
    evidence_dir: Path,
    config_dir: Path,
    credentials_file: Path | None,
    username: str | None,
    password: str | None,
    password_stdin: bool,
    key_file: str | None,
    allow_no_console: bool,
    accept_bleeding_edge: bool,
    skip_release_notes_gate: bool,
    allow_unverified_checksums: bool,
) -> None:
    """Two-phase business-hours staging: copy & verify next hop without rebooting."""
    try:
        safe_change_num = validate_safe_path_segment(change_number, "--change-number")
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    releases_path = _resolve_releases_arg(releases)
    base_url, policies, exclusions = load_release_catalog(releases_path)
    all_switches = _load_inventory_or_exit(manifest)
    graph = build_topology_graph(all_switches)
    targets = _filter_switches(all_switches, site, model, hosts)
    if not targets:
        if hosts:
            raise click.ClickException(
                "No eligible switches matched the specified --host filter(s)."
            )
        console.print("[yellow]No eligible switches matched your filters.[/yellow]")
        return

    _warn_if_bleeding_edge(
        policies,
        accept_bleeding_edge=accept_bleeding_edge,
        require_accept=True,
        batch_size=batch_size,
        targets=targets,
    )

    creds = _load_creds_or_exit(credentials_file, username, password, password_stdin, key_file)
    factory = _make_transport_factory(creds)
    state_lock = threading.Lock()
    opts = UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=firmware_dir,
        evidence_root=evidence_dir,
        config_root=config_dir,
        manifest_path=manifest,
        change_number=safe_change_num,
        operator=operator,
        batch_size=batch_size,
        max_hops=1,
        include_cores=include_cores,
        auto_cleanup=auto_cleanup,
        ignore_old_cores=ignore_old_cores,
        transfer_mode=transfer_mode,
        require_release_notes=not skip_release_notes_gate,
        stage_only=True,
        allow_no_console=allow_no_console,
        accept_bleeding_edge=accept_bleeding_edge,
        allow_unverified_checksums=allow_unverified_checksums,
        state_lock=state_lock,
    )

    def _snapshot_topology() -> dict[str, Any]:
        with state_lock:
            snap = [SwitchRecord.from_dict(s.to_dict()) for s in list(all_switches)]
        return build_topology_graph(snap, origin=graph.origin).to_api_dict()

    need_http = transfer_mode != "scp"
    allowed_fw_clients = (
        _resolve_restricted_firmware_clients(targets)
        if (need_http and restrict_firmware_clients)
        else None
    )
    with contextlib.ExitStack() as stack:
        srv: UnifiedFirmwareServer | None = None
        if need_http:
            try:
                srv = stack.enter_context(
                    UnifiedFirmwareServer(
                        firmware_dir=firmware_dir,
                        bind_host=bind_host,
                        port=http_port,
                        topology_provider=_snapshot_topology,
                        html_provider=render_topology_html,
                        allow_remote_ui=allow_remote_ui,
                        allowed_clients=allowed_fw_clients,
                    )
                )
            except OSError as exc:
                raise click.ClickException(
                    f"Unable to bind HTTP server on {bind_host}:{http_port}: {exc}"
                ) from exc
            console.print(
                f"[cyan]Unified HTTP+SCP firmware server & live topology UI at "
                f"http://{rich_escape(bind_host)}:{srv.port}/[/cyan]"
            )
        processed, ok = run_upgrade_batches(
            all_switches, targets, policies, exclusions, factory, opts, server=srv, graph=graph
        )
    save_inventory(all_switches, manifest)

    if not processed and targets:
        console.print(
            "[yellow]0 switches processed (Core switches require --include-cores, "
            "or remaining targets are failed/held/excluded).[/yellow]"
        )
        raise click.ClickException("0 switches processed during staging.")

    for sw in processed:
        if sw.state == SwitchState.COMPLETED:
            style = "green"
        elif sw.state == SwitchState.STAGED:
            style = "cyan"
        else:
            style = "red"
        console.print(
            f"[{style}]{rich_escape(sw.hostname)}: {rich_escape(sw.state.value)} "
            f"({rich_escape(sw.staged_package or '-')})[/{style}]"
        )
        if sw.last_error:
            console.print(f"  [red]Error:[/red] {rich_escape(sw.last_error)}")
    if not ok:
        raise click.ClickException("Staging halted due to switch pre-check or transfer failure.")


@main.command("upgrade")
@click.option(
    "--manifest",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_MANIFEST,
)
@click.option(
    "--releases",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--firmware-dir", type=click.Path(path_type=Path), default=DEFAULT_FIRMWARE_DIR)
@click.option("--site", default=None)
@click.option("--model", default=None)
@click.option(
    "--host",
    "--hosts",
    "hosts",
    multiple=True,
    help="Target hostname or IP (repeatable or comma-separated)",
)
@click.option("--batch-size", type=click.IntRange(min=1), default=1, show_default=True)
@click.option("--max-hops", type=click.IntRange(min=1), default=None)
@click.option("--include-cores", is_flag=True, help="Allow upgrading Core role switches")
@click.option("--auto-cleanup/--no-auto-cleanup", default=True, show_default=True)
@click.option("--ignore-old-cores", is_flag=True)
@click.option(
    "--transfer-mode",
    type=click.Choice(["auto", "http", "http-stream", "scp"]),
    default="auto",
)
@click.option(
    "--bind-host",
    default="0.0.0.0",  # nosec B104
    show_default=True,
    help="HTTP server bind address",
)
@click.option("--http-port", type=click.IntRange(0, 65535), default=8080, show_default=True)
@click.option(
    "--allow-remote-ui", is_flag=True, help="Allow non-loopback clients to access topology UI"
)
@click.option(
    "--restrict-firmware-clients",
    is_flag=True,
    help="Restrict HTTP /firmware/ fetches strictly to targeted switches' literal management IPs",
)
@click.option("--fast-intermediate/--full-all-hops", default=True, show_default=True)
@click.option(
    "--post-settle-seconds",
    type=click.FloatRange(min=0.0),
    default=60.0,
    show_default=True,
)
@click.option("--allow-no-console", is_flag=True)
@click.option(
    "--refresh-snapshot",
    is_flag=True,
    help="Refresh OAM/VMHost recovery snapshot after final hop",
)
@click.option("--change-number", required=True)
@click.option("--operator", required=True)
@click.option(
    "--evidence-dir", type=click.Path(path_type=Path), default=Path("deliverables/evidence")
)
@click.option("--config-dir", type=click.Path(path_type=Path), default=Path("deliverables/configs"))
@click.option(
    "--credentials-file",
    "--creds",
    "credentials_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
)
@click.option("--username", default=None)
@click.option(
    "--password",
    default=None,
    envvar="JUNOS_PASSWORD",
    help="SSH password (prefer --credentials-file, JUNOS_PASSWORD, or --password-stdin)",
)
@click.option("--password-stdin", is_flag=True, help="Read SSH password from stdin")
@click.option("--key-file", default=None)
@click.option("--skip-release-notes-gate", is_flag=True)
@click.option(
    "--accept-bleeding-edge", is_flag=True, help="Acknowledge non-JTAC bleeding-edge firmware"
)
@click.option(
    "--allow-unverified-checksums",
    is_flag=True,
    help="Allow placeholder/unverified package checksums (lab use only)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Live SSH triage, cleanup preview & backup; skip software add & reboot",
)
def upgrade_cmd(
    manifest: Path,
    releases: Path | None,
    firmware_dir: Path,
    site: str | None,
    model: str | None,
    hosts: tuple[str, ...],
    batch_size: int,
    max_hops: int | None,
    include_cores: bool,
    auto_cleanup: bool,
    ignore_old_cores: bool,
    transfer_mode: str,
    bind_host: str,
    http_port: int,
    allow_remote_ui: bool,
    restrict_firmware_clients: bool,
    fast_intermediate: bool,
    post_settle_seconds: float,
    allow_no_console: bool,
    refresh_snapshot: bool,
    change_number: str,
    operator: str,
    evidence_dir: Path,
    config_dir: Path,
    credentials_file: Path | None,
    username: str | None,
    password: str | None,
    password_stdin: bool,
    key_file: str | None,
    skip_release_notes_gate: bool,
    accept_bleeding_edge: bool,
    allow_unverified_checksums: bool,
    dry_run: bool,
) -> None:
    """Target switches leaf-first across topology waves and upgrade hop-by-hop until current."""
    try:
        safe_change_num = validate_safe_path_segment(change_number, "--change-number")
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    releases_path = _resolve_releases_arg(releases)
    base_url, policies, exclusions = load_release_catalog(releases_path)
    all_switches = _load_inventory_or_exit(manifest)
    graph = build_topology_graph(all_switches)
    targets = _filter_switches(all_switches, site, model, hosts)
    if not targets:
        if hosts:
            raise click.ClickException(
                "No eligible switches matched the specified --host filter(s)."
            )
        console.print("[yellow]No eligible switches matched your filters.[/yellow]")
        return

    _warn_if_bleeding_edge(
        policies,
        accept_bleeding_edge=accept_bleeding_edge,
        require_accept=(not dry_run),
        batch_size=batch_size,
        targets=targets,
    )

    creds = _load_creds_or_exit(credentials_file, username, password, password_stdin, key_file)
    factory = _make_transport_factory(creds)
    state_lock = threading.Lock()
    opts = UpgradeOptions(
        firmware_base_url=base_url,
        firmware_dir=firmware_dir,
        evidence_root=evidence_dir,
        config_root=config_dir,
        manifest_path=manifest,
        change_number=safe_change_num,
        operator=operator,
        batch_size=batch_size,
        max_hops=max_hops,
        include_cores=include_cores,
        auto_cleanup=auto_cleanup,
        ignore_old_cores=ignore_old_cores,
        transfer_mode=transfer_mode,
        require_release_notes=not skip_release_notes_gate,
        fast_intermediate_hops=fast_intermediate,
        post_settle_seconds=post_settle_seconds,
        allow_no_console=allow_no_console,
        refresh_snapshot=refresh_snapshot,
        accept_bleeding_edge=accept_bleeding_edge,
        allow_unverified_checksums=allow_unverified_checksums,
        state_lock=state_lock,
        dry_run=dry_run,
    )

    def _snapshot_topology() -> dict[str, Any]:
        with state_lock:
            snap = [SwitchRecord.from_dict(s.to_dict()) for s in list(all_switches)]
        return build_topology_graph(snap, origin=graph.origin).to_api_dict()

    need_http = (not dry_run) and (transfer_mode != "scp")
    allowed_fw_clients = (
        _resolve_restricted_firmware_clients(targets)
        if (need_http and restrict_firmware_clients)
        else None
    )
    with contextlib.ExitStack() as stack:
        srv: UnifiedFirmwareServer | None = None
        if need_http:
            try:
                srv = stack.enter_context(
                    UnifiedFirmwareServer(
                        firmware_dir=firmware_dir,
                        bind_host=bind_host,
                        port=http_port,
                        topology_provider=_snapshot_topology,
                        html_provider=render_topology_html,
                        allow_remote_ui=allow_remote_ui,
                        allowed_clients=allowed_fw_clients,
                    )
                )
            except OSError as exc:
                raise click.ClickException(
                    f"Unable to bind HTTP server on {bind_host}:{http_port}: {exc}"
                ) from exc
            console.print(
                f"[cyan]Unified HTTP+SCP firmware server & live topology UI at "
                f"http://{rich_escape(bind_host)}:{srv.port}/[/cyan]"
            )
        processed, wave_ok = run_upgrade_batches(
            all_switches,
            targets,
            policies,
            exclusions,
            factory,
            opts,
            server=srv,
            graph=graph,
        )
    if not dry_run:
        save_inventory(all_switches, manifest)

    if not processed and targets:
        console.print(
            "[yellow]0 switches processed (Core switches require --include-cores, "
            "or remaining targets are failed/held/excluded).[/yellow]"
        )
        raise click.ClickException("0 switches processed during upgrade.")

    for sw in processed:
        if sw.state in (SwitchState.COMPLETED, SwitchState.VALIDATED, SwitchState.READY):
            style = "green"
        elif sw.state == SwitchState.STAGED:
            style = "cyan"
        else:
            style = "red"
        console.print(
            f"[{style}]{rich_escape(sw.hostname)}: {rich_escape(sw.state.value)} @ "
            f"{rich_escape(sw.current_version)}[/{style}]"
        )
        if sw.last_error:
            console.print(f"  [red]Error:[/red] {rich_escape(sw.last_error)}")

    if not wave_ok:
        raise click.ClickException(
            "Wave halted due to switch failure or hardware triage quarantine."
        )


if __name__ == "__main__":
    main()
