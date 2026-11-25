# SPDX-License-Identifier: AGPL-3.0-or-later
"""Origin-anchored live dependency topology and leaf-first daisy-chain wave scheduler."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from junos_upgrader.junos_client import detect_outbound_ip
from junos_upgrader.models import NeighborExpectation, SwitchRecord, SwitchState

_MAC_CLEAN_RE = re.compile(r"[^0-9a-f]")


def _norm_host(name: str) -> str:
    """Normalize hostname to lowercase short name (stripping any FQDN domain suffix)."""
    clean = name.strip().lower()
    return clean.split(".", 1)[0] if clean else ""


def _norm_mac(mac: str) -> str:
    """Normalize MAC address (colon/hyphen/dot formats) to 12 lowercase hex digits."""
    return _MAC_CLEAN_RE.sub("", mac.strip().lower())


def _is_valid_ip(candidate: str) -> bool:
    clean = candidate.strip()
    if not clean or clean.startswith("-"):
        return False
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def _allocate_redacted_ip(index: int) -> str:
    """Deterministically allocate a valid documentation/benchmark IPv4 address for index >= 1."""
    if 1 <= index <= 254:
        return f"198.51.100.{index}"
    if 255 <= index <= 508:
        return f"203.0.113.{index - 254}"
    # Overflow cleanly into RFC 2544 benchmarking block 198.18.0.0/15, avoiding .0 and .255 hosts
    offset = index - 509
    subnet, host = divmod(offset, 254)
    base_int = int(ipaddress.IPv4Address("198.18.0.0"))
    addr_int = base_int + (subnet * 256) + (host + 1)
    max_int = int(ipaddress.IPv4Address("198.19.255.254"))
    if addr_int > max_int:
        addr_int = base_int + 1 + (offset % (max_int - base_int))
    return str(ipaddress.IPv4Address(addr_int))


@dataclass
class RunnerOrigin:
    """Local control laptop/runner identity and first-hop network origin."""

    hostname: str
    outbound_ip: str
    outbound_iface: str
    gateway_ip: str


@dataclass
class TopologyEdge:
    """Directed upstream -> downstream link in the site topology."""

    parent_id: str
    child_id: str
    parent_port: str
    child_port: str
    link_type: str = "lldp"


@dataclass
class TopologyGraph:
    """Origin-anchored dependency graph from runner laptop out to leaf switches."""

    origin: RunnerOrigin
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[TopologyEdge] = field(default_factory=list)
    ancestors: dict[str, set[str]] = field(default_factory=dict)
    redaction_map: dict[str, str] = field(default_factory=dict)

    def to_api_dict(self) -> dict[str, Any]:
        """Serialize topology for live web UI polling."""
        return {
            "origin": {
                "hostname": self.origin.hostname,
                "ip": self.origin.outbound_ip,
                "interface": self.origin.outbound_iface,
                "gateway_ip": self.origin.gateway_ip,
            },
            "nodes": list(self.nodes.values()),
            "edges": [
                {
                    "from": e.parent_id,
                    "to": e.child_id,
                    "from_port": e.parent_port,
                    "to_port": e.child_port,
                    "type": e.link_type,
                }
                for e in self.edges
            ],
        }


def detect_local_runner_origin(sample_target_ip: str = "192.0.2.1") -> RunnerOrigin:
    """Inspect local routing table to identify outbound NIC, IP, and default gateway."""
    hostname = socket.gethostname()
    clean_target = sample_target_ip.strip() if isinstance(sample_target_ip, str) else ""
    valid_target = _is_valid_ip(clean_target)
    probe_target = clean_target if valid_target else "192.0.2.1"
    outbound_ip = detect_outbound_ip(probe_target)
    outbound_iface = ""
    gateway_ip = ""

    if valid_target:
        try:
            out = subprocess.check_output(
                ["ip", "route", "get", clean_target],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            tokens = out.split()
            if "dev" in tokens:
                outbound_iface = tokens[tokens.index("dev") + 1]
            if "via" in tokens:
                gateway_ip = tokens[tokens.index("via") + 1]
            if "src" in tokens:
                outbound_ip = tokens[tokens.index("src") + 1]
        except (OSError, subprocess.SubprocessError, IndexError):
            pass

    if not gateway_ip:
        try:
            def_out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            parts = def_out.split()
            if "via" in parts:
                gateway_ip = parts[parts.index("via") + 1]
            if not outbound_iface and "dev" in parts:
                outbound_iface = parts[parts.index("dev") + 1]
        except (OSError, subprocess.SubprocessError, IndexError):
            pass

    return RunnerOrigin(
        hostname=hostname,
        outbound_ip=outbound_ip,
        outbound_iface=outbound_iface or "eth0",
        gateway_ip=gateway_ip or "",
    )


def _node_dict_from_switch(sw: SwitchRecord) -> dict[str, Any]:
    return {
        "id": sw.hostname,
        "label": sw.hostname,
        "kind": "switch",
        "site": sw.site,
        "ip": sw.management_ip,
        "model": sw.model,
        "role": sw.role,
        "version": sw.current_version,
        "next_hop": sw.next_hop,
        "final_target": sw.final_target,
        "state": sw.state.value,
        "triage": sw.triage_verdict or "pending",
        "free_mb": sw.free_storage_mb,
        "depth": sw.topology_depth,
        "upstream": sw.upstream_switch,
    }


def build_topology_graph(
    switches: list[SwitchRecord],
    sample_target_ip: str | None = None,
    origin: RunnerOrigin | None = None,
) -> TopologyGraph:
    """Compute upstream/downstream dependency tree, depths, and origin-anchored graph."""
    target_ip = sample_target_ip or (switches[0].management_ip if switches else "192.0.2.1")
    resolved_origin = origin or detect_local_runner_origin(target_ip)

    # Deduplicate exact duplicate hostnames cleanly while preserving input order
    unique_switches: list[SwitchRecord] = []
    duplicate_records: dict[str, list[SwitchRecord]] = {}
    by_host: dict[str, SwitchRecord] = {}
    for sw in switches:
        if sw.hostname in by_host:
            duplicate_records.setdefault(sw.hostname, []).append(sw)
            continue
        by_host[sw.hostname] = sw
        unique_switches.append(sw)

    # Build unambiguous normalized hostname (lowercase short name), IP, and MAC indexes
    norm_counts: dict[str, int] = {}
    for sw in unique_switches:
        nh = _norm_host(sw.hostname)
        if nh:
            norm_counts[nh] = norm_counts.get(nh, 0) + 1
    by_norm_host: dict[str, SwitchRecord] = {
        _norm_host(sw.hostname): sw
        for sw in unique_switches
        if _norm_host(sw.hostname) and norm_counts.get(_norm_host(sw.hostname), 0) == 1
    }
    by_ip: dict[str, SwitchRecord] = {
        sw.management_ip.strip(): sw for sw in unique_switches if sw.management_ip.strip()
    }
    by_mac: dict[str, SwitchRecord] = {
        _norm_mac(sw.mac_address): sw for sw in unique_switches if _norm_mac(sw.mac_address)
    }

    def _resolve_neighbor(nbr: NeighborExpectation) -> SwitchRecord | None:
        if nbr.remote_device:
            exact = by_host.get(nbr.remote_device)
            if exact is not None:
                return exact
            norm = _norm_host(nbr.remote_device)
            if norm:
                matched = by_norm_host.get(norm)
                if matched is not None:
                    return matched
        if nbr.remote_ip:
            ip_match = by_ip.get(nbr.remote_ip.strip())
            if ip_match is not None:
                return ip_match
        if nbr.remote_mac:
            mac_norm = _norm_mac(nbr.remote_mac)
            if mac_norm:
                mac_match = by_mac.get(mac_norm)
                if mac_match is not None:
                    return mac_match
        return None

    # Build undirected adjacency of managed switches with port mappings
    adj: dict[str, list[tuple[str, str, str]]] = {sw.hostname: [] for sw in unique_switches}
    explicit_upstream: dict[str, tuple[str, str, str]] = {}

    for sw in unique_switches:
        sw.downstream_switches = []
        for nbr in sw.expected_neighbors:
            remote_sw = _resolve_neighbor(nbr)
            if not remote_sw or remote_sw.hostname == sw.hostname:
                continue
            adj[sw.hostname].append((remote_sw.hostname, nbr.local_port, nbr.remote_port))
            adj[remote_sw.hostname].append((sw.hostname, nbr.remote_port, nbr.local_port))
            if nbr.is_upstream and sw.hostname not in explicit_upstream:
                # Store (parent_host, child_local_port, parent_remote_port)
                explicit_upstream[sw.hostname] = (
                    remote_sw.hostname,
                    nbr.local_port,
                    nbr.remote_port,
                )

    def _has_unmanaged_upstream(sw: SwitchRecord) -> bool:
        return any(
            nbr.is_upstream and _resolve_neighbor(nbr) is None for nbr in sw.expected_neighbors
        )

    # Identify primary roots: Core switches not downstream of another Core, else gateway-uplinked
    core_hosts = {sw.hostname for sw in unique_switches if sw.role.lower() == "core"}
    roots: list[str] = [
        sw.hostname
        for sw in unique_switches
        if sw.hostname in core_hosts
        and not (
            sw.hostname in explicit_upstream and explicit_upstream[sw.hostname][0] in core_hosts
        )
    ]
    if not roots and core_hosts:
        # Cycle among Core switches -> fall back to all Cores
        roots = [sw.hostname for sw in unique_switches if sw.hostname in core_hosts]
    if not roots:
        roots = [sw.hostname for sw in unique_switches if _has_unmanaged_upstream(sw)]

    depth: dict[str, int] = {}
    parent: dict[str, tuple[str, str, str]] = {}

    def _is_acyclic_explicit_upstream(node: str, comp_nodes: set[str], root_set: set[str]) -> bool:
        """Check that following explicit_upstream from node stays acyclic within comp_nodes."""
        if node in root_set or node not in explicit_upstream:
            return False
        seen_chain: set[str] = {node}
        cur = node
        while cur in explicit_upstream:
            nxt = explicit_upstream[cur][0]
            if nxt not in comp_nodes or nxt in seen_chain:
                return False
            if nxt in root_set:
                return True
            seen_chain.add(nxt)
            cur = nxt
        return True

    def _bfs_component(seed_roots: list[str]) -> None:
        # 1. Discover all unplaced nodes reachable in this undirected component
        comp_nodes: set[str] = set()
        scan_q: deque[str] = deque()
        for r in seed_roots:
            if r not in depth and r not in comp_nodes:
                comp_nodes.add(r)
                scan_q.append(r)
        while scan_q:
            u = scan_q.popleft()
            for v, _, _ in adj[u]:
                if v not in depth and v not in comp_nodes:
                    comp_nodes.add(v)
                    scan_q.append(v)

        root_set = {r for r in seed_roots if r in comp_nodes}

        # 2. Reserve nodes with a valid acyclic explicit_upstream for their designated parent
        reserved_parent: dict[str, str] = {}
        explicit_children: dict[str, list[tuple[str, str, str]]] = {}
        for node in comp_nodes:
            if _is_acyclic_explicit_upstream(node, comp_nodes, root_set):
                p_host, child_port, parent_port = explicit_upstream[node]
                reserved_parent[node] = p_host
                explicit_children.setdefault(p_host, []).append((node, parent_port, child_port))

        # 3. Pass A: BFS from seed_roots respecting STP explicit_upstream reservations
        queue: deque[str] = deque()
        for r in seed_roots:
            if r in comp_nodes and r not in depth:
                depth[r] = 1
                parent[r] = ("__runner__", resolved_origin.outbound_iface, "")
                queue.append(r)

        while queue:
            cur = queue.popleft()
            cur_depth = depth[cur]
            seen_nbrs: set[str] = set()

            # Expand explicit STP children first using exact root-port mappings
            for child_host, parent_port, child_port in explicit_children.get(cur, []):
                if child_host in depth or child_host in seen_nbrs:
                    continue
                seen_nbrs.add(child_host)
                depth[child_host] = cur_depth + 1
                parent[child_host] = (cur, parent_port, child_port)
                queue.append(child_host)

            # Expand undirected LLDP neighbors not reserved for another parent
            for nbr_host, local_port, remote_port in adj[cur]:
                if nbr_host not in comp_nodes or nbr_host in seen_nbrs or nbr_host in depth:
                    continue
                seen_nbrs.add(nbr_host)
                if nbr_host in reserved_parent and reserved_parent[nbr_host] != cur:
                    continue
                depth[nbr_host] = cur_depth + 1
                parent[nbr_host] = (cur, local_port, remote_port)
                queue.append(nbr_host)

        # 4. Pass B fallback: attach any remaining nodes in comp_nodes (e.g., broken by cycles)
        unplaced = comp_nodes - set(depth)
        if unplaced:
            placed_sorted = sorted(comp_nodes & set(depth), key=lambda h: depth[h])
            fallback_q: deque[str] = deque(placed_sorted)
            while fallback_q:
                cur = fallback_q.popleft()
                cur_depth = depth[cur]
                seen_nbrs = set()
                for nbr_host, local_port, remote_port in adj[cur]:
                    if nbr_host not in comp_nodes or nbr_host in seen_nbrs or nbr_host in depth:
                        continue
                    seen_nbrs.add(nbr_host)
                    depth[nbr_host] = cur_depth + 1
                    parent[nbr_host] = (cur, local_port, remote_port)
                    fallback_q.append(nbr_host)

    # Run BFS for primary roots if any exist
    if roots:
        _bfs_component(roots)

    # Run per-component BFS for any disconnected components so internal trees stay intact
    for sw in unique_switches:
        if sw.hostname in depth:
            continue
        # Discover this disconnected component
        comp_order: list[str] = []
        comp_set: set[str] = {sw.hostname}
        cq: deque[str] = deque([sw.hostname])
        while cq:
            u = cq.popleft()
            comp_order.append(u)
            for v, _, _ in adj[u]:
                if v not in depth and v not in comp_set:
                    comp_set.add(v)
                    cq.append(v)

        # Choose root(s) for this disconnected component:
        # 1) Unmanaged gateway uplink, 2) nodes without an in-component explicit_upstream
        #    (preferring those pointed to as upstream by others), 3) first node deterministically.
        comp_roots = [h for h in comp_order if _has_unmanaged_upstream(by_host[h])]
        if not comp_roots:
            targeted_counts: dict[str, int] = {}
            for h in comp_order:
                exp = explicit_upstream.get(h)
                if exp and exp[0] in comp_set:
                    targeted_counts[exp[0]] = targeted_counts.get(exp[0], 0) + 1
            no_in_comp_parent = [
                h
                for h in comp_order
                if h not in explicit_upstream or explicit_upstream[h][0] not in comp_set
            ]
            if no_in_comp_parent:
                # Prefer a node that other nodes point to as upstream; tie-break by input order
                best_root = max(no_in_comp_parent, key=lambda h: targeted_counts.get(h, 0))
                comp_roots = [best_root]
            else:
                comp_roots = [comp_order[0]]

        _bfs_component(comp_roots)

    # Populate SwitchRecord topology fields
    edges: list[TopologyEdge] = []
    for sw in unique_switches:
        sw.topology_depth = depth[sw.hostname]
        p_host, p_port, c_port = parent[sw.hostname]
        if p_host == "__runner__":
            # Only match gateway IP when resolved_origin.gateway_ip is non-empty
            gw_nbr = next(
                (
                    n
                    for n in sw.expected_neighbors
                    if _resolve_neighbor(n) is None
                    and (
                        n.is_upstream
                        or (
                            bool(resolved_origin.gateway_ip)
                            and n.remote_ip.strip() == resolved_origin.gateway_ip
                        )
                    )
                ),
                None,
            )
            sw.upstream_switch = gw_nbr.remote_device if gw_nbr else resolved_origin.hostname
            sw.upstream_local_port = gw_nbr.local_port if gw_nbr else ""
            sw.upstream_remote_port = (
                gw_nbr.remote_port if gw_nbr else resolved_origin.outbound_iface
            )
            edges.append(
                TopologyEdge(
                    parent_id="__runner__",
                    child_id=sw.hostname,
                    parent_port=resolved_origin.outbound_iface,
                    child_port=sw.upstream_local_port or "mgmt",
                    link_type="uplink",
                )
            )
        else:
            sw.upstream_switch = p_host
            sw.upstream_local_port = c_port
            sw.upstream_remote_port = p_port
            by_host[p_host].downstream_switches.append(sw.hostname)
            edges.append(
                TopologyEdge(
                    parent_id=p_host,
                    child_id=sw.hostname,
                    parent_port=p_port,
                    child_port=c_port,
                    link_type="lldp",
                )
            )

    # Mirror computed topology fields onto any duplicate records for consistency
    for host, dupes in duplicate_records.items():
        primary = by_host[host]
        for dup in dupes:
            dup.topology_depth = primary.topology_depth
            dup.upstream_switch = primary.upstream_switch
            dup.upstream_local_port = primary.upstream_local_port
            dup.upstream_remote_port = primary.upstream_remote_port
            dup.downstream_switches = list(primary.downstream_switches)

    # Compute ancestor sets for branch-disjoint scheduling
    ancestors: dict[str, set[str]] = {}
    for sw in unique_switches:
        anc: set[str] = set()
        cur = sw.hostname
        while cur in parent:
            p_host = parent[cur][0]
            if p_host == "__runner__" or p_host == sw.hostname or p_host in anc:
                break
            anc.add(p_host)
            cur = p_host
        ancestors[sw.hostname] = anc

    nodes: dict[str, dict[str, Any]] = {
        "__runner__": {
            "id": "__runner__",
            "label": f"{resolved_origin.hostname} (Runner)",
            "kind": "runner",
            "site": "LOCAL",
            "ip": resolved_origin.outbound_ip,
            "model": f"NIC {resolved_origin.outbound_iface}",
            "role": "Controller",
            "version": f"GW {resolved_origin.gateway_ip or 'local'}",
            "next_hop": "",
            "final_target": "",
            "state": "runner",
            "triage": "ok",
            "free_mb": None,
            "depth": 0,
            "upstream": "",
        }
    }
    for sw in unique_switches:
        nodes[sw.hostname] = _node_dict_from_switch(sw)

    return TopologyGraph(origin=resolved_origin, nodes=nodes, edges=edges, ancestors=ancestors)


def compute_topology_waves(
    targets: list[SwitchRecord],
    graph: TopologyGraph,
    batch_size: int = 1,
    include_cores: bool = False,
) -> list[list[SwitchRecord]]:
    """Order switches strictly deepest-leaf-first and prevent upstream+downstream pairing."""
    blocked_states = {
        SwitchState.EXCLUDED,
        SwitchState.COMPLETED,
        SwitchState.REPLACE_RECOMMENDED,
        SwitchState.FAILED,
        SwitchState.ANCESTOR_HOLD,
    }
    failed_states = {SwitchState.FAILED, SwitchState.REPLACE_RECOMMENDED}
    failed_values = {SwitchState.FAILED.value, SwitchState.REPLACE_RECOMMENDED.value}

    # Hold ancestors of any pre-existing FAILED or REPLACE_RECOMMENDED switches
    failed_hosts: set[str] = {sw.hostname for sw in targets if sw.state in failed_states}
    for node_id, node in graph.nodes.items():
        if node.get("kind") == "switch" and node.get("state") in failed_values:
            failed_hosts.add(node_id)

    held_ancestors: set[str] = set()
    for fh in failed_hosts:
        held_ancestors |= graph.ancestors.get(fh, set())

    eligible = [
        sw
        for sw in targets
        if sw.state not in blocked_states
        and sw.hostname not in held_ancestors
        and (include_cores or sw.role.lower() != "core")
    ]
    # Deepest leaves first; tie-break deterministically by site and hostname
    eligible.sort(key=lambda s: (-s.topology_depth, s.site, s.hostname))

    waves: list[list[SwitchRecord]] = []
    remaining = list(eligible)
    size = max(1, batch_size)

    while remaining:
        wave: list[SwitchRecord] = []
        wave_hosts: set[str] = set()
        next_remaining: list[SwitchRecord] = []

        for sw in remaining:
            if len(wave) >= size:
                next_remaining.append(sw)
                continue
            sw_anc = graph.ancestors.get(sw.hostname, set())
            # Disjoint branch check: neither sw nor any already-picked switch can be an ancestor of the other
            conflict = bool(sw_anc & wave_hosts) or any(
                sw.hostname in graph.ancestors.get(w.hostname, set()) for w in wave
            )
            if conflict:
                next_remaining.append(sw)
            else:
                wave.append(sw)
                wave_hosts.add(sw.hostname)

        if not wave:
            # Fallback single item to avoid infinite loop
            wave.append(next_remaining.pop(0))
        waves.append(wave)
        remaining = next_remaining

    return waves


def mark_ancestor_holds(
    failed_switch: SwitchRecord,
    all_switches: list[SwitchRecord],
    graph: TopologyGraph,
) -> list[str]:
    """Place upstream transit ancestors of a failed switch on ANCESTOR_HOLD."""
    by_host = {sw.hostname: sw for sw in all_switches}
    held: list[str] = []
    reason = f"Held because downstream dependent {failed_switch.hostname} failed/needs replacement."
    for anc_host in sorted(graph.ancestors.get(failed_switch.hostname, set())):
        anc_sw = by_host.get(anc_host)
        if anc_sw and anc_sw.state not in (
            SwitchState.EXCLUDED,
            SwitchState.COMPLETED,
            SwitchState.FAILED,
            SwitchState.REPLACE_RECOMMENDED,
        ):
            if anc_sw.state == SwitchState.ANCESTOR_HOLD:
                if failed_switch.hostname not in anc_sw.last_error:
                    anc_sw.last_error = (
                        f"{anc_sw.last_error}; {reason}" if anc_sw.last_error else reason
                    )
            else:
                anc_sw.state = SwitchState.ANCESTOR_HOLD
                anc_sw.last_error = reason
                held.append(anc_host)
    return held


def redact_topology_graph(graph: TopologyGraph) -> TopologyGraph:
    """Return a sanitized copy of graph with anonymized hostnames and RFC 5737/2544 IPs."""
    origin = RunnerOrigin(
        hostname="RUNNER",
        outbound_ip="192.0.2.10",
        outbound_iface="eth0",
        gateway_ip="192.0.2.1",
    )
    id_map: dict[str, str] = {"__runner__": "__runner__"}
    redaction_map: dict[str, str] = {}
    sw_idx = 0
    for node_id in graph.nodes:
        if node_id != "__runner__":
            sw_idx += 1
            alias = f"SW-{sw_idx:02d}"
            id_map[node_id] = alias
            redaction_map[node_id] = alias

    nodes: dict[str, dict[str, Any]] = {}
    for node_id, node in graph.nodes.items():
        if node_id == "__runner__":
            nodes["__runner__"] = {
                **node,
                "label": "RUNNER (Controller)",
                "ip": origin.outbound_ip,
                "model": "NIC eth0",
                "version": f"GW {origin.gateway_ip}",
            }
            continue
        alias = id_map[node_id]
        alias_num = int(alias.split("-")[1])
        nodes[alias] = {
            **node,
            "id": alias,
            "label": alias,
            "site": "SITE",
            "ip": _allocate_redacted_ip(alias_num),
            "upstream": id_map.get(str(node.get("upstream", "")), "RUNNER"),
        }

    edges = [
        TopologyEdge(
            parent_id=id_map.get(e.parent_id, e.parent_id),
            child_id=id_map.get(e.child_id, e.child_id),
            parent_port="eth0" if e.parent_id == "__runner__" else e.parent_port,
            child_port=e.child_port,
            link_type=e.link_type,
        )
        for e in graph.edges
    ]
    ancestors = {
        id_map.get(k, k): {id_map.get(a, a) for a in v} for k, v in graph.ancestors.items()
    }
    return TopologyGraph(
        origin=origin,
        nodes=nodes,
        edges=edges,
        ancestors=ancestors,
        redaction_map=redaction_map,
    )
