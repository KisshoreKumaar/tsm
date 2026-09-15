"""Campaign correlation (F1): link incidents that share entities within the campaign window.

Links are explained (type, shared value, time delta, supporting events, strength). Campaigns are connected components
of the link graph, so they are a pure function of the stored incidents and never depend on arrival order.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import combinations
from typing import Any

from app.core.timeutil import parse_iso

LINK_NAMESPACE = uuid.UUID("0f4f2a7e-3b61-4d0c-8f25-7f3c2d9a41b2")


@dataclass(frozen=True)
class LinkType:
    entity_type: str
    link_type: str
    weight: float
    label: str
    reason: str


LINK_TYPES: dict[str, LinkType] = {
    "user": LinkType("user", "same_user", 0.6, "user", "The same user account is active on different assets"),
    "source_ip": LinkType(
        "source_ip", "same_external_source_ip", 0.8, "source IP", "The same external source IP reached different assets"
    ),
    "destination_ip": LinkType(
        "destination_ip",
        "same_external_destination_ip",
        0.5,
        "destination IP",
        "Different assets contacted the same external IP",
    ),
    "domain": LinkType("domain", "same_domain", 0.7, "domain", "Different assets involve the same domain"),
    "file_hash": LinkType(
        "file_hash", "same_file_hash", 0.9, "file hash", "The same file hash appears on different assets"
    ),
}
LINKABLE_ENTITY_TYPES = tuple(LINK_TYPES)

# Shared internal infrastructure (file servers, DNS, scanners) would over-link; only external IPs create links.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)


def is_external_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_multicast or address.is_unspecified:
        return False
    return not any(address.version == network.version and address in network for network in _INTERNAL_NETWORKS)


def allowlist_keys(entity_type: str, value: str) -> set[str]:
    keys = {f"{entity_type}:{value}".lower()}
    if entity_type in ("source_ip", "destination_ip"):
        keys.add(f"ip:{value}".lower())
    return keys


def humanize_seconds(seconds: int) -> str:
    if seconds <= 0:
        return "overlapping in time"
    if seconds < 60:
        return f"{seconds} s apart"
    if seconds < 3600:
        return f"{seconds // 60} min apart"
    return f"{seconds / 3600:.1f} h apart"


@dataclass(frozen=True)
class IncidentNode:
    id: str
    asset: str
    username: str
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    severity: str
    title: str
    status: str

    @classmethod
    def from_row(cls, row: Any) -> IncidentNode:
        return cls(
            id=row["id"],
            asset=row["asset"],
            username=row["username"],
            first_seen=parse_iso(row["first_seen"]),
            last_seen=parse_iso(row["last_seen"]),
            risk_score=int(row["risk_score"]),
            severity=row["severity"],
            title=row["title"],
            status=row["status"],
        )


@dataclass(frozen=True)
class Link:
    incident_a: str
    incident_b: str
    link_type: str
    entity_type: str
    entity_value: str
    time_delta_seconds: int
    strength: float
    supporting_event_ids: tuple[str, ...]

    @property
    def id(self) -> str:
        return str(
            uuid.uuid5(LINK_NAMESPACE, f"{self.incident_a}|{self.incident_b}|{self.entity_type}|{self.entity_value}")
        )

    @property
    def reason(self) -> str:
        return f"Shared {LINK_TYPES[self.entity_type].label} {self.entity_value}; {humanize_seconds(self.time_delta_seconds)}"

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "incident_a": self.incident_a,
            "incident_b": self.incident_b,
            "link_type": self.link_type,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "time_delta_seconds": self.time_delta_seconds,
            "strength": self.strength,
            "supporting_event_ids": list(self.supporting_event_ids),
            "reason": self.reason,
        }


def activity_gap_seconds(a: IncidentNode, b: IncidentNode) -> int:
    if a.last_seen < b.first_seen:
        return int((b.first_seen - a.last_seen).total_seconds())
    if b.last_seen < a.first_seen:
        return int((a.first_seen - b.last_seen).total_seconds())
    return 0


def compute_links(
    nodes: Mapping[str, IncidentNode],
    entity_rows: Iterable[tuple[str, str, str, str]],
    *,
    window_seconds: int,
    allowlist: frozenset[str],
    max_degree: int,
) -> list[Link]:
    """`entity_rows` are (incident_id, entity_type, value, event_id). Entities shared by more than `max_degree`
    incidents are treated as too common to be meaningful and create no links."""
    occurrences: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for incident_id, entity_type, value, event_id in entity_rows:
        if incident_id not in nodes or entity_type not in LINK_TYPES:
            continue
        if entity_type in ("source_ip", "destination_ip") and not is_external_ip(value):
            continue
        if allowlist_keys(entity_type, value) & allowlist:
            continue
        occurrences[(entity_type, value)][incident_id].add(event_id)
    links: list[Link] = []
    for (entity_type, value), by_incident in sorted(occurrences.items()):
        if len(by_incident) < 2 or len(by_incident) > max_degree:
            continue
        spec = LINK_TYPES[entity_type]
        for first, second in combinations(sorted(by_incident), 2):
            a, b = nodes[first], nodes[second]
            if a.asset == b.asset:
                continue
            gap = activity_gap_seconds(a, b)
            if gap > window_seconds:
                continue
            strength = round(spec.weight * (1 - 0.5 * gap / window_seconds), 2)
            support = tuple(sorted(by_incident[first])[:10] + sorted(by_incident[second])[:10])
            links.append(Link(first, second, spec.link_type, entity_type, value, gap, strength, support))
    return links


def link_components(node_ids: Iterable[str], links: Sequence[Link]) -> list[list[str]]:
    parent = {node: node for node in node_ids}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    for link in links:
        root_a, root_b = find(link.incident_a), find(link.incident_b)
        if root_a != root_b:
            parent[max(root_a, root_b)] = min(root_a, root_b)
    groups: dict[str, list[str]] = defaultdict(list)
    for node in parent:
        groups[find(node)].append(node)
    return sorted((sorted(group) for group in groups.values() if len(group) >= 2), key=lambda group: group[0])
