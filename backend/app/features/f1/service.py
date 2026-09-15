"""Campaign persistence, queries, entity pivots and graph data (F1)."""

from __future__ import annotations

import ipaddress
import json
import uuid
from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from app.core.db import Session
from app.core.errors import ApiError, NotFound
from app.core.jsonutil import canonical_json, sha256_json
from app.core.timeutil import iso
from app.correlation.campaigns import (
    LINK_TYPES,
    LINKABLE_ENTITY_TYPES,
    IncidentNode,
    Link,
    allowlist_keys,
    compute_links,
    is_external_ip,
    link_components,
)
from app.detection.risk import band
from app.features.core.incidents import incident_summary
from app.ingest.normalize import ENTITY_TYPES

CAMPAIGN_EXCLUDED_STATUSES = ("MERGED", "FALSE_POSITIVE")
TIMELINE_LIMIT = 500


def setup(ctx: Any) -> None:
    service = CampaignService(ctx)
    ctx.services["campaigns"] = service
    ctx.service("pipeline").change_hooks.append(lambda session, _incident_ids, actor: service.recompute(session, actor))


def _link_from_row(row: Any) -> Link:
    return Link(
        incident_a=row["incident_a"],
        incident_b=row["incident_b"],
        link_type=row["link_type"],
        entity_type=row["entity_type"],
        entity_value=row["entity_value"],
        time_delta_seconds=int(row["time_delta_seconds"]),
        strength=float(row["strength"]),
        supporting_event_ids=tuple(json.loads(row["supporting_event_ids"])),
    )


def campaign_summary(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "status": row["status"],
        "merged_into": row["merged_into"],
        "revision": row["revision"],
        "title": row["title"],
        "risk_score": row["risk_score"],
        "severity": row["severity"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "incident_count": row["incident_count"],
        "assets": json.loads(row["assets"]),
        "users": json.loads(row["users"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


class CampaignService:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    # -- recomputation (inside the caller's write transaction) ---------------------------------------

    def recompute(self, session: Session, actor: str) -> list[str]:
        ctx = self._ctx
        settings = ctx.settings
        marks = ",".join("?" * len(CAMPAIGN_EXCLUDED_STATUSES))
        rows = session.all(
            "SELECT id, asset, username, first_seen, last_seen, risk_score, severity, title, status FROM incidents "
            f"WHERE status NOT IN ({marks})",
            CAMPAIGN_EXCLUDED_STATUSES,
        )
        nodes = {row["id"]: IncidentNode.from_row(row) for row in rows}
        type_marks = ",".join("?" * len(LINKABLE_ENTITY_TYPES))
        entity_rows = [
            (row["incident_id"], row["entity_type"], row["value"], row["event_id"])
            for row in session.all(
                "SELECT ie.incident_id, ee.entity_type, ee.value, ee.event_id FROM incident_events ie "
                "JOIN incidents i ON i.id = ie.incident_id JOIN event_entities ee ON ee.event_id = ie.event_id "
                f"WHERE i.status NOT IN ({marks}) AND ee.entity_type IN ({type_marks})",
                [*CAMPAIGN_EXCLUDED_STATUSES, *LINKABLE_ENTITY_TYPES],
            )
        ]
        links = compute_links(
            nodes,
            entity_rows,
            window_seconds=settings.campaign_window_seconds,
            allowlist=settings.common_entities,
            max_degree=settings.max_link_degree,
        )
        components = link_components(nodes, links)
        components.sort(key=lambda members: (min(nodes[i].first_seen for i in members), members[0]))

        existing = session.all("SELECT * FROM campaigns WHERE status = 'ACTIVE' ORDER BY created_at, id")
        membership: dict[str, set[str]] = defaultdict(set)
        for row in session.all(
            "SELECT ci.campaign_id, ci.incident_id FROM campaign_incidents ci JOIN campaigns c ON c.id = ci.campaign_id "
            "WHERE c.status = 'ACTIVE'"
        ):
            membership[row["campaign_id"]].add(row["incident_id"])

        now = iso(ctx.clock.now())
        claimed: set[str] = set()
        touched: list[str] = []
        link_campaign: dict[str, str] = {}
        for members in components:
            member_set = set(members)
            component_links = [link for link in links if link.incident_a in member_set]
            summary = self._summarize(members, component_links, nodes)
            fingerprint = sha256_json(
                {
                    "incidents": members,
                    "links": sorted([link.id, link.strength] for link in component_links),
                    "risk": summary["risk_score"],
                    "title": summary["title"],
                }
            )
            overlapping = [c for c in existing if c["id"] not in claimed and membership[c["id"]] & member_set]
            if overlapping:
                canonical = overlapping[0]
                campaign_id = canonical["id"]
                claimed.add(campaign_id)
                for other in overlapping[1:]:
                    claimed.add(other["id"])
                    session.execute(
                        "UPDATE campaigns SET status = 'MERGED', merged_into = ?, revision = revision + 1, updated_at = ? "
                        "WHERE id = ?",
                        (campaign_id, now, other["id"]),
                    )
                    session.execute("DELETE FROM campaign_incidents WHERE campaign_id = ?", (other["id"],))
                    ctx.audit.append(
                        session,
                        "campaign.merged",
                        actor,
                        {"campaign_id": other["id"], "merged_into": campaign_id},
                        subject=("campaign", other["id"]),
                    )
                    touched.append(other["id"])
                if canonical["fingerprint"] != fingerprint or membership[campaign_id] != member_set:
                    revision = int(canonical["revision"]) + 1
                    session.execute(
                        "UPDATE campaigns SET revision = ?, title = ?, risk_score = ?, severity = ?, risk_factors = ?, "
                        "first_seen = ?, last_seen = ?, incident_count = ?, assets = ?, users = ?, fingerprint = ?, "
                        "updated_at = ? WHERE id = ?",
                        (
                            revision,
                            summary["title"],
                            summary["risk_score"],
                            summary["severity"],
                            summary["risk_factors"],
                            summary["first_seen"],
                            summary["last_seen"],
                            len(members),
                            summary["assets"],
                            summary["users"],
                            fingerprint,
                            now,
                            campaign_id,
                        ),
                    )
                    self._replace_members(session, campaign_id, members)
                    ctx.audit.append(
                        session,
                        "campaign.updated",
                        actor,
                        {
                            "campaign_id": campaign_id,
                            "revision": revision,
                            "incident_ids": members,
                            "links": len(component_links),
                        },
                        subject=("campaign", campaign_id),
                    )
                    touched.append(campaign_id)
            else:
                campaign_id = str(uuid.uuid4())
                session.execute(
                    "INSERT INTO campaigns (id, status, revision, title, risk_score, severity, risk_factors, first_seen, "
                    "last_seen, incident_count, assets, users, fingerprint, created_at, updated_at) "
                    "VALUES (?, 'ACTIVE', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        campaign_id,
                        summary["title"],
                        summary["risk_score"],
                        summary["severity"],
                        summary["risk_factors"],
                        summary["first_seen"],
                        summary["last_seen"],
                        len(members),
                        summary["assets"],
                        summary["users"],
                        fingerprint,
                        now,
                        now,
                    ),
                )
                self._replace_members(session, campaign_id, members)
                ctx.audit.append(
                    session,
                    "campaign.created",
                    actor,
                    {"campaign_id": campaign_id, "incident_ids": members, "links": len(component_links)},
                    subject=("campaign", campaign_id),
                )
                touched.append(campaign_id)
            for link in component_links:
                link_campaign[link.id] = campaign_id

        for campaign in existing:
            if campaign["id"] in claimed:
                continue
            session.execute(
                "UPDATE campaigns SET status = 'DISSOLVED', revision = revision + 1, updated_at = ? WHERE id = ?",
                (now, campaign["id"]),
            )
            session.execute("DELETE FROM campaign_incidents WHERE campaign_id = ?", (campaign["id"],))
            ctx.audit.append(
                session,
                "campaign.dissolved",
                actor,
                {"campaign_id": campaign["id"], "reason": "Its incidents are no longer linked"},
                subject=("campaign", campaign["id"]),
            )
            touched.append(campaign["id"])

        current = {
            (row["id"], float(row["strength"]), row["campaign_id"])
            for row in session.all("SELECT id, strength, campaign_id FROM correlation_links")
        }
        desired = {(link.id, link.strength, link_campaign[link.id]) for link in links}
        if current != desired:
            session.execute("DELETE FROM correlation_links")
            session.executemany(
                "INSERT INTO correlation_links (id, incident_a, incident_b, link_type, entity_type, entity_value, "
                "time_delta_seconds, strength, supporting_event_ids, campaign_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        link.id,
                        link.incident_a,
                        link.incident_b,
                        link.link_type,
                        link.entity_type,
                        link.entity_value,
                        link.time_delta_seconds,
                        link.strength,
                        canonical_json(list(link.supporting_event_ids)),
                        link_campaign[link.id],
                        now,
                    )
                    for link in links
                ],
            )
        if touched:
            changed = list(touched)
            session.after_commit(lambda: ctx.bus.publish("campaign.updated", {"campaign_ids": changed}))
        return touched

    @staticmethod
    def _replace_members(session: Session, campaign_id: str, members: Sequence[str]) -> None:
        session.execute("DELETE FROM campaign_incidents WHERE campaign_id = ?", (campaign_id,))
        session.executemany(
            "INSERT INTO campaign_incidents (campaign_id, incident_id) VALUES (?, ?)",
            [(campaign_id, incident_id) for incident_id in members],
        )

    @staticmethod
    def _summarize(members: Sequence[str], links: Sequence[Link], nodes: dict[str, IncidentNode]) -> dict[str, Any]:
        incidents = [nodes[i] for i in members]
        assets = sorted({n.asset for n in incidents})
        users = sorted({n.username for n in incidents})
        top = max(incidents, key=lambda n: n.risk_score)
        breadth = min(15, 5 * (len(assets) - 1))
        multi_user = 5 if len(users) > 1 else 0
        score = min(100, top.risk_score + breadth + multi_user)
        factors = [
            {
                "name": "highest_incident_risk",
                "label": "Highest incident risk",
                "points": top.risk_score,
                "max_points": 100,
                "explanation": f"Highest-risk member incident scores {top.risk_score}",
            },
            {
                "name": "asset_breadth",
                "label": "Asset breadth",
                "points": breadth,
                "max_points": 15,
                "explanation": f"{len(assets)} assets affected",
            },
            {
                "name": "multiple_users",
                "label": "Multiple users",
                "points": multi_user,
                "max_points": 5,
                "explanation": f"{len(users)} user account(s) involved",
            },
        ]
        parts: list[str] = []
        for entity_type in ("user", "source_ip", "destination_ip", "domain", "file_hash"):
            values = sorted({link.entity_value for link in links if link.entity_type == entity_type})
            if values:
                shown = ", ".join(values[:2]) + (f" (+{len(values) - 2})" if len(values) > 2 else "")
                parts.append(f"{LINK_TYPES[entity_type].label} {shown}")
        title = (
            f"Shared {' and '.join(parts)} across {len(assets)} assets" if parts else f"{len(members)} linked incidents"
        )
        return {
            "title": title[:200],
            "risk_score": score,
            "severity": band(score),
            "risk_factors": canonical_json(factors),
            "first_seen": iso(min(n.first_seen for n in incidents)),
            "last_seen": iso(max(n.last_seen for n in incidents)),
            "assets": canonical_json(assets),
            "users": canonical_json(users),
        }

    # -- queries -------------------------------------------------------------------------------------

    def count(self) -> int:
        with self._ctx.db.read() as session:
            return int(session.scalar("SELECT count(*) FROM campaigns WHERE status = 'ACTIVE'"))

    def list(self, *, status: str = "ACTIVE", offset: int = 0, limit: int = 50) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            total = session.scalar("SELECT count(*) FROM campaigns WHERE status = ?", (status,))
            rows = session.all(
                "SELECT * FROM campaigns WHERE status = ? ORDER BY risk_score DESC, updated_at DESC, id LIMIT ? OFFSET ?",
                (status, limit, offset),
            )
        return {"items": [campaign_summary(r) for r in rows], "total": total, "offset": offset, "limit": limit}

    def member_ids(self, session: Session, campaign_id: str) -> list[str]:
        return [
            r["incident_id"]
            for r in session.all(
                "SELECT incident_id FROM campaign_incidents WHERE campaign_id = ? ORDER BY incident_id", (campaign_id,)
            )
        ]

    def _incident_rows(self, session: Session, incident_ids: Sequence[str]) -> list[Any]:
        if not incident_ids:
            return []
        marks = ",".join("?" * len(incident_ids))
        return session.all(
            "SELECT i.*, (SELECT group_concat(DISTINCT d.rule_id) FROM detections d "
            "WHERE d.incident_id = i.id AND d.status = 'ACTIVE') AS rules "
            f"FROM incidents i WHERE i.id IN ({marks}) ORDER BY i.first_seen, i.id",
            list(incident_ids),
        )

    def get(self, campaign_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            row = session.one("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
            if row is None:
                raise NotFound("Unknown campaign")
            members = self.member_ids(session, campaign_id)
            incidents = self._incident_rows(session, members)
            links = [
                _link_from_row(r)
                for r in session.all(
                    "SELECT * FROM correlation_links WHERE campaign_id = ? ORDER BY strength DESC, id", (campaign_id,)
                )
            ]
            timeline: list[dict[str, Any]] = []
            if members:
                marks = ",".join("?" * len(members))
                for event in session.all(
                    "SELECT e.id, e.ts, e.kind, e.asset, e.username, e.source, e.source_ip, e.destination_ip, "
                    "e.destination_port, e.process_name, e.command_line, e.file_path, e.details, e.injection_suspected, "
                    f"ie.incident_id FROM events e JOIN incident_events ie ON ie.event_id = e.id WHERE ie.incident_id IN ({marks}) "
                    "ORDER BY e.ts, e.id LIMIT ?",
                    [*members, TIMELINE_LIMIT + 1],
                ):
                    timeline.append(
                        {
                            "id": event["id"],
                            "timestamp": event["ts"],
                            "kind": event["kind"],
                            "asset": event["asset"],
                            "user": event["username"],
                            "source": event["source"],
                            "source_ip": event["source_ip"],
                            "destination_ip": event["destination_ip"],
                            "destination_port": event["destination_port"],
                            "process_name": event["process_name"],
                            "command_line": event["command_line"],
                            "file_path": event["file_path"],
                            "details": event["details"],
                            "injection_suspected": bool(event["injection_suspected"]),
                            "incident_id": event["incident_id"],
                        }
                    )
        by_id = {r["id"]: r for r in incidents}
        return {
            **campaign_summary(row),
            "risk": {
                "score": row["risk_score"],
                "severity": row["severity"],
                "label": "Heuristic campaign score; not a probability.",
                "factors": json.loads(row["risk_factors"]),
            },
            "incidents": [incident_summary(r) for r in incidents],
            "links": [
                {
                    **link.public(),
                    "asset_a": by_id[link.incident_a]["asset"] if link.incident_a in by_id else None,
                    "asset_b": by_id[link.incident_b]["asset"] if link.incident_b in by_id else None,
                }
                for link in links
            ],
            "timeline": timeline[:TIMELINE_LIMIT],
            "timeline_truncated": len(timeline) > TIMELINE_LIMIT,
        }

    def related(self, incident_id: str) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            if session.one("SELECT id FROM incidents WHERE id = ?", (incident_id,)) is None:
                raise NotFound("Unknown incident")
            campaign = session.one(
                "SELECT c.* FROM campaigns c JOIN campaign_incidents ci ON ci.campaign_id = c.id "
                "WHERE ci.incident_id = ? AND c.status = 'ACTIVE'",
                (incident_id,),
            )
            links = [
                _link_from_row(r)
                for r in session.all(
                    "SELECT * FROM correlation_links WHERE incident_a = ? OR incident_b = ? ORDER BY strength DESC, id",
                    (incident_id, incident_id),
                )
            ]
            related_ids = {link.incident_b if link.incident_a == incident_id else link.incident_a for link in links}
            if campaign is not None:
                related_ids.update(self.member_ids(session, campaign["id"]))
            related_ids.discard(incident_id)
            incidents = self._incident_rows(session, sorted(related_ids))
        assets = {r["id"]: r["asset"] for r in incidents}
        return {
            "incident_id": incident_id,
            "campaign": campaign_summary(campaign) if campaign is not None else None,
            "links": [
                {
                    **link.public(),
                    "other_incident_id": link.incident_b if link.incident_a == incident_id else link.incident_a,
                    "other_asset": assets.get(link.incident_b if link.incident_a == incident_id else link.incident_a),
                }
                for link in links
            ],
            "related_incidents": [incident_summary(r) for r in incidents],
        }

    def entity(self, entity_type: str, value: str) -> dict[str, Any]:
        if entity_type not in ENTITY_TYPES:
            raise NotFound("Unknown entity type")
        if entity_type in ("source_ip", "destination_ip"):
            try:
                normalized = str(ipaddress.ip_address(value))
            except ValueError:
                raise ApiError("Invalid IP address", code="invalid_entity", status_code=422) from None
        else:
            normalized = value.strip().lower()
        settings = self._ctx.settings
        with self._ctx.db.read() as session:
            stats = session.one(
                "SELECT count(*) AS events, min(e.ts) AS first_seen, max(e.ts) AS last_seen FROM event_entities ee "
                "JOIN events e ON e.id = ee.event_id WHERE ee.entity_type = ? AND ee.value = ?",
                (entity_type, normalized),
            )
            incident_ids = [
                r["incident_id"]
                for r in session.all(
                    "SELECT DISTINCT ie.incident_id FROM event_entities ee JOIN incident_events ie ON ie.event_id = ee.event_id "
                    "JOIN incidents i ON i.id = ie.incident_id WHERE ee.entity_type = ? AND ee.value = ? AND i.status != 'MERGED'",
                    (entity_type, normalized),
                )
            ]
            incidents = self._incident_rows(session, incident_ids[:100])
            assets = sorted(
                r["asset"]
                for r in session.all(
                    "SELECT DISTINCT e.asset FROM event_entities ee JOIN events e ON e.id = ee.event_id "
                    "WHERE ee.entity_type = ? AND ee.value = ? LIMIT 100",
                    (entity_type, normalized),
                )
            )
            users = sorted(
                r["username"]
                for r in session.all(
                    "SELECT DISTINCT e.username FROM event_entities ee JOIN events e ON e.id = ee.event_id "
                    "WHERE ee.entity_type = ? AND ee.value = ? LIMIT 100",
                    (entity_type, normalized),
                )
            )
        allowlisted = bool(allowlist_keys(entity_type, normalized) & settings.common_entities)
        degree = len([r for r in incidents if r["status"] not in CAMPAIGN_EXCLUDED_STATUSES])
        linkable = (
            entity_type in LINK_TYPES
            and not allowlisted
            and (entity_type not in ("source_ip", "destination_ip") or is_external_ip(normalized))
        )
        return {
            "entity_type": entity_type,
            "value": normalized,
            "events": stats["events"] if stats else 0,
            "first_seen": stats["first_seen"] if stats else None,
            "last_seen": stats["last_seen"] if stats else None,
            "assets": assets,
            "users": users,
            "incidents": [incident_summary(r) for r in incidents],
            "allowlisted": allowlisted,
            "degree": degree,
            "max_link_degree": settings.max_link_degree,
            "linkable": linkable and degree <= settings.max_link_degree,
        }

    def graph(
        self, *, campaign_id: str | None = None, incident_id: str | None = None, limit: int = 150
    ) -> dict[str, Any]:
        with self._ctx.db.read() as session:
            if campaign_id:
                if session.one("SELECT id FROM campaigns WHERE id = ?", (campaign_id,)) is None:
                    raise NotFound("Unknown campaign")
                ids = set(self.member_ids(session, campaign_id))
            elif incident_id:
                if session.one("SELECT id FROM incidents WHERE id = ?", (incident_id,)) is None:
                    raise NotFound("Unknown incident")
                ids = {incident_id}
                for row in session.all(
                    "SELECT incident_a, incident_b FROM correlation_links WHERE incident_a = ? OR incident_b = ?",
                    (incident_id, incident_id),
                ):
                    ids.update((row["incident_a"], row["incident_b"]))
                campaign = session.scalar(
                    "SELECT ci.campaign_id FROM campaign_incidents ci JOIN campaigns c ON c.id = ci.campaign_id "
                    "WHERE ci.incident_id = ? AND c.status = 'ACTIVE'",
                    (incident_id,),
                )
                if campaign:
                    ids.update(self.member_ids(session, campaign))
            else:
                ids = {
                    r["incident_id"]
                    for r in session.all(
                        "SELECT ci.incident_id FROM campaign_incidents ci JOIN campaigns c ON c.id = ci.campaign_id "
                        "WHERE c.status = 'ACTIVE'"
                    )
                }
                ids.update(
                    r["id"]
                    for r in session.all(
                        "SELECT id FROM incidents WHERE status NOT IN ('MERGED') ORDER BY updated_at DESC LIMIT 50"
                    )
                )
            ordered = sorted(ids)
            truncated = len(ordered) > limit
            ordered = ordered[:limit]
            incidents = self._incident_rows(session, ordered)
            marks = ",".join("?" * len(ordered)) if ordered else "''"
            links = (
                [
                    _link_from_row(r)
                    for r in session.all(
                        f"SELECT * FROM correlation_links WHERE incident_a IN ({marks}) AND incident_b IN ({marks})",
                        [*ordered, *ordered],
                    )
                ]
                if ordered
                else []
            )
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[str, dict[str, Any]] = {}

        def add_edge(source: str, target: str, kind: str, label: str, **extra: Any) -> None:
            edge_id = f"{source}->{target}:{kind}"
            if edge_id in edges:
                if label not in edges[edge_id]["label"]:
                    edges[edge_id]["label"] += f"; {label}"
                return
            edges[edge_id] = {"id": edge_id, "source": source, "target": target, "kind": kind, "label": label, **extra}

        for incident in incidents:
            node_id = f"incident:{incident['id']}"
            nodes[node_id] = {
                "id": node_id,
                "type": "incident",
                "label": f"{incident['asset']} · {incident['severity']} {incident['risk_score']}",
                "severity": incident["severity"],
                "risk": incident["risk_score"],
                "incident_id": incident["id"],
                "status": incident["status"],
            }
            asset_id, user_id = f"asset:{incident['asset']}", f"user:{incident['username']}"
            nodes.setdefault(asset_id, {"id": asset_id, "type": "asset", "label": incident["asset"]})
            nodes.setdefault(user_id, {"id": user_id, "type": "user", "label": incident["username"]})
            add_edge(node_id, asset_id, "membership", "on asset")
            add_edge(node_id, user_id, "membership", "user")
        for link in links:
            a, b = f"incident:{link.incident_a}", f"incident:{link.incident_b}"
            entity_id = f"{link.entity_type}:{link.entity_value}"
            if link.entity_type != "user":
                nodes.setdefault(entity_id, {"id": entity_id, "type": link.entity_type, "label": link.entity_value})
                add_edge(a, entity_id, "membership", LINK_TYPES[link.entity_type].label)
                add_edge(b, entity_id, "membership", LINK_TYPES[link.entity_type].label)
            add_edge(a, b, "correlation", link.reason, strength=link.strength, link_type=link.link_type)
        return {"nodes": list(nodes.values()), "edges": list(edges.values()), "truncated": truncated}
