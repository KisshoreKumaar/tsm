"""Ingestion pipeline: store events, rebuild affected correlation components, run rules and upsert incidents.

An incident is a connected component of events that share asset + user and lie within the incident window of each
other (chained). Components are a pure function of the stored events, so results never depend on arrival order.
Adding events can only grow or join components; joined incidents merge into the one detected first.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from app.core.db import Session
from app.core.errors import ApiError, CapacityError, Conflict
from app.core.jsonutil import canonical_json
from app.core.timeutil import iso
from app.detection.analysis import build_analysis, build_title
from app.detection.base import Detection, Event
from app.detection.engine import RuleEngine
from app.detection.risk import score_incident
from app.ingest.normalize import EventValidationError, NormalizedEvent, normalize
from app.response.simulation import cancel_open_responses

CLOSED_STATUSES = frozenset({"RESOLVED", "FALSE_POSITIVE"})

SuppressionCheck = Callable[[Session, Detection, Sequence[Event]], "str | None"]
ObservedCounter = Callable[[Session, str], int]
IncidentsChangedHook = Callable[[Session, Sequence[str], str], None]

# Key in ctx.services holding the per-application list of IncidentsChangedHook callbacks.
INCIDENT_CHANGE_HOOKS = "incident_change_hooks"


@dataclass(frozen=True)
class IngestResult:
    id: str
    duplicate: bool
    source: str
    event_id: str | None

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "duplicate": self.duplicate, "source": self.source, "event_id": self.event_id}


@dataclass(frozen=True)
class IncidentChange:
    incident_id: str
    kind: str  # "created" or "updated"
    revision: int
    event_ids: tuple[str, ...]
    new_event_ids: tuple[str, ...]
    merged_ids: tuple[str, ...]
    reopened: bool
    rule_ids: tuple[str, ...]


IncidentListener = Callable[[Session, IncidentChange], None]


@dataclass
class IngestOutcome:
    results: list[IngestResult] = field(default_factory=list)
    changes: list[IncidentChange] = field(default_factory=list)

    @property
    def incident_ids(self) -> list[str]:
        return sorted({change.incident_id for change in self.changes})

    def public(self) -> dict[str, Any]:
        stored = sum(1 for r in self.results if not r.duplicate)
        return {
            "stored": stored,
            "duplicates": len(self.results) - stored,
            "results": [r.public() for r in self.results],
            "incident_ids": self.incident_ids,
        }


def _event_from(event_id: str, item: NormalizedEvent) -> Event:
    return Event(
        id=event_id,
        source=item.source,
        external_id=item.external_id,
        digest=item.digest,
        ts=item.ts,
        kind=item.kind,
        asset=item.asset,
        username=item.username,
        criticality=item.criticality,
        privileged=item.privileged,
        source_ip=item.source_ip,
        destination_ip=item.destination_ip,
        destination_port=item.destination_port,
        domain=item.domain,
        process_name=item.process_name,
        parent_process=item.parent_process,
        command_line=item.command_line,
        file_path=item.file_path,
        file_hash=item.file_hash,
        details=item.details,
        injection_matches=item.injection_matches,
    )


def _marks(values: Sequence[Any]) -> str:
    return ",".join("?" * len(values))


class IngestPipeline:
    def __init__(self, ctx: Any, engine: RuleEngine) -> None:
        self._ctx = ctx
        self.engine = engine
        self.suppression_checks: list[SuppressionCheck] = []
        self.listeners: list[IncidentListener] = []
        self.observed_counter: ObservedCounter | None = None

    # -- validation (outside any transaction) --------------------------------------------------------

    def validate(self, raw_events: Sequence[Any]) -> list[NormalizedEvent]:
        settings = self._ctx.settings
        latest = self._ctx.clock.now() + timedelta(seconds=settings.clock_skew_seconds)
        errors: list[dict[str, Any]] = []
        normalized: list[NormalizedEvent] = []
        for index, raw in enumerate(raw_events):
            try:
                event = normalize(raw)
            except EventValidationError as exc:
                errors.append({"index": index, "errors": exc.errors})
                continue
            if event.ts > latest:
                errors.append(
                    {
                        "index": index,
                        "errors": [
                            {
                                "loc": ["timestamp"],
                                "msg": f"must not be later than server time plus {settings.clock_skew_seconds} seconds",
                                "type": "value_error",
                            }
                        ],
                    }
                )
                continue
            normalized.append(event)
        if errors:
            raise ApiError(
                "One or more events are invalid; nothing was stored",
                code="validation_error",
                status_code=422,
                details=errors[:100],
            )
        return normalized

    # -- storage and correlation (inside the caller's write transaction) -----------------------------

    def ingest(self, session: Session, events: Sequence[NormalizedEvent], actor: str) -> IngestOutcome:
        ctx = self._ctx
        now = iso(ctx.clock.now())
        outcome = IngestOutcome()
        stored: list[Event] = []
        seen: dict[tuple[str, str], tuple[str, str]] = {}
        for item in events:
            if item.external_id is not None:
                key = (item.source, item.external_id)
                prior = seen.get(key)
                if prior is None:
                    row = session.one("SELECT id, digest FROM events WHERE source = ? AND external_id = ?", key)
                    prior = (row["id"], row["digest"]) if row else None
                if prior is not None:
                    if prior[1] != item.digest:
                        raise Conflict(
                            f"Event {item.external_id} from source {item.source} was already ingested with different "
                            "content; nothing was stored",
                            code="event_conflict",
                        )
                    outcome.results.append(IngestResult(prior[0], True, item.source, item.external_id))
                    continue
            event_id = str(uuid.uuid4())
            session.execute(
                "INSERT INTO events (id, source, external_id, digest, ts, kind, asset, username, source_ip, destination_ip, "
                "destination_port, domain, process_name, parent_process, command_line, file_path, file_hash, details, "
                "criticality, privileged, injection_suspected, injection_matches, ingested_at, ingested_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    item.source,
                    item.external_id,
                    item.digest,
                    iso(item.ts),
                    item.kind,
                    item.asset,
                    item.username,
                    item.source_ip,
                    item.destination_ip,
                    item.destination_port,
                    item.domain,
                    item.process_name,
                    item.parent_process,
                    item.command_line,
                    item.file_path,
                    item.file_hash,
                    item.details,
                    item.criticality,
                    int(item.privileged),
                    int(item.injection_suspected),
                    canonical_json(list(item.injection_matches)),
                    now,
                    actor,
                ),
            )
            session.execute(
                "INSERT INTO raw_events (event_id, body) VALUES (?, ?)", (event_id, canonical_json(item.raw))
            )
            session.executemany(
                "INSERT INTO event_entities (event_id, entity_type, value) VALUES (?, ?, ?)",
                [(event_id, entity_type, value) for entity_type, value in item.entities()],
            )
            if item.external_id is not None:
                seen[(item.source, item.external_id)] = (event_id, item.digest)
            stored.append(_event_from(event_id, item))
            outcome.results.append(IngestResult(event_id, False, item.source, item.external_id))

        if stored:
            ctx.audit.append(
                session,
                "events.ingested",
                actor,
                {
                    "stored": len(stored),
                    "duplicates": len(outcome.results) - len(stored),
                    "event_ids": [e.id for e in stored][:500],
                    "injection_suspected": [e.id for e in stored if e.injection_suspected][:100],
                },
            )
            outcome.changes = self._correlate(session, stored, actor)
            if outcome.changes:
                changed = {c.incident_id for c in outcome.changes} | {m for c in outcome.changes for m in c.merged_ids}
                self.notify_incidents_changed(session, sorted(changed), actor)
            stored_count = len(stored)
            incident_ids = outcome.incident_ids
            session.after_commit(
                lambda: ctx.bus.publish("events.ingested", {"stored": stored_count, "incident_ids": incident_ids})
            )
        return outcome

    def notify_incidents_changed(self, session: Session, incident_ids: Sequence[str], actor: str) -> None:
        """Run feature hooks (e.g. campaign recomputation) in the same transaction that changed the incidents."""
        hooks: list[IncidentsChangedHook] = self._ctx.services.setdefault(INCIDENT_CHANGE_HOOKS, [])
        for hook in hooks:
            hook(session, incident_ids, actor)

    @property
    def change_hooks(self) -> list[IncidentsChangedHook]:
        hooks: list[IncidentsChangedHook] = self._ctx.services.setdefault(INCIDENT_CHANGE_HOOKS, [])
        return hooks

    def refresh_incident(self, session: Session, incident_id: str, actor: str) -> list[IncidentChange]:
        """Re-evaluate an incident's component (e.g. after a suppression or an observed prediction)."""
        row = session.one(
            "SELECT e.* FROM events e JOIN incident_events ie ON ie.event_id = e.id WHERE ie.incident_id = ? "
            "ORDER BY e.ts LIMIT 1",
            (incident_id,),
        )
        if row is None:
            return []
        component = self._component(session, Event.from_row(row))
        changes = self._apply_component(session, component, set(), actor)
        if changes:
            self.notify_incidents_changed(session, [c.incident_id for c in changes], actor)
        return changes

    def _correlate(self, session: Session, new_events: Sequence[Event], actor: str) -> list[IncidentChange]:
        new_ids = {e.id for e in new_events}
        covered: set[str] = set()
        changes: list[IncidentChange] = []
        for seed in sorted(new_events, key=lambda e: e.sort_key):
            if seed.id in covered:
                continue
            component = self._component(session, seed)
            covered.update(e.id for e in component)
            changes.extend(self._apply_component(session, component, new_ids, actor))
        return changes

    def _component(self, session: Session, seed: Event) -> list[Event]:
        settings = self._ctx.settings
        window = timedelta(seconds=settings.incident_window_seconds)
        cap = settings.max_component_events
        low = high = seed.ts
        known: dict[str, Event] = {}
        while True:
            rows = session.all(
                "SELECT * FROM events WHERE asset = ? AND username = ? AND ts >= ? AND ts <= ? ORDER BY ts LIMIT ?",
                (seed.asset, seed.username, iso(low - window), iso(high + window), cap + 1),
            )
            if len(rows) > cap:
                raise CapacityError(
                    f"A correlated component exceeds {cap} events; the batch was rolled back. "
                    "Split sources or raise AEGIS capacity settings."
                )
            found = {row["id"]: Event.from_row(row) for row in rows}
            if len(found) == len(known):
                break
            known = found
            low = min(e.ts for e in known.values())
            high = max(e.ts for e in known.values())
        return sorted(known.values(), key=lambda e: e.sort_key)

    def _apply_component(
        self, session: Session, component: Sequence[Event], new_ids: set[str], actor: str
    ) -> list[IncidentChange]:
        ctx = self._ctx
        ids = [e.id for e in component]
        detections = self.engine.evaluate(component)
        suppression: dict[str, str | None] = {}
        for detection in detections:
            suppression[detection.id] = next(
                (sid for check in self.suppression_checks if (sid := check(session, detection, component))), None
            )
        active = [d for d in detections if suppression[d.id] is None]
        existing = session.all(
            f"SELECT DISTINCT i.* FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id "
            f"WHERE ie.event_id IN ({_marks(ids)}) AND i.status != 'MERGED' "
            "ORDER BY i.first_detected_at, i.created_at, i.rowid",
            ids,
        )
        old_rows = session.all(
            f"SELECT DISTINCT d.id, d.status, d.suppression_id, d.created_at, d.incident_id FROM detections d "
            f"JOIN detection_events de ON de.detection_id = d.id WHERE de.event_id IN ({_marks(ids)})",
            ids,
        )
        old_map = {r["id"]: (r["status"], r["suppression_id"]) for r in old_rows}
        new_map = {
            d.id: ("ACTIVE" if suppression[d.id] is None else "SUPPRESSED", suppression[d.id]) for d in detections
        }
        now = iso(ctx.clock.now())

        if not existing and not active:
            if old_map != new_map:
                self._replace_detections(session, old_rows, detections, suppression, None, now)
                if any(suppression.values()):
                    ctx.audit.append(
                        session,
                        "detections.suppressed",
                        actor,
                        {"detection_ids": sorted(d.id for d in detections if suppression[d.id])},
                    )
            return []

        canonical = existing[0] if existing else None
        others = list(existing[1:])
        observed = 0
        if canonical is not None and self.observed_counter is not None:
            observed = self.observed_counter(session, canonical["id"])
        assessment = score_incident(component, active, observed)
        membership: set[str] = set()
        if canonical is not None:
            membership = {
                r["event_id"]
                for r in session.all("SELECT event_id FROM incident_events WHERE incident_id = ?", (canonical["id"],))
            }
            unchanged = (
                not others
                and membership == set(ids)
                and old_map == new_map
                and canonical["risk_score"] == assessment.score
                and all(r["incident_id"] == canonical["id"] for r in old_rows)
            )
            if unchanged:
                return []

        incident_id = canonical["id"] if canonical is not None else str(uuid.uuid4())
        self._replace_detections(session, old_rows, detections, suppression, incident_id, now)
        analysis = build_analysis(
            component, active, [(d, suppression[d.id]) for d in detections if suppression[d.id]], self.engine.catalog
        )
        title = build_title(component[0].asset, component[0].username, active or detections)
        rule_ids = tuple(sorted({d.rule_id for d in active}))
        risk_factors = canonical_json([f.public() for f in assessment.factors])
        first_seen, last_seen = iso(component[0].ts), iso(max(e.ts for e in component))
        reopened = False
        added = set(ids) - membership

        if canonical is None:
            revision = 1
            kind = "created"
            session.execute(
                "INSERT INTO incidents (id, status, revision, title, asset, username, first_seen, last_seen, event_count, "
                "risk_score, severity, risk_factors, analysis, first_detected_at, created_at, updated_at) "
                "VALUES (?, 'OPEN', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    incident_id,
                    title,
                    component[0].asset,
                    component[0].username,
                    first_seen,
                    last_seen,
                    len(ids),
                    assessment.score,
                    assessment.severity,
                    risk_factors,
                    canonical_json(analysis),
                    now,
                    now,
                    now,
                ),
            )
            ctx.audit.append(
                session,
                "incident.created",
                actor,
                {
                    "incident_id": incident_id,
                    "revision": 1,
                    "rules": list(rule_ids),
                    "event_count": len(ids),
                    "risk_score": assessment.score,
                    "severity": assessment.severity,
                },
                subject=("incident", incident_id),
            )
        else:
            kind = "updated"
            revision = int(canonical["revision"]) + 1
            status = canonical["status"]
            closed_at = canonical["closed_at"]
            if status in CLOSED_STATUSES and added:
                status, closed_at, reopened = "OPEN", None, True
            session.execute(
                "UPDATE incidents SET status = ?, revision = ?, title = ?, first_seen = ?, last_seen = ?, event_count = ?, "
                "risk_score = ?, severity = ?, risk_factors = ?, analysis = ?, updated_at = ?, closed_at = ? WHERE id = ?",
                (
                    status,
                    revision,
                    title,
                    first_seen,
                    last_seen,
                    len(ids),
                    assessment.score,
                    assessment.severity,
                    risk_factors,
                    canonical_json(analysis),
                    now,
                    closed_at,
                    incident_id,
                ),
            )
            if reopened:
                session.execute(
                    "INSERT INTO incident_notes (id, incident_id, author, kind, text, created_at) VALUES (?, ?, ?, 'reopen', ?, ?)",
                    (
                        str(uuid.uuid4()),
                        incident_id,
                        "system",
                        f"Reopened automatically: {len(added)} new correlated event(s) arrived after closure.",
                        now,
                    ),
                )
                ctx.audit.append(
                    session,
                    "incident.reopened",
                    actor,
                    {"incident_id": incident_id, "revision": revision, "new_events": len(added)},
                    subject=("incident", incident_id),
                )
            if added or others:
                cancel_open_responses(
                    session, ctx.audit, ctx.clock, incident_id, actor, "New correlated evidence changed the incident"
                )
            for other in others:
                session.execute(
                    "UPDATE incidents SET status = 'MERGED', merged_into = ?, revision = revision + 1, updated_at = ? "
                    "WHERE id = ?",
                    (incident_id, now, other["id"]),
                )
                cancel_open_responses(
                    session, ctx.audit, ctx.clock, other["id"], actor, f"Incident merged into {incident_id}"
                )
                ctx.audit.append(
                    session,
                    "incident.merged",
                    actor,
                    {"incident_id": other["id"], "merged_into": incident_id},
                    subject=("incident", other["id"]),
                )
            ctx.audit.append(
                session,
                "incident.updated",
                actor,
                {
                    "incident_id": incident_id,
                    "revision": revision,
                    "added_events": len(added),
                    "merged": [o["id"] for o in others],
                    "rules": list(rule_ids),
                    "risk_score": assessment.score,
                    "severity": assessment.severity,
                },
                subject=("incident", incident_id),
            )

        session.executemany(
            "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
            [(incident_id, event_id) for event_id in ids],
        )
        change = IncidentChange(
            incident_id=incident_id,
            kind=kind,
            revision=revision,
            event_ids=tuple(ids),
            new_event_ids=tuple(e for e in ids if e in new_ids),
            merged_ids=tuple(o["id"] for o in others),
            reopened=reopened,
            rule_ids=rule_ids,
        )
        for listener in self.listeners:
            listener(session, change)
        session.after_commit(
            lambda: ctx.bus.publish(
                f"incident.{change.kind}",
                {"incident_id": change.incident_id, "revision": change.revision, "merged": list(change.merged_ids)},
            )
        )
        return [change]

    def _replace_detections(
        self,
        session: Session,
        old_rows: Sequence[Any],
        detections: Sequence[Detection],
        suppression: dict[str, str | None],
        incident_id: str | None,
        now: str,
    ) -> None:
        created_at = {row["id"]: row["created_at"] for row in old_rows}
        old_ids = [row["id"] for row in old_rows]
        if old_ids:
            session.execute(f"DELETE FROM detection_events WHERE detection_id IN ({_marks(old_ids)})", old_ids)
            session.execute(f"DELETE FROM detections WHERE id IN ({_marks(old_ids)})", old_ids)
        for detection in detections:
            suppression_id = suppression.get(detection.id)
            session.execute(
                "INSERT INTO detections (id, incident_id, rule_id, rule_version, rule_name, severity, confidence, stage, "
                "techniques, group_key, first_ts, last_ts, event_ids, summary, details, status, suppression_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    detection.id,
                    incident_id,
                    detection.rule_id,
                    detection.rule_version,
                    detection.rule_name,
                    detection.severity,
                    detection.confidence,
                    detection.stage,
                    canonical_json(list(detection.techniques)),
                    detection.group_key,
                    iso(detection.first_ts),
                    iso(detection.last_ts),
                    canonical_json(list(detection.event_ids)),
                    detection.summary,
                    canonical_json(dict(detection.details)),
                    "ACTIVE" if suppression_id is None else "SUPPRESSED",
                    suppression_id,
                    created_at.get(detection.id, now),
                ),
            )
            session.executemany(
                "INSERT INTO detection_events (detection_id, event_id) VALUES (?, ?)",
                [(detection.id, event_id) for event_id in detection.event_ids],
            )
