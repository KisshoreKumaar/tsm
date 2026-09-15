"""HMAC-SHA256 hash-chained audit log.

Every successful state change calls `AuditLog.append(session, ...)` with the *same* write session that made
the change, so the audit record commits or rolls back together with it.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from typing import Any

from app.core.db import Database, Session
from app.core.jsonutil import canonical_json, loads_stored
from app.core.timeutil import Clock, SystemClock, iso

GENESIS_DIGEST = "0" * 64
ACTION_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
CORE_AUDIT_ACTIONS = frozenset(
    {
        "system.initialized",
        "job.enqueued",
        "job.started",
        "job.succeeded",
        "job.failed",
        "job.cancelled",
        "job.requeued",
    }
)
_SECRET_KEY_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "token",
        "access_token",
        "secret",
        "secret_key",
        "password",
        "authorization",
        "key_ciphertext",
        "ciphertext",
    }
)
_FINGERPRINT_LABEL = b"aegis-audit-key-fingerprint-v1"


class AuditError(RuntimeError):
    pass


def _reject_secrets(value: Any, path: str = "body") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise AuditError(f"{path} keys must be strings")
            if key.lower() in _SECRET_KEY_NAMES:
                raise AuditError(f"Audit records must never contain secrets ({path}.{key})")
            _reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _reject_secrets(item, f"{path}[{index}]")


class AuditLog:
    def __init__(self, key: str, actions: Iterable[str] = (), clock: Clock | None = None) -> None:
        if len(key) < 32:
            raise AuditError("The audit key must contain at least 32 characters")
        self._key = key.encode("utf-8")
        self._clock: Clock = clock or SystemClock()
        self._actions: set[str] = set(CORE_AUDIT_ACTIONS)
        self.register_actions(actions)

    def register_actions(self, actions: Iterable[str]) -> None:
        for action in actions:
            if not ACTION_RE.match(action):
                raise AuditError(f"Invalid audit action name: {action}")
            self._actions.add(action)

    @property
    def actions(self) -> frozenset[str]:
        return frozenset(self._actions)

    @property
    def fingerprint(self) -> str:
        return hmac.new(self._key, _FINGERPRINT_LABEL, hashlib.sha256).hexdigest()

    def _digest(
        self,
        seq: int,
        ts: str,
        action: str,
        actor: str,
        subject_type: str | None,
        subject_id: str | None,
        body: str,
        prev: str,
    ) -> str:
        material = canonical_json([seq, ts, action, actor, subject_type, subject_id, body, prev]).encode("utf-8")
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()

    def append(
        self,
        session: Session,
        action: str,
        actor: str,
        body: Mapping[str, Any] | None = None,
        *,
        subject: tuple[str, str] | None = None,
    ) -> int:
        if not session.writable or not session.in_transaction:
            raise AuditError("Audit records must be written inside the state-changing write transaction")
        if action not in self._actions:
            raise AuditError(f"Unregistered audit action: {action}")
        payload = dict(body or {})
        _reject_secrets(payload)
        serialized = canonical_json(payload)
        last = session.one("SELECT seq, digest FROM audit_log ORDER BY seq DESC LIMIT 1")
        seq = int(last["seq"]) + 1 if last else 1
        prev = str(last["digest"]) if last else GENESIS_DIGEST
        ts = iso(self._clock.now())
        subject_type, subject_id = subject if subject else (None, None)
        digest = self._digest(seq, ts, action, actor, subject_type, subject_id, serialized, prev)
        session.execute(
            "INSERT INTO audit_log(seq, ts, action, actor, subject_type, subject_id, body, prev_digest, digest) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (seq, ts, action, actor, subject_type, subject_id, serialized, prev, digest),
        )
        return seq

    def initialize(self, db: Database) -> None:
        """Bind the key to the database on first start; refuse a different key afterwards."""
        with db.write() as session:
            stored = session.scalar("SELECT value FROM metadata WHERE key = 'audit_key_fingerprint'")
            if stored is None:
                if session.scalar("SELECT count(*) FROM audit_log"):
                    raise AuditError("Audit records exist but no key fingerprint is stored; refusing to start")
                session.execute(
                    "INSERT INTO metadata(key, value) VALUES ('audit_key_fingerprint', ?)", (self.fingerprint,)
                )
                self.append(session, "system.initialized", "system", {"mode": "HMAC-SHA256"})
            elif not hmac.compare_digest(str(stored), self.fingerprint):
                raise AuditError(
                    "AEGIS_AUDIT_KEY does not match this database. Restore the original key; "
                    "never rotate it without a documented migration."
                )

    def verify(self, db: Database) -> dict[str, Any]:
        previous = GENESIS_DIGEST
        count = 0
        head_seq = 0
        with db.read() as session:
            stored = session.scalar("SELECT value FROM metadata WHERE key = 'audit_key_fingerprint'")
            if stored is not None and not hmac.compare_digest(str(stored), self.fingerprint):
                return {"valid": False, "records": 0, "failed_seq": None, "reason": "Audit key does not match"}
            cursor = session.conn.execute(
                "SELECT seq, ts, action, actor, subject_type, subject_id, body, prev_digest, digest "
                "FROM audit_log ORDER BY seq"
            )
            for row in cursor:
                seq = int(row["seq"])
                reason = None
                if seq != head_seq + 1:
                    reason = "Sequence gap"
                elif row["prev_digest"] != previous:
                    reason = "Broken chain link"
                else:
                    expected = self._digest(
                        seq,
                        row["ts"],
                        row["action"],
                        row["actor"],
                        row["subject_type"],
                        row["subject_id"],
                        row["body"],
                        previous,
                    )
                    if not hmac.compare_digest(expected, str(row["digest"])):
                        reason = "Digest mismatch (record altered)"
                if reason:
                    return {"valid": False, "records": count, "failed_seq": seq, "reason": reason}
                previous = str(row["digest"])
                head_seq = seq
                count += 1
        return {
            "valid": True,
            "records": count,
            "head_seq": head_seq,
            "head_digest": previous,
            "mode": "HMAC-SHA256",
            "note": "Retain exported checkpoints outside this database to detect truncation or wholesale replacement.",
        }

    def checkpoint(self, db: Database) -> dict[str, Any]:
        result = self.verify(db)
        return {
            "valid": result["valid"],
            "records": result["records"],
            "head_seq": result.get("head_seq"),
            "head_digest": result.get("head_digest"),
            "exported_at": iso(self._clock.now()),
            "mode": "HMAC-SHA256",
        }

    def page(
        self,
        db: Database,
        *,
        offset: int = 0,
        limit: int = 50,
        action: str | None = None,
        actor: str | None = None,
        subject_type: str | None = None,
        subject_id: str | None = None,
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("action", action),
            ("actor", actor),
            ("subject_type", subject_type),
            ("subject_id", subject_id),
        ):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with db.read() as session:
            total = session.scalar(f"SELECT count(*) FROM audit_log {where}", params)
            rows = session.all(
                f"SELECT seq, ts, action, actor, subject_type, subject_id, body, digest FROM audit_log {where} "
                "ORDER BY seq DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            )
        items = [
            {
                "seq": row["seq"],
                "ts": row["ts"],
                "action": row["action"],
                "actor": row["actor"],
                "subject_type": row["subject_type"],
                "subject_id": row["subject_id"],
                "body": loads_stored(row["body"]),
                "digest": row["digest"],
            }
            for row in rows
        ]
        return {"items": items, "total": total, "offset": offset, "limit": limit}
