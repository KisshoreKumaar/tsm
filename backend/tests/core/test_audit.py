from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.core.audit import AuditError, AuditLog
from app.core.context import StartupError
from app.core.db import Database
from app.core.migrations import apply_migrations
from app.core.timeutil import ManualClock
from app.main import create_app
from tests.support import make_settings

KEY_A = "a" * 40
KEY_B = "b" * 40


@pytest.fixture
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "audit.db")
    apply_migrations(database)
    return database


def make_log(key: str = KEY_A) -> AuditLog:
    return AuditLog(key, ["test.action"], ManualClock())


def append_many(db: Database, log: AuditLog, count: int) -> None:
    with db.write() as session:
        for index in range(count):
            log.append(session, "test.action", "tester", {"index": index}, subject=("thing", str(index)))


def test_append_requires_write_transaction(db: Database) -> None:
    log = make_log()
    log.initialize(db)
    with db.read() as session, pytest.raises(AuditError, match="write transaction"):
        log.append(session, "test.action", "tester")


def test_chain_verifies_and_checkpoint_matches_head(db: Database) -> None:
    log = make_log()
    log.initialize(db)
    append_many(db, log, 5)
    result = log.verify(db)
    assert result["valid"] is True
    assert result["records"] == 6  # includes system.initialized
    checkpoint = log.checkpoint(db)
    assert checkpoint["head_digest"] == result["head_digest"]
    assert checkpoint["head_seq"] == 6


def test_unregistered_action_is_rejected(db: Database) -> None:
    log = make_log()
    log.initialize(db)
    with db.write() as session, pytest.raises(AuditError, match="Unregistered"):
        log.append(session, "unknown.action", "tester")


def test_secrets_are_rejected_in_bodies(db: Database) -> None:
    log = make_log()
    log.initialize(db)
    with db.write() as session, pytest.raises(AuditError, match="secrets"):
        log.append(session, "test.action", "tester", {"provider": {"api_key": "sk-123"}})


def test_rollback_discards_the_audit_record(db: Database) -> None:
    log = make_log()
    log.initialize(db)
    with pytest.raises(RuntimeError), db.write() as session:
        log.append(session, "test.action", "tester")
        raise RuntimeError("state change failed")
    assert log.verify(db)["records"] == 1


def test_triggers_block_updates_and_deletes(db: Database) -> None:
    log = make_log()
    log.initialize(db)
    conn = db.raw_connection()
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE audit_log SET actor = 'mallory'")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM audit_log")
    finally:
        conn.close()


def test_altered_record_is_detected(db: Database) -> None:
    log = make_log()
    log.initialize(db)
    append_many(db, log, 3)
    conn = db.raw_connection()
    try:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("UPDATE audit_log SET body = '{\"index\":99}' WHERE seq = 3")
    finally:
        conn.close()
    result = log.verify(db)
    assert result == {"valid": False, "records": 2, "failed_seq": 3, "reason": "Digest mismatch (record altered)"}


def test_deleted_record_is_detected(db: Database) -> None:
    log = make_log()
    log.initialize(db)
    append_many(db, log, 3)
    conn = db.raw_connection()
    try:
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE seq = 2")
    finally:
        conn.close()
    result = log.verify(db)
    assert result["valid"] is False
    assert result["failed_seq"] == 3


def test_wrong_key_is_refused(db: Database) -> None:
    make_log(KEY_A).initialize(db)
    with pytest.raises(AuditError, match="does not match"):
        make_log(KEY_B).initialize(db)
    assert make_log(KEY_B).verify(db)["valid"] is False


def test_startup_refuses_a_tampered_chain(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    app = create_app(settings)
    db: Database = app.state.ctx.db
    with db.write() as session:
        app.state.ctx.audit.append(session, "job.requeued", "tester", {"job_id": "x"})
    conn = db.raw_connection()
    try:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2")
    finally:
        conn.close()
    with pytest.raises(StartupError, match="verification failed"):
        create_app(settings)


def test_startup_refuses_a_different_audit_key(tmp_path: Path) -> None:
    create_app(make_settings(tmp_path))
    with pytest.raises(AuditError):
        create_app(make_settings(tmp_path, audit_key="z" * 40))


def test_audit_routes(client, ctx) -> None:  # type: ignore[no-untyped-def]
    from tests.support import auth

    verify = client.get("/api/audit/verify", headers=auth("viewer"))
    assert verify.status_code == 200
    assert verify.json()["valid"] is True
    page = client.get("/api/audit", headers=auth("viewer"), params={"limit": 5})
    assert page.status_code == 200
    assert page.json()["items"][0]["action"]
    assert client.get("/api/audit/checkpoint", headers=auth("analyst")).status_code == 403
    assert client.get("/api/audit/checkpoint", headers=auth("admin")).json()["valid"] is True
