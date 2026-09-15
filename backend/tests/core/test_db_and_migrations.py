from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.core.db import Database
from app.core.migrations import MigrationError, apply_migrations, discover


def write(directory: Path, name: str, sql: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(sql, encoding="utf-8")


def test_migrations_apply_in_order_and_are_idempotent(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    write(migrations, "0001_create.sql", "CREATE TABLE t (x INTEGER);")
    write(migrations, "0002_seed.sql", "INSERT INTO t VALUES (1);")
    db = Database(tmp_path / "a.db")
    assert apply_migrations(db, migrations) == [1, 2]
    assert apply_migrations(db, migrations) == []
    with db.read() as session:
        assert session.scalar("SELECT count(*) FROM schema_migrations") == 2
        assert session.scalar("SELECT count(*) FROM t") == 1


def test_project_migrations_apply(tmp_path: Path) -> None:
    db = Database(tmp_path / "a.db")
    applied = apply_migrations(db)
    assert applied[0] == 1
    with db.read() as session:
        tables = {row[0] for row in session.all("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"metadata", "audit_log", "jobs", "schema_migrations"} <= tables
    assert db.journal_mode.lower() == "wal"


def test_modified_applied_migration_is_refused(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    write(migrations, "0001_create.sql", "CREATE TABLE t (x INTEGER);")
    db = Database(tmp_path / "a.db")
    apply_migrations(db, migrations)
    write(migrations, "0001_create.sql", "CREATE TABLE t (x INTEGER, y INTEGER);")
    with pytest.raises(MigrationError, match="append-only"):
        apply_migrations(db, migrations)


def test_numbering_gap_is_refused(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    write(migrations, "0001_create.sql", "CREATE TABLE t (x INTEGER);")
    write(migrations, "0003_skip.sql", "CREATE TABLE u (x INTEGER);")
    with pytest.raises(MigrationError, match="contiguously"):
        discover(migrations)


def test_invalid_filename_is_refused(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    write(migrations, "1_bad.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="filename"):
        discover(migrations)


def test_failed_migration_rolls_back_completely(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    write(migrations, "0001_ok.sql", "CREATE TABLE t (x INTEGER);")
    write(migrations, "0002_broken.sql", "CREATE TABLE y (a INTEGER);\nINSERT INTO missing VALUES (1);")
    db = Database(tmp_path / "a.db")
    with pytest.raises(MigrationError, match="0002_broken"):
        apply_migrations(db, migrations)
    with db.read() as session:
        tables = {row[0] for row in session.all("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "y" not in tables
        assert session.scalar("SELECT max(version) FROM schema_migrations") == 1


def test_unknown_applied_version_is_refused(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    write(migrations, "0001_a.sql", "CREATE TABLE t (x INTEGER);")
    write(migrations, "0002_b.sql", "CREATE TABLE u (x INTEGER);")
    db = Database(tmp_path / "a.db")
    apply_migrations(db, migrations)
    (migrations / "0002_b.sql").unlink()
    with pytest.raises(MigrationError, match="does not know"):
        apply_migrations(db, migrations)


def test_read_sessions_reject_writes(tmp_path: Path) -> None:
    db = Database(tmp_path / "a.db")
    apply_migrations(db)
    with db.read() as session, pytest.raises(sqlite3.OperationalError):
        session.execute("INSERT INTO metadata (key, value) VALUES ('a', 'b')")


def test_nested_writes_join_the_outer_transaction(tmp_path: Path) -> None:
    db = Database(tmp_path / "a.db")
    apply_migrations(db)
    calls: list[str] = []
    with pytest.raises(ValueError), db.write() as outer:
        with db.write() as inner:
            assert inner is outer
            inner.execute("INSERT INTO metadata (key, value) VALUES ('joined', '1')")
            inner.after_commit(lambda: calls.append("inner"))
        with db.read() as reader:  # reads inside a write see its uncommitted changes
            assert reader.scalar("SELECT value FROM metadata WHERE key = 'joined'") == "1"
        raise ValueError("outer failure rolls back the nested work too")
    assert calls == []
    with db.read() as session:
        assert session.scalar("SELECT count(*) FROM metadata WHERE key = 'joined'") == 0
    with db.write() as outer, db.write() as inner:
        inner.execute("INSERT INTO metadata (key, value) VALUES ('joined', '2')")
        inner.after_commit(lambda: calls.append("committed"))
    assert calls == ["committed"]


def test_after_commit_runs_only_after_successful_commit(tmp_path: Path) -> None:
    db = Database(tmp_path / "a.db")
    apply_migrations(db)
    calls: list[str] = []
    with db.write() as session:
        session.execute("INSERT INTO metadata (key, value) VALUES ('a', 'b')")
        session.after_commit(lambda: calls.append("committed"))
        assert calls == []
    assert calls == ["committed"]
    with pytest.raises(ValueError), db.write() as session:
        session.execute("INSERT INTO metadata (key, value) VALUES ('c', 'd')")
        session.after_commit(lambda: calls.append("should not run"))
        raise ValueError("boom")
    assert calls == ["committed"]
    with db.read() as session:
        assert session.scalar("SELECT count(*) FROM metadata WHERE key = 'c'") == 0


def test_backup_refuses_to_overwrite(tmp_path: Path) -> None:
    db = Database(tmp_path / "a.db")
    apply_migrations(db)
    target = tmp_path / "backup.db"
    db.backup(target)
    assert target.exists()
    with pytest.raises(FileExistsError):
        db.backup(target)
