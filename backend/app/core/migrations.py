"""Append-only numbered SQL migrations. Applied migrations are checksummed; editing one refuses startup."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from app.core.db import Database
from app.core.timeutil import utc_now_iso

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"
FILENAME_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str
    checksum: str


def discover(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    found: list[Migration] = []
    for path in sorted(directory.glob("*.sql")):
        match = FILENAME_RE.match(path.name)
        if not match:
            raise MigrationError(f"Invalid migration filename: {path.name} (expected NNNN_name.sql)")
        text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        checksum = hashlib.sha256(text.encode("utf-8")).hexdigest()
        found.append(Migration(int(match.group(1)), match.group(2), text, checksum))
    for position, migration in enumerate(found, start=1):
        if migration.version != position:
            raise MigrationError(
                "Migrations must be numbered contiguously from 0001; "
                f"found {migration.version:04d} at position {position}"
            )
    return found


def apply_migrations(db: Database, directory: Path = MIGRATIONS_DIR) -> list[int]:
    """Apply pending migrations in order. Returns the versions applied by this call."""
    migrations = discover(directory)
    conn = db.raw_connection()
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
        )
        applied = {row["version"]: row for row in conn.execute("SELECT version, name, checksum FROM schema_migrations")}
        unknown = sorted(set(applied) - {m.version for m in migrations})
        if unknown:
            raise MigrationError(f"Database contains migrations this code does not know about: {unknown}")
        newly_applied: list[int] = []
        for migration in migrations:
            existing = applied.get(migration.version)
            if existing is not None:
                if existing["checksum"] != migration.checksum:
                    raise MigrationError(
                        f"Migration {migration.version:04d}_{migration.name} changed after it was applied. "
                        "Migrations are append-only: add a new migration instead."
                    )
                continue
            body = migration.sql.strip()
            if not body.endswith(";"):
                body += ";"
            # name and checksum are constrained by FILENAME_RE / hex digest, so inlining them is safe.
            script = (
                "BEGIN IMMEDIATE;\n"
                f"{body}\n"
                "INSERT INTO schema_migrations(version, name, checksum, applied_at) "
                f"VALUES ({migration.version}, '{migration.name}', '{migration.checksum}', '{utc_now_iso()}');\n"
                "COMMIT;"
            )
            try:
                conn.executescript(script)
            except sqlite3.Error as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise MigrationError(f"Migration {migration.version:04d}_{migration.name} failed: {exc}") from exc
            newly_applied.append(migration.version)
        return newly_applied
    finally:
        conn.close()
