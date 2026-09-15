"""SQLite access: WAL mode, one short-lived connection per unit of work, explicit transactions.

Writes go through `Database.write()`, which serialises writers, opens `BEGIN IMMEDIATE`, and runs
after-commit callbacks (e.g. live-update publication) only once the transaction has committed.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.db")

Params = Sequence[Any] | dict[str, Any]


class Session:
    """A connection bound to one transaction."""

    def __init__(self, conn: sqlite3.Connection, *, writable: bool) -> None:
        self.conn = conn
        self.writable = writable
        self._after_commit: list[Callable[[], None]] = []

    @property
    def in_transaction(self) -> bool:
        return self.conn.in_transaction

    def execute(self, sql: str, params: Params = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, rows: Sequence[Params]) -> sqlite3.Cursor:
        return self.conn.executemany(sql, rows)

    def one(self, sql: str, params: Params = ()) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.conn.execute(sql, params).fetchone()
        return row

    def all(self, sql: str, params: Params = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def scalar(self, sql: str, params: Params = ()) -> Any:
        row = self.conn.execute(sql, params).fetchone()
        return None if row is None else row[0]

    def after_commit(self, callback: Callable[[], None]) -> None:
        if not self.writable:
            raise RuntimeError("after_commit is only available in write sessions")
        self._after_commit.append(callback)


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self._local = threading.local()
        conn = self._connect()
        try:
            self.journal_mode = str(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0])
        finally:
            conn.close()

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15.0, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA synchronous=NORMAL")
        if read_only:
            conn.execute("PRAGMA query_only=ON")
        return conn

    def raw_connection(self) -> sqlite3.Connection:
        """Autocommit connection for the migration runner and maintenance scripts."""
        return self._connect()

    @contextmanager
    def read(self) -> Iterator[Session]:
        """A consistent read snapshot; writes are rejected by `query_only`. Inside a write transaction on the same
        thread, reads use that transaction's connection so composed operations see their own uncommitted changes."""
        if getattr(self._local, "writing", False):
            yield Session(self._local.session.conn, writable=False)
            return
        conn = self._connect(read_only=True)
        try:
            conn.execute("BEGIN")
            yield Session(conn, writable=False)
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    @contextmanager
    def write(self) -> Iterator[Session]:
        """Serialised write transaction. A nested `write()` on the same thread joins the outer transaction, so
        composed domain operations (e.g. applying an agent proposal) commit or roll back together."""
        if getattr(self._local, "writing", False):
            yield self._local.session
            return
        with self._write_lock:
            self._local.writing = True
            conn = self._connect()
            session = Session(conn, writable=True)
            self._local.session = session
            try:
                conn.execute("BEGIN IMMEDIATE")
                # Foreign keys are checked at COMMIT, so multi-step writes (e.g. merges) need no statement ordering.
                conn.execute("PRAGMA defer_foreign_keys = ON")
                yield session
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
                self._local.writing = False
        for callback in session._after_commit:
            try:
                callback()
            except Exception:
                logger.exception("after-commit callback failed")

    def backup(self, destination: str | Path) -> None:
        """Consistent online backup using SQLite's backup API. Refuses to overwrite."""
        target = Path(destination)
        if target.exists():
            raise FileExistsError(f"Refusing to overwrite existing file: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        source = self._connect(read_only=True)
        dest = sqlite3.connect(str(target))
        try:
            source.backup(dest)
        finally:
            dest.close()
            source.close()
