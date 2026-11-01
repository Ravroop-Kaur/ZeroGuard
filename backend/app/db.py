"""Tiny database adapter: SQLite for local/tests, PostgreSQL when DATABASE_URL is set. One shared connection, serialized by a lock."""
import sqlite3, threading
from contextlib import contextmanager


class Rows(list):
    def fetchone(self):
        return self[0] if self else None

    def fetchall(self):
        return list(self)


class DB:
    def __init__(self, target: str):
        self.lock = threading.RLock()
        self.pg = target.startswith(("postgres://", "postgresql://"))
        if self.pg:
            import psycopg
            from psycopg.rows import dict_row
            self.conn = psycopg.connect(target.replace("postgres://", "postgresql://", 1), autocommit=True, row_factory=dict_row)
        else:
            self.conn = sqlite3.connect(target, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        self.kind = "postgresql" if self.pg else "sqlite"

    def execute(self, sql: str, params=()):
        with self.lock:
            cur = self.conn.execute(sql.replace("?", "%s") if self.pg else sql, tuple(params))
            rows = Rows(cur.fetchall()) if cur.description else Rows()
            if not self.pg:
                self.conn.commit()
            return rows

    def executemany(self, sql: str, seq):
        for p in seq:
            self.execute(sql, p)

    def commit(self):
        if not self.pg:
            with self.lock:
                self.conn.commit()

    @contextmanager
    def exclusive(self):
        """Serialize audit-chain writes: process lock, plus a database advisory lock on PostgreSQL (several app instances)."""
        with self.lock:
            if self.pg:
                self.conn.execute("SELECT pg_advisory_lock(727001)")
            try:
                yield
            finally:
                if self.pg:
                    self.conn.execute("SELECT pg_advisory_unlock(727001)")

    def columns(self, table: str) -> set:
        if self.pg:
            return {r["column_name"] for r in self.execute("SELECT column_name FROM information_schema.columns WHERE table_name=?", (table,))}
        return {r["name"] for r in self.execute(f"PRAGMA table_info({table})")}
