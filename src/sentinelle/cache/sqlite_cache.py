import sqlite3
import json
import time
import threading
from typing import Optional, Any


class SQLiteCache:
    """Simple SQLite-backed key/value cache with TTL.

    Stores JSON-serialized values and an expiry timestamp. Safe for multi-threaded
    usage within a single process via an internal threading.Lock.
    """

    def __init__(self, path: str, table_name: str = "cache", default_ttl: int = 300):
        self.path = path
        self.table = table_name
        self._ttl = int(default_ttl)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute(
            f"CREATE TABLE IF NOT EXISTS {self.table} (key TEXT PRIMARY KEY, value TEXT, expires INTEGER)"
        )
        self._conn.commit()

    def _now(self) -> int:
        return int(time.time())

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            cur = self._conn.execute(
                f"SELECT value, expires FROM {self.table} WHERE key = ?", (key,)
            )
            row = cur.fetchone()
            if not row:
                return None
            value_s, expires = row
            if expires is not None and expires <= self._now():
                # expired
                self._conn.execute(f"DELETE FROM {self.table} WHERE key = ?", (key,))
                self._conn.commit()
                return None
            try:
                return json.loads(value_s)
            except Exception:
                return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        ttl = int(ttl) if ttl is not None else self._ttl
        expires = self._now() + int(ttl)
        value_s = json.dumps(value)
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO {self.table} (key, value, expires) VALUES (?, ?, ?)",
                (key, value_s, expires),
            )
            self._conn.commit()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass
