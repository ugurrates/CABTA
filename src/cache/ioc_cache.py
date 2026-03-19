"""
Author: Ugur Ates
IOC Cache - SQLite-backed cache for threat intelligence lookups.

Features:
- Per-IOC caching with configurable TTL
- Automatic expiry of stale entries
- Source-specific cache (VirusTotal, AbuseIPDB, etc.)
- Cache hit/miss statistics
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / '.blue-team-assistant' / 'cache' / 'ioc_cache.db'


class IOCCache:
    """SQLite-backed IOC lookup cache.

    Usage::

        cache = IOCCache()
        cached = cache.get('8.8.8.8', 'ip', 'virustotal')
        if cached is None:
            result = api_call(...)
            cache.set('8.8.8.8', 'ip', 'virustotal', result, ttl_hours=24)
    """

    def __init__(self, db_path: Optional[str] = None, default_ttl_hours: int = 24):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._default_ttl = default_ttl_hours
        self._lock = threading.Lock()
        self._stats = {'hits': 0, 'misses': 0, 'sets': 0, 'evictions': 0}
        self._init_db()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def get(
        self,
        ioc: str,
        ioc_type: str,
        source: str,
    ) -> Optional[Dict]:
        """Retrieve a cached IOC result.

        Returns ``None`` on cache miss or expired entry.
        """
        with self._lock:
            try:
                conn = self._connect()
                cur = conn.execute(
                    """SELECT result_json, queried_at, ttl_hours
                       FROM ioc_cache
                       WHERE ioc = ? AND ioc_type = ? AND source = ?""",
                    (ioc, ioc_type, source),
                )
                row = cur.fetchone()
                conn.close()

                if row is None:
                    self._stats['misses'] += 1
                    return None

                result_json, queried_at_str, ttl_hours = row
                queried_at = datetime.fromisoformat(queried_at_str)
                if queried_at.tzinfo is None:
                    queried_at = queried_at.replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)
                if (now - queried_at) > timedelta(hours=ttl_hours):
                    self._stats['misses'] += 1
                    self._stats['evictions'] += 1
                    self._delete(ioc, ioc_type, source)
                    return None

                self._stats['hits'] += 1
                return json.loads(result_json)

            except Exception as exc:
                logger.debug(f"[IOC-CACHE] get error: {exc}")
                self._stats['misses'] += 1
                return None

    def set(
        self,
        ioc: str,
        ioc_type: str,
        source: str,
        result: Any,
        ttl_hours: Optional[int] = None,
    ) -> None:
        """Store an IOC lookup result in cache."""
        ttl = ttl_hours if ttl_hours is not None else self._default_ttl
        now = datetime.now(timezone.utc).isoformat()
        result_json = json.dumps(result, default=str)

        with self._lock:
            try:
                conn = self._connect()
                conn.execute(
                    """INSERT OR REPLACE INTO ioc_cache
                       (ioc, ioc_type, source, result_json, queried_at, ttl_hours)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (ioc, ioc_type, source, result_json, now, ttl),
                )
                conn.commit()
                conn.close()
                self._stats['sets'] += 1
            except Exception as exc:
                logger.debug(f"[IOC-CACHE] set error: {exc}")

    def invalidate(self, ioc: str, ioc_type: str = '', source: str = '') -> int:
        """Remove entries matching the given filters.  Returns count deleted."""
        with self._lock:
            try:
                conn = self._connect()
                if source and ioc_type:
                    cur = conn.execute(
                        "DELETE FROM ioc_cache WHERE ioc=? AND ioc_type=? AND source=?",
                        (ioc, ioc_type, source),
                    )
                elif ioc_type:
                    cur = conn.execute(
                        "DELETE FROM ioc_cache WHERE ioc=? AND ioc_type=?",
                        (ioc, ioc_type),
                    )
                else:
                    cur = conn.execute("DELETE FROM ioc_cache WHERE ioc=?", (ioc,))
                conn.commit()
                deleted = cur.rowcount
                conn.close()
                return deleted
            except Exception:
                return 0

    def cleanup_expired(self) -> int:
        """Remove all expired entries.  Returns count deleted."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                conn = self._connect()
                cur = conn.execute(
                    """DELETE FROM ioc_cache
                       WHERE datetime(queried_at, '+' || ttl_hours || ' hours') < ?""",
                    (now,),
                )
                conn.commit()
                deleted = cur.rowcount
                conn.close()
                self._stats['evictions'] += deleted
                return deleted
            except Exception:
                return 0

    def get_stats(self) -> Dict:
        """Return cache hit/miss statistics."""
        total = self._stats['hits'] + self._stats['misses']
        return {
            **self._stats,
            'hit_rate': round(self._stats['hits'] / total, 3) if total else 0.0,
            'total_queries': total,
        }

    def count(self) -> int:
        """Return number of entries in cache."""
        try:
            conn = self._connect()
            cur = conn.execute("SELECT COUNT(*) FROM ioc_cache")
            n = cur.fetchone()[0]
            conn.close()
            return n
        except Exception:
            return 0

    def clear(self) -> None:
        """Remove all cache entries."""
        with self._lock:
            try:
                conn = self._connect()
                conn.execute("DELETE FROM ioc_cache")
                conn.commit()
                conn.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ioc_cache (
                ioc       TEXT NOT NULL,
                ioc_type  TEXT NOT NULL,
                source    TEXT NOT NULL,
                result_json TEXT NOT NULL,
                queried_at TEXT NOT NULL,
                ttl_hours  INTEGER NOT NULL DEFAULT 24,
                PRIMARY KEY (ioc, ioc_type, source)
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ioc_cache_queried ON ioc_cache(queried_at)"
        )
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    def _delete(self, ioc: str, ioc_type: str, source: str) -> None:
        try:
            conn = self._connect()
            conn.execute(
                "DELETE FROM ioc_cache WHERE ioc=? AND ioc_type=? AND source=?",
                (ioc, ioc_type, source),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
