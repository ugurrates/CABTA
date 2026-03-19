"""
Author: Ugur Ates
Analysis Cache - SQLite-backed cache for file analysis results.

Caches full analysis results keyed by SHA-256 hash to prevent
redundant re-analysis of the same file.
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / '.blue-team-assistant' / 'cache' / 'analysis_cache.db'


class AnalysisCache:
    """SQLite-backed file analysis result cache.

    Usage::

        cache = AnalysisCache()
        cached = cache.get('abc123sha256...')
        if cached is None:
            result = run_analysis(file_path)
            cache.set('abc123sha256...', result)
    """

    def __init__(self, db_path: Optional[str] = None, max_age_days: int = 30):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._max_age_days = max_age_days
        self._lock = threading.Lock()
        self._stats = {'hits': 0, 'misses': 0, 'sets': 0}
        self._init_db()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def get(self, sha256: str) -> Optional[Dict]:
        """Retrieve cached analysis result by SHA-256.

        Returns ``None`` on cache miss or expired entry.
        """
        with self._lock:
            try:
                conn = self._connect()
                cur = conn.execute(
                    "SELECT result_json, analyzed_at FROM file_cache WHERE sha256 = ?",
                    (sha256,),
                )
                row = cur.fetchone()
                conn.close()

                if row is None:
                    self._stats['misses'] += 1
                    return None

                result_json, analyzed_at_str = row
                analyzed_at = datetime.fromisoformat(analyzed_at_str)
                if analyzed_at.tzinfo is None:
                    analyzed_at = analyzed_at.replace(tzinfo=timezone.utc)

                age = (datetime.now(timezone.utc) - analyzed_at).days
                if age > self._max_age_days:
                    self._stats['misses'] += 1
                    self._delete(sha256)
                    return None

                self._stats['hits'] += 1
                return json.loads(result_json)

            except Exception as exc:
                logger.debug(f"[ANALYSIS-CACHE] get error: {exc}")
                self._stats['misses'] += 1
                return None

    def set(self, sha256: str, result: Dict) -> None:
        """Store analysis result in cache."""
        now = datetime.now(timezone.utc).isoformat()
        result_json = json.dumps(result, default=str)

        with self._lock:
            try:
                conn = self._connect()
                conn.execute(
                    """INSERT OR REPLACE INTO file_cache
                       (sha256, result_json, analyzed_at)
                       VALUES (?, ?, ?)""",
                    (sha256, result_json, now),
                )
                conn.commit()
                conn.close()
                self._stats['sets'] += 1
            except Exception as exc:
                logger.debug(f"[ANALYSIS-CACHE] set error: {exc}")

    def has(self, sha256: str) -> bool:
        """Check if a non-expired result exists for this hash."""
        return self.get(sha256) is not None

    def invalidate(self, sha256: str) -> bool:
        """Remove a specific cached result.  Returns True if deleted."""
        with self._lock:
            return self._delete(sha256)

    def cleanup_expired(self) -> int:
        """Remove all expired entries.  Returns count deleted."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self._max_age_days)).isoformat()
        with self._lock:
            try:
                conn = self._connect()
                cur = conn.execute(
                    "DELETE FROM file_cache WHERE analyzed_at < ?",
                    (cutoff,),
                )
                conn.commit()
                deleted = cur.rowcount
                conn.close()
                return deleted
            except Exception:
                return 0

    def get_stats(self) -> Dict:
        """Return cache statistics."""
        total = self._stats['hits'] + self._stats['misses']
        return {
            **self._stats,
            'hit_rate': round(self._stats['hits'] / total, 3) if total else 0.0,
            'total_queries': total,
            'entries': self.count(),
        }

    def count(self) -> int:
        """Return number of entries in cache."""
        try:
            conn = self._connect()
            cur = conn.execute("SELECT COUNT(*) FROM file_cache")
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
                conn.execute("DELETE FROM file_cache")
                conn.commit()
                conn.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_cache (
                sha256      TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                analyzed_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    def _delete(self, sha256: str) -> bool:
        try:
            conn = self._connect()
            cur = conn.execute("DELETE FROM file_cache WHERE sha256=?", (sha256,))
            conn.commit()
            deleted = cur.rowcount > 0
            conn.close()
            return deleted
        except Exception:
            return False
