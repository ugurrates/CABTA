"""
Investigation Memory - Persistent memory for past IOC results and investigation patterns.

Uses a dedicated SQLite database at ``~/.blue-team-assistant/cache/agent_memory.db``
with threading.Lock for safe concurrent access (follows the AgentStore pattern).

Tables:
  - ``ioc_cache``: Previously investigated IOCs with TTL-based expiration.
  - ``investigation_patterns``: Recurring investigation patterns and their frequency.

The memory allows the agent to avoid redundant lookups, recall prior verdicts,
and detect recurring threat patterns across investigations.
"""

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / '.blue-team-assistant' / 'cache' / 'agent_memory.db'

# Default TTL for IOC cache entries (hours)
_DEFAULT_TTL_HOURS = 24


class InvestigationMemory:
    """Persistent investigation memory backed by SQLite.

    Stores previously investigated IOC results (with TTL-based expiration)
    and recurring investigation patterns.  Provides sub-millisecond lookups
    via an in-memory cache that is warmed at startup.

    Follows the same ``threading.Lock + _init_db + _connect + _row_to_dict``
    pattern used by ``AgentStore``.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._lock = threading.Lock()
        self._init_db()

        # In-memory IOC cache for fast lookups
        self._ioc_mem_cache: Dict[str, Dict] = {}
        self._warm_cache()

    # ================================================================== #
    #  IOC Cache
    # ================================================================== #

    def remember_ioc(
        self,
        ioc: str,
        result: Dict,
        ttl_hours: int = _DEFAULT_TTL_HOURS,
    ) -> None:
        """Store an IOC investigation result in the cache.

        Args:
            ioc:       The indicator (IP, domain, URL, hash).
            result:    Full investigation result dict.
            ttl_hours: Time-to-live in hours (default 24).
        """
        now = datetime.now(timezone.utc).isoformat()
        result_json = json.dumps(result, default=str)

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO ioc_cache
                       (ioc, result_json, queried_at, ttl_hours)
                       VALUES (?, ?, ?, ?)""",
                    (ioc, result_json, now, ttl_hours),
                )
                conn.commit()
            finally:
                conn.close()

        # Update in-memory cache
        self._ioc_mem_cache[ioc] = {
            "ioc": ioc,
            "result": result,
            "queried_at": now,
            "ttl_hours": ttl_hours,
        }

        logger.debug("[MEMORY] Remembered IOC: %s (ttl=%dh)", ioc, ttl_hours)

    def recall_ioc(self, ioc: str) -> Optional[Dict]:
        """Look up a previously investigated IOC.

        Returns the cached result dict if the entry exists and has not
        expired, or ``None`` if the IOC is unknown or stale.
        """
        # Check in-memory cache first
        if ioc in self._ioc_mem_cache:
            entry = self._ioc_mem_cache[ioc]
            if not self._is_expired(entry.get("queried_at", ""),
                                    entry.get("ttl_hours", _DEFAULT_TTL_HOURS)):
                return entry.get("result")
            else:
                # Expired -- remove from memory cache
                del self._ioc_mem_cache[ioc]

        # Fall back to SQLite
        try:
            conn = self._connect()
            cur = conn.execute(
                "SELECT ioc, result_json, queried_at, ttl_hours "
                "FROM ioc_cache WHERE ioc = ?",
                (ioc,),
            )
            row = cur.fetchone()
            conn.close()
        except Exception as exc:
            logger.debug("[MEMORY] recall_ioc DB error: %s", exc)
            return None

        if row is None:
            return None

        queried_at = row[2]
        ttl_hours = row[3] or _DEFAULT_TTL_HOURS

        if self._is_expired(queried_at, ttl_hours):
            # Expired entry -- clean it up
            self._delete_ioc(ioc)
            return None

        try:
            result = json.loads(row[1]) if row[1] else {}
        except json.JSONDecodeError:
            result = {}

        # Populate in-memory cache
        self._ioc_mem_cache[ioc] = {
            "ioc": row[0],
            "result": result,
            "queried_at": queried_at,
            "ttl_hours": ttl_hours,
        }

        return result

    def forget_ioc(self, ioc: str) -> None:
        """Remove a specific IOC from the cache."""
        self._ioc_mem_cache.pop(ioc, None)
        self._delete_ioc(ioc)

    def purge_expired(self) -> int:
        """Remove all expired IOC cache entries.

        Returns the number of entries removed.
        """
        now = datetime.now(timezone.utc)
        removed = 0

        try:
            conn = self._connect()
            cur = conn.execute("SELECT ioc, queried_at, ttl_hours FROM ioc_cache")
            rows = cur.fetchall()

            to_delete: List[str] = []
            for ioc, queried_at, ttl_hours in rows:
                if self._is_expired(queried_at, ttl_hours or _DEFAULT_TTL_HOURS):
                    to_delete.append(ioc)

            if to_delete:
                with self._lock:
                    conn2 = self._connect()
                    conn2.executemany(
                        "DELETE FROM ioc_cache WHERE ioc = ?",
                        [(ioc,) for ioc in to_delete],
                    )
                    conn2.commit()
                    conn2.close()
                    removed = len(to_delete)

                # Clean memory cache
                for ioc in to_delete:
                    self._ioc_mem_cache.pop(ioc, None)

            conn.close()
        except Exception as exc:
            logger.warning("[MEMORY] purge_expired error: %s", exc)

        if removed > 0:
            logger.info("[MEMORY] Purged %d expired IOC cache entries", removed)
        return removed

    def list_cached_iocs(self, limit: int = 100) -> List[Dict]:
        """Return recently cached IOCs (newest first)."""
        try:
            conn = self._connect()
            cur = conn.execute(
                "SELECT ioc, result_json, queried_at, ttl_hours "
                "FROM ioc_cache ORDER BY queried_at DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
            conn.close()
            results = []
            for row in rows:
                try:
                    result = json.loads(row[1]) if row[1] else {}
                except json.JSONDecodeError:
                    result = {}
                results.append({
                    "ioc": row[0],
                    "result": result,
                    "queried_at": row[2],
                    "ttl_hours": row[3],
                })
            return results
        except Exception as exc:
            logger.debug("[MEMORY] list_cached_iocs error: %s", exc)
            return []

    # ================================================================== #
    #  Investigation Patterns
    # ================================================================== #

    def record_pattern(
        self,
        pattern_type: str,
        description: str,
    ) -> None:
        """Record or increment the frequency of an investigation pattern.

        Args:
            pattern_type: Category of the pattern (e.g. ``"c2_infrastructure"``,
                          ``"malware_family"``, ``"attack_technique"``).
            description:  Human-readable description of the specific pattern
                          (e.g. ``"Cobalt Strike beacon on port 443"``).
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            try:
                # Try to increment existing pattern
                cur = conn.execute(
                    """UPDATE investigation_patterns
                       SET frequency = frequency + 1, last_seen = ?
                       WHERE pattern_type = ? AND description = ?""",
                    (now, pattern_type, description),
                )
                if cur.rowcount == 0:
                    # Insert new pattern
                    conn.execute(
                        """INSERT INTO investigation_patterns
                           (pattern_type, description, frequency, first_seen, last_seen)
                           VALUES (?, ?, 1, ?, ?)""",
                        (pattern_type, description, now, now),
                    )
                conn.commit()
            finally:
                conn.close()

        logger.debug("[MEMORY] Recorded pattern: %s / %s", pattern_type, description[:60])

    def get_frequent_patterns(
        self,
        pattern_type: Optional[str] = None,
        min_frequency: int = 2,
        limit: int = 50,
    ) -> List[Dict]:
        """Return investigation patterns ordered by frequency.

        Args:
            pattern_type:  Filter to a specific pattern type (optional).
            min_frequency: Only return patterns seen at least this many times.
            limit:         Maximum number of results.

        Returns:
            List of dicts with ``pattern_type``, ``description``,
            ``frequency``, ``first_seen``, ``last_seen``.
        """
        try:
            conn = self._connect()
            if pattern_type:
                cur = conn.execute(
                    """SELECT pattern_type, description, frequency, first_seen, last_seen
                       FROM investigation_patterns
                       WHERE pattern_type = ? AND frequency >= ?
                       ORDER BY frequency DESC
                       LIMIT ?""",
                    (pattern_type, min_frequency, limit),
                )
            else:
                cur = conn.execute(
                    """SELECT pattern_type, description, frequency, first_seen, last_seen
                       FROM investigation_patterns
                       WHERE frequency >= ?
                       ORDER BY frequency DESC
                       LIMIT ?""",
                    (min_frequency, limit),
                )
            rows = cur.fetchall()
            conn.close()

            return [
                {
                    "pattern_type": row[0],
                    "description": row[1],
                    "frequency": row[2],
                    "first_seen": row[3],
                    "last_seen": row[4],
                }
                for row in rows
            ]
        except Exception as exc:
            logger.debug("[MEMORY] get_frequent_patterns error: %s", exc)
            return []

    def get_pattern_summary(self) -> Dict:
        """Return aggregate statistics about recorded patterns."""
        try:
            conn = self._connect()
            cur = conn.execute(
                "SELECT COUNT(*), SUM(frequency) FROM investigation_patterns"
            )
            row = cur.fetchone()
            total_patterns = row[0] or 0
            total_sightings = row[1] or 0

            cur2 = conn.execute(
                """SELECT pattern_type, COUNT(*) as cnt
                   FROM investigation_patterns
                   GROUP BY pattern_type
                   ORDER BY cnt DESC"""
            )
            by_type = {r[0]: r[1] for r in cur2.fetchall()}

            cur3 = conn.execute("SELECT COUNT(*) FROM ioc_cache")
            cached_iocs = cur3.fetchone()[0] or 0

            conn.close()

            return {
                "total_patterns": total_patterns,
                "total_sightings": total_sightings,
                "patterns_by_type": by_type,
                "cached_iocs": cached_iocs,
            }
        except Exception as exc:
            logger.debug("[MEMORY] get_pattern_summary error: %s", exc)
            return {
                "total_patterns": 0,
                "total_sightings": 0,
                "patterns_by_type": {},
                "cached_iocs": 0,
            }

    # ================================================================== #
    #  DB initialisation & helpers
    # ================================================================== #

    def _init_db(self) -> None:
        """Create the database and tables if they do not exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ioc_cache (
                ioc         TEXT PRIMARY KEY,
                result_json TEXT,
                queried_at  TEXT NOT NULL,
                ttl_hours   INTEGER DEFAULT 24
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigation_patterns (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT NOT NULL,
                description  TEXT NOT NULL,
                frequency    INTEGER DEFAULT 1,
                first_seen   TEXT NOT NULL,
                last_seen    TEXT NOT NULL,
                UNIQUE(pattern_type, description)
            )
        """)

        # Indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ioc_cache_queried "
            "ON ioc_cache(queried_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_patterns_type "
            "ON investigation_patterns(pattern_type)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_patterns_freq "
            "ON investigation_patterns(frequency DESC)"
        )

        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        """Open a connection to the memory database."""
        return sqlite3.connect(str(self._db_path), timeout=5)

    def _warm_cache(self) -> None:
        """Pre-load recent non-expired IOC entries into memory."""
        try:
            conn = self._connect()
            cur = conn.execute(
                "SELECT ioc, result_json, queried_at, ttl_hours "
                "FROM ioc_cache ORDER BY queried_at DESC LIMIT 5000"
            )
            rows = cur.fetchall()
            conn.close()

            for row in rows:
                queried_at = row[2]
                ttl_hours = row[3] or _DEFAULT_TTL_HOURS
                if not self._is_expired(queried_at, ttl_hours):
                    try:
                        result = json.loads(row[1]) if row[1] else {}
                    except json.JSONDecodeError:
                        result = {}
                    self._ioc_mem_cache[row[0]] = {
                        "ioc": row[0],
                        "result": result,
                        "queried_at": queried_at,
                        "ttl_hours": ttl_hours,
                    }

            logger.debug("[MEMORY] Warmed cache with %d IOCs", len(self._ioc_mem_cache))
        except Exception as exc:
            logger.debug("[MEMORY] Cache warm-up failed: %s", exc)

    def _delete_ioc(self, ioc: str) -> None:
        """Delete a single IOC from the database."""
        try:
            with self._lock:
                conn = self._connect()
                conn.execute("DELETE FROM ioc_cache WHERE ioc = ?", (ioc,))
                conn.commit()
                conn.close()
        except Exception as exc:
            logger.debug("[MEMORY] _delete_ioc error: %s", exc)

    @staticmethod
    def _is_expired(queried_at: str, ttl_hours: int) -> bool:
        """Check whether an IOC cache entry has exceeded its TTL."""
        if not queried_at:
            return True
        try:
            ts = datetime.fromisoformat(queried_at)
            # Ensure timezone-aware comparison
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            expiry = ts + timedelta(hours=ttl_hours)
            return datetime.now(timezone.utc) > expiry
        except (ValueError, TypeError):
            return True

    @staticmethod
    def _row_to_dict(description, row) -> Dict:
        """Convert a sqlite3 row to a dict (AgentStore convention)."""
        cols = [d[0] for d in description]
        d = dict(zip(cols, row))
        for key in ("result_json",):
            if d.get(key) and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except json.JSONDecodeError:
                    pass
        return d
