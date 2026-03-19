"""
Agent Store - SQLite persistence for agent sessions, steps, MCP connections and playbooks.

Follows the AnalysisManager / CaseStore pattern (threading.Lock + _init_db + _connect + _row_to_dict).
"""

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / '.blue-team-assistant' / 'cache' / 'agent.db'


class AgentStore:
    """SQLite-backed persistence for the autonomous agent."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._lock = threading.Lock()
        self._init_db()

    # ================================================================== #
    #  Sessions
    # ================================================================== #

    def create_session(
        self,
        goal: str,
        case_id: Optional[str] = None,
        playbook_id: Optional[str] = None,
    ) -> str:
        """Create a new agent session. Returns session ID."""
        session_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO agent_sessions
                   (id, case_id, goal, status, playbook_id, created_at, findings, metadata)
                   VALUES (?, ?, ?, 'active', ?, ?, '[]', '{}')""",
                (session_id, case_id, goal, playbook_id, now),
            )
            conn.commit()
            conn.close()

        logger.info(f"[AGENT] Created session {session_id}: {goal[:80]}")
        return session_id

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Retrieve a single session by ID."""
        conn = self._connect()
        cur = conn.execute(
            "SELECT * FROM agent_sessions WHERE id = ?", (session_id,),
        )
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return self._row_to_dict(cur.description, row)

    def list_sessions(
        self, limit: int = 50, status: Optional[str] = None,
    ) -> List[Dict]:
        """List sessions, newest first, with optional status filter."""
        conn = self._connect()
        if status:
            cur = conn.execute(
                """SELECT * FROM agent_sessions WHERE status = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (status, limit),
            )
        else:
            cur = conn.execute(
                "SELECT * FROM agent_sessions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, r) for r in rows]

    def update_session_status(
        self,
        session_id: str,
        status: str,
        summary: Optional[str] = None,
    ) -> None:
        """Update session status and optionally set the summary."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            if summary is not None:
                conn.execute(
                    """UPDATE agent_sessions
                       SET status = ?, summary = ?, completed_at = ?
                       WHERE id = ?""",
                    (status, summary, now, session_id),
                )
            else:
                conn.execute(
                    "UPDATE agent_sessions SET status = ? WHERE id = ?",
                    (status, session_id),
                )
            conn.commit()
            conn.close()

        logger.info(f"[AGENT] Session {session_id} -> {status}")

    def update_session_findings(
        self, session_id: str, findings: List[Dict],
    ) -> None:
        """Persist the current findings list."""
        findings_json = json.dumps(findings, default=str)
        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE agent_sessions SET findings = ? WHERE id = ?",
                (findings_json, session_id),
            )
            conn.commit()
            conn.close()

    # ================================================================== #
    #  Steps
    # ================================================================== #

    def add_step(
        self,
        session_id: str,
        step_number: int,
        step_type: str,
        content: str,
        tool_name: Optional[str] = None,
        tool_params: Optional[str] = None,
        tool_result: Optional[str] = None,
        duration_ms: Optional[int] = None,
    ) -> str:
        """Record an agent step. Returns step ID."""
        step_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            conn.execute(
                """INSERT INTO agent_steps
                   (id, session_id, step_number, step_type, content,
                    tool_name, tool_params, tool_result, duration_ms, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (step_id, session_id, step_number, step_type, content,
                 tool_name, tool_params, tool_result, duration_ms, now),
            )
            conn.commit()
            conn.close()

        return step_id

    def get_steps(self, session_id: str) -> List[Dict]:
        """Return all steps for a session ordered by step_number."""
        conn = self._connect()
        cur = conn.execute(
            """SELECT * FROM agent_steps
               WHERE session_id = ?
               ORDER BY step_number ASC""",
            (session_id,),
        )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, r) for r in rows]

    # ================================================================== #
    #  MCP Connections
    # ================================================================== #

    def save_mcp_connection(
        self, name: str, transport: str, config: Dict,
    ) -> str:
        """Upsert an MCP server connection. Returns connection ID."""
        conn_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        config_json = json.dumps(config, default=str)

        with self._lock:
            conn = self._connect()
            # Try update first
            cur = conn.execute(
                """UPDATE mcp_connections
                   SET transport = ?, config_json = ?
                   WHERE name = ?""",
                (transport, config_json, name),
            )
            if cur.rowcount == 0:
                conn.execute(
                    """INSERT INTO mcp_connections
                       (id, name, transport, config_json, status, created_at)
                       VALUES (?, ?, ?, ?, 'disconnected', ?)""",
                    (conn_id, name, transport, config_json, now),
                )
            conn.commit()
            conn.close()

        logger.info(f"[AGENT] Saved MCP connection: {name} ({transport})")
        return conn_id

    def list_mcp_connections(self) -> List[Dict]:
        """Return all registered MCP connections."""
        conn = self._connect()
        cur = conn.execute(
            "SELECT * FROM mcp_connections ORDER BY name ASC",
        )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, r) for r in rows]

    def update_mcp_status(
        self,
        name: str,
        status: str,
        tools: Optional[List[Dict]] = None,
    ) -> None:
        """Update connection status and optionally refresh tool list."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            if tools is not None:
                tools_json = json.dumps(tools, default=str)
                conn.execute(
                    """UPDATE mcp_connections
                       SET status = ?, last_connected = ?, tools_json = ?
                       WHERE name = ?""",
                    (status, now, tools_json, name),
                )
            else:
                conn.execute(
                    """UPDATE mcp_connections
                       SET status = ?, last_connected = ?
                       WHERE name = ?""",
                    (status, now, name),
                )
            conn.commit()
            conn.close()

    def delete_mcp_connection(self, name: str) -> None:
        """Remove an MCP connection by name."""
        with self._lock:
            conn = self._connect()
            conn.execute(
                "DELETE FROM mcp_connections WHERE name = ?", (name,),
            )
            conn.commit()
            conn.close()
        logger.info(f"[AGENT] Deleted MCP connection: {name}")

    # ================================================================== #
    #  Playbooks
    # ================================================================== #

    def save_playbook(
        self,
        name: str,
        description: str,
        steps: List[Dict],
        trigger_type: str = 'manual',
    ) -> str:
        """Create or update a playbook. Returns playbook ID."""
        playbook_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        steps_json = json.dumps(steps, default=str)

        with self._lock:
            conn = self._connect()
            # Try update first
            cur = conn.execute(
                """UPDATE playbooks
                   SET description = ?, trigger_type = ?, steps_json = ?, updated_at = ?
                   WHERE name = ?""",
                (description, trigger_type, steps_json, now, name),
            )
            if cur.rowcount == 0:
                conn.execute(
                    """INSERT INTO playbooks
                       (id, name, description, trigger_type, steps_json, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (playbook_id, name, description, trigger_type, steps_json, now, now),
                )
            conn.commit()
            conn.close()

        logger.info(f"[AGENT] Saved playbook: {name}")
        return playbook_id

    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        """Retrieve a single playbook by ID."""
        conn = self._connect()
        cur = conn.execute(
            "SELECT * FROM playbooks WHERE id = ?", (playbook_id,),
        )
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return self._row_to_dict(cur.description, row)

    def list_playbooks(self) -> List[Dict]:
        """List all playbooks."""
        conn = self._connect()
        cur = conn.execute(
            "SELECT * FROM playbooks ORDER BY updated_at DESC",
        )
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        return [self._row_to_dict(desc, r) for r in rows]

    # ================================================================== #
    #  Statistics
    # ================================================================== #

    def get_agent_stats(self) -> Dict:
        """Return aggregate statistics across sessions and steps."""
        conn = self._connect()

        cur = conn.execute(
            """SELECT
                 COUNT(*) AS total,
                 SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
                 SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
                 SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
               FROM agent_sessions"""
        )
        row = cur.fetchone()
        total_sessions = row[0] or 0
        active_sessions = row[1] or 0
        completed_sessions = row[2] or 0
        failed_sessions = row[3] or 0

        cur2 = conn.execute("SELECT COUNT(*) FROM agent_steps")
        total_steps = cur2.fetchone()[0] or 0

        conn.close()

        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "completed_sessions": completed_sessions,
            "failed_sessions": failed_sessions,
            "total_steps": total_steps,
        }

    # ================================================================== #
    #  DB helpers
    # ================================================================== #

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()

        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_sessions (
                id           TEXT PRIMARY KEY,
                case_id      TEXT,
                goal         TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'active',
                playbook_id  TEXT,
                created_at   TEXT NOT NULL,
                completed_at TEXT,
                summary      TEXT,
                findings     TEXT DEFAULT '[]',
                metadata     TEXT DEFAULT '{}'
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_steps (
                id           TEXT PRIMARY KEY,
                session_id   TEXT NOT NULL,
                step_number  INTEGER NOT NULL,
                step_type    TEXT NOT NULL,
                content      TEXT NOT NULL,
                tool_name    TEXT,
                tool_params  TEXT,
                tool_result  TEXT,
                duration_ms  INTEGER,
                created_at   TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES agent_sessions(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS mcp_connections (
                id             TEXT PRIMARY KEY,
                name           TEXT NOT NULL UNIQUE,
                transport      TEXT NOT NULL,
                config_json    TEXT NOT NULL,
                status         TEXT DEFAULT 'disconnected',
                last_connected TEXT,
                tools_json     TEXT DEFAULT '[]',
                created_at     TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS playbooks (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL UNIQUE,
                description  TEXT,
                trigger_type TEXT DEFAULT 'manual',
                steps_json   TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            )
        """)

        # Indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_status ON agent_sessions(status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_created ON agent_sessions(created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_steps_session ON agent_steps(session_id)"
        )

        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    @staticmethod
    def _row_to_dict(description, row) -> Dict:
        cols = [d[0] for d in description]
        d = dict(zip(cols, row))
        # Parse known JSON columns
        for key in ('findings', 'metadata', 'config_json', 'tools_json', 'steps_json'):
            if d.get(key) and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except json.JSONDecodeError:
                    pass
        return d
