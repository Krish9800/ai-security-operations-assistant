"""SQLite persistence engine with Write-Ahead Logging (WAL) mode."""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ai_secops.config.settings import get_settings
from ai_secops.models.enums import ActionStatus, MessageRole, SIEMTarget
from ai_secops.models.schemas import (
    ContainmentAction,
    CopilotMessage,
    CopilotSession,
    IncidentNarrative,
    RootCauseAnalysis,
    TimelineEvent,
)


class DatabaseEngine:
    """Manages SQLite connections, schema migrations, and WAL persistence."""

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        metadata TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS query_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        prompt TEXT NOT NULL,
        target TEXT NOT NULL,
        query TEXT NOT NULL,
        validated INTEGER NOT NULL,
        explanation TEXT,
        timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS incident_narratives (
        incident_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        executive_summary TEXT NOT NULL,
        technical_narrative TEXT NOT NULL,
        rca_json TEXT NOT NULL,
        timeline_json TEXT NOT NULL,
        affected_assets_json TEXT NOT NULL,
        affected_identities_json TEXT NOT NULL,
        mitre_techniques_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS recommendations (
        action_id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        rationale TEXT NOT NULL,
        confidence_score REAL NOT NULL,
        blast_radius_score REAL NOT NULL,
        requires_confirmation INTEGER NOT NULL,
        status TEXT NOT NULL,
        rollback_procedure TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            settings = get_settings()
            self.db_path = settings.resolve_db_path()

        self._initialize_schema()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a connection configured with WAL mode, normal sync, and foreign keys."""
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize_schema(self) -> None:
        """Create database tables if they do not exist."""
        with self.get_connection() as conn:
            conn.executescript(self.SCHEMA_SQL)

    # --- Session & Message Repository ---

    def create_session(self, title: str, session_id: str | None = None) -> CopilotSession:
        """Create a new copilot conversation session."""
        import uuid

        sid = session_id or f"sess-{uuid.uuid4().hex[:8]}"
        now = datetime.now(UTC).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, title, created_at) VALUES (?, ?, ?)",
                (sid, title, now),
            )
        return CopilotSession(session_id=sid, title=title, created_at=now, messages=[])

    def get_session(self, session_id: str) -> CopilotSession | None:
        """Retrieve a session and its message history."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT session_id, title, created_at FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if not row:
                return None

            msg_rows = conn.execute(
                "SELECT role, content, timestamp, metadata FROM messages "
                "WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            ).fetchall()

            messages = [
                CopilotMessage(
                    role=MessageRole(m["role"]),
                    content=m["content"],
                    timestamp=m["timestamp"],
                    metadata=json.loads(m["metadata"]),
                )
                for m in msg_rows
            ]

            return CopilotSession(
                session_id=row["session_id"],
                title=row["title"],
                created_at=row["created_at"],
                messages=messages,
            )

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all conversation sessions ordered by creation date."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT session_id, title, created_at FROM sessions ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_session(self, session_id: str) -> bool:
        """Delete a conversation session and cascade its messages."""
        with self.get_connection() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            return cur.rowcount > 0

    def add_message(
        self,
        session_id: str,
        role: MessageRole,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> CopilotMessage:
        """Append a message to an existing session."""
        now = datetime.now(UTC).isoformat()
        meta_str = json.dumps(metadata or {})
        with self.get_connection() as conn:
            conn.execute(
                "INSERT INTO messages (session_id, role, content, timestamp, metadata) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, role.value, content, now, meta_str),
            )
        return CopilotMessage(role=role, content=content, timestamp=now, metadata=metadata or {})

    # --- Query Logs Repository ---

    def log_query(
        self,
        prompt: str,
        target: SIEMTarget,
        query: str,
        validated: bool,
        explanation: str,
        session_id: str | None = None,
    ) -> int:
        """Log a synthesized SIEM query for audit and performance metrics."""
        now = datetime.now(UTC).isoformat()
        with self.get_connection() as conn:
            sql = (
                "INSERT INTO query_logs "
                "(session_id, prompt, target, query, validated, explanation, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            cur = conn.execute(
                sql,
                (session_id, prompt, target.value, query, 1 if validated else 0, explanation, now),
            )
            return int(cur.lastrowid or 0)

    def get_query_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent query logs."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM query_logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # --- Narrative Repository ---

    def save_incident_narrative(self, narrative: IncidentNarrative) -> None:
        """Persist an incident narrative and RCA report."""
        now = datetime.now(UTC).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO incident_narratives ("
                "incident_id, title, executive_summary, technical_narrative, "
                "rca_json, timeline_json, affected_assets_json, affected_identities_json, "
                "mitre_techniques_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    narrative.incident_id,
                    narrative.title,
                    narrative.executive_summary,
                    narrative.technical_narrative,
                    narrative.rca.model_dump_json(),
                    json.dumps([t.model_dump() for t in narrative.timeline]),
                    json.dumps(narrative.affected_assets),
                    json.dumps(narrative.affected_identities),
                    json.dumps(narrative.mitre_techniques),
                    now,
                ),
            )

    def get_incident_narrative(self, incident_id: str) -> IncidentNarrative | None:
        """Retrieve an incident narrative by ID."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM incident_narratives WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if not row:
                return None

            rca = RootCauseAnalysis.model_validate_json(row["rca_json"])
            timeline_raw = json.loads(row["timeline_json"])
            timeline = [TimelineEvent.model_validate(t) for t in timeline_raw]

            return IncidentNarrative(
                incident_id=row["incident_id"],
                title=row["title"],
                executive_summary=row["executive_summary"],
                technical_narrative=row["technical_narrative"],
                timeline=timeline,
                rca=rca,
                affected_assets=json.loads(row["affected_assets_json"]),
                affected_identities=json.loads(row["affected_identities_json"]),
                mitre_techniques=json.loads(row["mitre_techniques_json"]),
            )

    # --- Recommendations Repository ---

    def save_recommendations(self, incident_id: str, actions: list[ContainmentAction]) -> None:
        """Persist containment action recommendations."""
        now = datetime.now(UTC).isoformat()
        with self.get_connection() as conn:
            for action in actions:
                conn.execute(
                    "INSERT OR REPLACE INTO recommendations ("
                    "action_id, incident_id, action_type, target_entity, rationale, "
                    "confidence_score, blast_radius_score, requires_confirmation, status, "
                    "rollback_procedure, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        action.action_id,
                        incident_id,
                        action.action_type.value,
                        action.target_entity,
                        action.rationale,
                        action.confidence_score,
                        action.blast_radius_score,
                        1 if action.requires_confirmation else 0,
                        action.status.value,
                        action.rollback_procedure,
                        now,
                    ),
                )

    def update_action_status(self, action_id: str, status: ActionStatus) -> bool:
        """Update the lifecycle status of a containment action (e.g. APPROVED, EXECUTED)."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE recommendations SET status = ? WHERE action_id = ?",
                (status.value, action_id),
            )
            return cur.rowcount > 0

    def get_incident_recommendations(self, incident_id: str) -> list[dict[str, Any]]:
        """Retrieve stored recommendations for an incident."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM recommendations WHERE incident_id = ? ORDER BY created_at ASC",
                (incident_id,),
            ).fetchall()
            return [dict(r) for r in rows]
