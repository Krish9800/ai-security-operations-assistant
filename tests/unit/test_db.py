"""Unit tests for SQLite WAL persistence engine."""

from pathlib import Path

from ai_secops.db import DatabaseEngine
from ai_secops.models.enums import (
    ActionStatus,
    ActionType,
    ConfidenceLevel,
    MessageRole,
    SIEMTarget,
)
from ai_secops.models.schemas import (
    ContainmentAction,
    IncidentNarrative,
    RootCauseAnalysis,
    TimelineEvent,
)


def test_sqlite_wal_pragmas(temp_dir: Path) -> None:
    """Verify SQLite WAL mode and foreign keys are active."""
    db_file = temp_dir / "wal_test.db"
    db = DatabaseEngine(db_file)

    with db.get_connection() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        foreign_keys = conn.execute("PRAGMA foreign_keys;").fetchone()[0]

    assert journal_mode.lower() == "wal"
    assert foreign_keys == 1


def test_session_lifecycle_and_messages(temp_dir: Path) -> None:
    """Test creating, listing, fetching, adding messages, and deleting sessions."""
    db = DatabaseEngine(temp_dir / "secops.db")

    session = db.create_session(title="Investigation S-1")
    assert session.session_id.startswith("sess-")
    assert session.title == "Investigation S-1"

    db.add_message(
        session_id=session.session_id,
        role=MessageRole.USER,
        content="Is host WS-01 compromised?",
    )
    db.add_message(
        session_id=session.session_id,
        role=MessageRole.ASSISTANT,
        content="Yes, high confidence indicators of compromise detected.",
        metadata={"confidence": 0.95},
    )

    retrieved = db.get_session(session.session_id)
    assert retrieved is not None
    assert len(retrieved.messages) == 2
    assert retrieved.messages[0].role == MessageRole.USER
    assert retrieved.messages[1].metadata["confidence"] == 0.95

    # Test listing
    sessions = db.list_sessions()
    assert len(sessions) == 1

    # Test cascade deletion
    deleted = db.delete_session(session.session_id)
    assert deleted is True
    assert db.get_session(session.session_id) is None
    assert len(db.list_sessions()) == 0


def test_query_logging(temp_dir: Path) -> None:
    """Test audit logging of synthesized queries."""
    db = DatabaseEngine(temp_dir / "secops.db")

    log_id = db.log_query(
        prompt="Find powershell downloads",
        target=SIEMTarget.SPL,
        query='index=windows process_name="powershell.exe" DownloadString',
        validated=True,
        explanation="Search for download cradles",
    )
    assert log_id > 0

    logs = db.get_query_logs()
    assert len(logs) == 1
    assert logs[0]["target"] == "spl"
    assert logs[0]["validated"] == 1


def test_incident_narrative_and_recommendations_persistence(temp_dir: Path) -> None:
    """Test saving and retrieving narratives and containment actions."""
    db = DatabaseEngine(temp_dir / "secops.db")

    timeline = [
        TimelineEvent(
            timestamp="2026-10-14T08:00:00Z",
            event_type="Alert Trigger",
            description="Initial phishing beacon",
            source="edr",
        )
    ]
    rca = RootCauseAnalysis(
        initial_vector="Phishing",
        vulnerability_or_weakness="Macro execution",
        lateral_movement_observed=False,
        data_impact="None",
        evidence_chains=["Step 1"],
    )
    narrative = IncidentNarrative(
        incident_id="INC-PERSIST-01",
        title="Persisted Incident Report",
        executive_summary="Summary text",
        technical_narrative="Technical narrative text",
        timeline=timeline,
        rca=rca,
        affected_assets=["HOST-A"],
        affected_identities=["user-b"],
        mitre_techniques=["T1059.001"],
    )

    db.save_incident_narrative(narrative)
    fetched = db.get_incident_narrative("INC-PERSIST-01")
    assert fetched is not None
    assert fetched.title == "Persisted Incident Report"
    assert len(fetched.timeline) == 1
    assert fetched.affected_assets == ["HOST-A"]

    assert db.get_incident_narrative("NON-EXISTENT") is None

    action = ContainmentAction(
        action_id="ACT-P1",
        action_type=ActionType.ISOLATE_HOST,
        target_entity="HOST-A",
        rationale="Isolate immediately",
        confidence_score=0.9,
        confidence_level=ConfidenceLevel.VERY_HIGH,
        blast_radius_score=0.2,
        requires_confirmation=False,
        status=ActionStatus.PROPOSED,
        rollback_procedure="Re-enable adapter",
    )
    db.save_recommendations("INC-PERSIST-01", [action])

    recs = db.get_incident_recommendations("INC-PERSIST-01")
    assert len(recs) == 1
    assert recs[0]["action_id"] == "ACT-P1"
    assert recs[0]["status"] == "proposed"

    # Update status
    updated = db.update_action_status("ACT-P1", ActionStatus.APPROVED)
    assert updated is True

    recs_updated = db.get_incident_recommendations("INC-PERSIST-01")
    assert recs_updated[0]["status"] == "approved"
