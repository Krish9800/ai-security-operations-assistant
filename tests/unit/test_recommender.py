"""Unit tests for triage and containment recommendation engine."""

import pytest

from ai_secops.models.enums import (
    ActionStatus,
    ActionType,
    AlertSource,
    ConfidenceLevel,
    Severity,
)
from ai_secops.models.schemas import IOC, SecurityAlert
from ai_secops.recommender import TriageRecommender


def test_triage_empty_alerts_raises() -> None:
    """Test error when empty alert list provided."""
    rec = TriageRecommender()
    with pytest.raises(ValueError, match="Alert list cannot be empty"):
        rec.evaluate_triage([])


def test_triage_standard_workstation_containment() -> None:
    """Test containment recommendation on a standard workstation."""
    alert = SecurityAlert(
        alert_id="ALT-10",
        title="Ransomware Canary Triggered",
        source=AlertSource.EDR,
        severity=Severity.HIGH,
        host="WS-DEV-99",
        username="dev_user",
        source_ip="192.168.1.105",
        iocs=[IOC(type="ip", value="203.0.113.10", reputation_score=0.85)],
    )

    rec = TriageRecommender()
    result = rec.evaluate_triage([alert], incident_id="INC-RANSOM-01")

    assert result.incident_id == "INC-RANSOM-01"
    assert result.severity == Severity.HIGH
    assert result.overall_confidence >= 0.80

    action_types = [a.action_type for a in result.recommended_actions]
    assert ActionType.ISOLATE_HOST in action_types
    assert ActionType.REVOKE_SESSION in action_types
    assert ActionType.ROTATE_CREDENTIALS in action_types

    # Standard workstation should NOT require confirmation
    host_act = next(
        a for a in result.recommended_actions if a.action_type == ActionType.ISOLATE_HOST
    )
    assert host_act.requires_confirmation is False
    assert host_act.blast_radius_score < 0.50
    assert host_act.status == ActionStatus.PROPOSED
    assert "edr-cli" in host_act.rollback_procedure


def test_triage_critical_domain_controller_enforces_confirmation() -> None:
    """Test high blast radius on Domain Controller forces confirmation."""
    alert = SecurityAlert(
        alert_id="ALT-DC-01",
        title="DCSync Credential Dumping Attempt",
        source=AlertSource.EDR,
        severity=Severity.CRITICAL,
        host="SRV-DC-01.corp.internal",
        username="krbtgt",
        source_ip="198.51.100.77",  # external IP
    )

    rec = TriageRecommender()
    result = rec.evaluate_triage([alert])

    assert result.severity == Severity.CRITICAL

    dc_action = next(
        a for a in result.recommended_actions if a.action_type == ActionType.ISOLATE_HOST
    )
    assert dc_action.blast_radius_score >= 0.80
    assert dc_action.requires_confirmation is True
    assert "Human signoff is mandatory" in result.risk_assessment

    ip_action = next(a for a in result.recommended_actions if a.action_type == ActionType.BLOCK_IP)
    assert ip_action.target_entity == "198.51.100.77"
    assert "fw-admin" in ip_action.rollback_procedure


def test_triage_no_entities_fallback_to_tier2() -> None:
    """Test fallback to Tier 2 escalation when alerts have no host/user/external IP."""
    alert = SecurityAlert(
        alert_id="ALT-GEN-01",
        title="Unclassified Anomaly Trigger",
        source=AlertSource.DNS,
        severity=Severity.LOW,
    )

    rec = TriageRecommender()
    result = rec.evaluate_triage([alert])

    assert len(result.recommended_actions) == 1
    assert result.recommended_actions[0].action_type == ActionType.ESCALATE_TIER2


def test_confidence_level_mapping() -> None:
    """Test confidence score to enum band mappings."""
    rec = TriageRecommender()
    assert rec._to_confidence_level(0.92) == ConfidenceLevel.VERY_HIGH
    assert rec._to_confidence_level(0.75) == ConfidenceLevel.HIGH
    assert rec._to_confidence_level(0.55) == ConfidenceLevel.MEDIUM
    assert rec._to_confidence_level(0.30) == ConfidenceLevel.LOW
