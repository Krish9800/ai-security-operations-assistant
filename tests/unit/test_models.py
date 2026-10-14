"""Unit tests for domain models and schemas."""

import pytest
from pydantic import ValidationError

from ai_secops.models import (
    IOC,
    ActionStatus,
    ActionType,
    AlertSource,
    AttackTactic,
    ConfidenceLevel,
    ContainmentAction,
    CopilotMessage,
    CopilotSession,
    GuardrailEvaluationResult,
    HuntingPlaybook,
    IncidentNarrative,
    MessageRole,
    QuerySynthesisRequest,
    RecommendationResult,
    RootCauseAnalysis,
    SecurityAlert,
    Severity,
    SIEMTarget,
    ThreatHuntingHypothesis,
    TimelineEvent,
)


def test_ioc_creation_and_bounds() -> None:
    """Test IOC validation and reputation bounds."""
    ioc = IOC(type="ip", value="198.51.100.24", reputation_score=0.92)
    assert ioc.type == "ip"
    assert ioc.value == "198.51.100.24"
    assert ioc.reputation_score == 0.92

    with pytest.raises(ValidationError):
        IOC(type="ip", value="1.1.1.1", reputation_score=1.5)


def test_security_alert_defaults() -> None:
    """Test alert defaults and fields."""
    alert = SecurityAlert(
        alert_id="ALT-1001",
        title="Suspicious PowerShell Encoded Command",
        source=AlertSource.EDR,
        host="WS-FINANCE-01",
        username="alice",
    )
    assert alert.severity == Severity.MEDIUM
    assert alert.host == "WS-FINANCE-01"
    assert len(alert.iocs) == 0


def test_query_synthesis_request_bounds() -> None:
    """Test QuerySynthesisRequest validation."""
    req = QuerySynthesisRequest(
        prompt="Find failed logins from external IPs",
        target=SIEMTarget.SPL,
    )
    assert req.target == SIEMTarget.SPL

    with pytest.raises(ValidationError):
        QuerySynthesisRequest(prompt="no", target=SIEMTarget.SPL)


def test_containment_action_and_recommendation() -> None:
    """Test ContainmentAction creation and status."""
    action = ContainmentAction(
        action_id="ACT-01",
        action_type=ActionType.ISOLATE_HOST,
        target_entity="WS-FINANCE-01",
        rationale="Active beaconing observed to C2 infrastructure",
        confidence_score=0.95,
        confidence_level=ConfidenceLevel.VERY_HIGH,
        blast_radius_score=0.3,
        requires_confirmation=False,
        rollback_procedure="Re-enable network adapter via EDR management console",
    )
    assert action.status == ActionStatus.PROPOSED
    assert action.confidence_level == ConfidenceLevel.VERY_HIGH

    rec = RecommendationResult(
        incident_id="INC-2026-001",
        summary="Workstation compromise detected",
        severity=Severity.HIGH,
        overall_confidence=0.91,
        recommended_actions=[action],
        risk_assessment="Low blast radius; finance workstation can be isolated safely.",
    )
    assert len(rec.recommended_actions) == 1


def test_incident_narrative_schema() -> None:
    """Test full incident narrative schema composition."""
    timeline = [
        TimelineEvent(
            timestamp="2026-10-14T08:00:00Z",
            event_type="Phishing Click",
            description="User clicked malicious macro document",
            source="Email Gateway",
            mitre_technique_id="T1566.001",
        )
    ]
    rca = RootCauseAnalysis(
        initial_vector="Spearphishing Attachment",
        vulnerability_or_weakness="Macros enabled on workstation",
        lateral_movement_observed=False,
        data_impact="No data exfiltration detected",
        evidence_chains=["Email delivered", "Word document spawned powershell.exe"],
    )
    narrative = IncidentNarrative(
        incident_id="INC-42",
        title="Contained Phishing Incident",
        executive_summary="An analyst successfully contained a phishing payload.",
        technical_narrative="Payload executed via powershell.exe with -enc flag.",
        timeline=timeline,
        rca=rca,
        affected_assets=["WS-FINANCE-01"],
        affected_identities=["alice"],
        mitre_techniques=["T1566.001", "T1059.001"],
    )
    assert narrative.incident_id == "INC-42"
    assert len(narrative.timeline) == 1
    assert narrative.rca.lateral_movement_observed is False


def test_threat_hunting_playbook_schema() -> None:
    """Test ThreatHuntingHypothesis and HuntingPlaybook."""
    hypo = ThreatHuntingHypothesis(
        hypothesis_id="HYP-01",
        title="Unusual PowerShell Download Cradles",
        tactic=AttackTactic.EXECUTION,
        mitre_technique_id="T1059.001",
        technique_name="PowerShell",
        hypothesis_statement="Adversaries may use Net.WebClient download strings.",
        test_queries={SIEMTarget.SPL: "index=windows EventCode=4104 WebClient"},
        inspection_checklist=["Review parent processes", "Check destination IPs"],
        false_positive_indicators=["IT deployment scripts from SCCM"],
    )
    playbook = HuntingPlaybook(
        playbook_id="PB-01",
        name="Living off the Land Execution Hunting",
        objective="Detect unapproved script execution across endpoints",
        hypotheses=[hypo],
        data_requirements=["Sysmon Event ID 1", "Windows Event ID 4104"],
    )
    assert playbook.playbook_id == "PB-01"
    assert len(playbook.hypotheses) == 1


def test_copilot_session_and_guardrail() -> None:
    """Test Copilot session and guardrail schemas."""
    msg = CopilotMessage(
        role=MessageRole.USER,
        content="Summarize alert ALT-1001",
    )
    session = CopilotSession(
        session_id="SESS-001",
        title="Investigation of ALT-1001",
        messages=[msg],
    )
    assert len(session.messages) == 1

    guardrail = GuardrailEvaluationResult(
        is_safe=True,
        sanitized_input="Summarize alert ALT-1001",
        risk_score=0.05,
    )
    assert guardrail.is_safe is True
    assert len(guardrail.detected_threats) == 0
