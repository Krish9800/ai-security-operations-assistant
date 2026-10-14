"""Pydantic schemas for the AI Security Operations Assistant."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from ai_secops.models.enums import (
    ActionStatus,
    ActionType,
    AlertSource,
    AttackTactic,
    ConfidenceLevel,
    MessageRole,
    Severity,
    SIEMTarget,
)


class IOC(BaseModel):
    """Indicator of Compromise representation."""

    type: str = Field(..., description="IOC Type e.g., ip, domain, sha256, md5, url")
    value: str = Field(..., description="Exact IOC string value")
    reputation_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Threat reputation score between 0 and 1"
    )
    context: str | None = Field(default=None, description="Optional enrichment metadata")


class SecurityAlert(BaseModel):
    """Raw or ingested multi-source security alert."""

    alert_id: str = Field(..., description="Unique alert identifier")
    title: str = Field(..., description="Descriptive alert title")
    source: AlertSource = Field(..., description="Telemetry source origin")
    severity: Severity = Field(default=Severity.MEDIUM, description="Normalized severity")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO 8601 UTC timestamp",
    )
    source_ip: str | None = Field(default=None, description="Source IP address if applicable")
    destination_ip: str | None = Field(
        default=None, description="Destination IP address if applicable"
    )
    host: str | None = Field(default=None, description="Affected host / endpoint hostname")
    username: str | None = Field(default=None, description="Associated user identity or account")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Raw event details/attributes"
    )
    iocs: list[IOC] = Field(default_factory=list, description="Extracted indicators of compromise")


class QuerySynthesisRequest(BaseModel):
    """Request payload to synthesize a SIEM / Sigma query."""

    prompt: str = Field(
        ..., min_length=3, max_length=2048, description="Natural language analyst intent"
    )
    target: SIEMTarget = Field(
        default=SIEMTarget.SPL, description="Desired SIEM / rule query target language"
    )
    timeframe: str = Field(default="last_24h", description="Default search timeframe filter")
    data_source: str | None = Field(
        default=None, description="Specific index or sourcetype constraint"
    )


class QuerySynthesisResponse(BaseModel):
    """Synthesized SIEM query response with validation metadata."""

    target: SIEMTarget = Field(..., description="Target query format")
    query: str = Field(..., description="Synthesized SIEM / Sigma query string")
    explanation: str = Field(..., description="Reasoning and structural explanation")
    validated: bool = Field(default=True, description="Syntax and safety validation status")
    syntax_notes: list[str] = Field(
        default_factory=list, description="Performance or safety hints for execution"
    )


class ContainmentAction(BaseModel):
    """Structured containment or triage recommendation."""

    action_id: str = Field(..., description="Unique action proposal ID")
    action_type: ActionType = Field(..., description="Type of automated/assisted containment")
    target_entity: str = Field(..., description="IP, hostname, username, or hash to act upon")
    rationale: str = Field(..., description="Explainable justification for recommendation")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Calibrated confidence metric")
    confidence_level: ConfidenceLevel = Field(..., description="Qualitative confidence band")
    blast_radius_score: float = Field(
        ..., ge=0.0, le=1.0, description="Estimated operational impact / disruption potential"
    )
    requires_confirmation: bool = Field(
        default=False, description="Whether blast radius enforces human-in-the-loop signoff"
    )
    status: ActionStatus = Field(
        default=ActionStatus.PROPOSED, description="Current execution state"
    )
    rollback_procedure: str = Field(..., description="Explicit rollback instructions")


class RecommendationResult(BaseModel):
    """Aggregate triage and containment response."""

    incident_id: str = Field(..., description="Associated incident ID")
    summary: str = Field(..., description="Executive triage summary")
    severity: Severity = Field(..., description="Triaged incident severity")
    overall_confidence: float = Field(..., ge=0.0, le=1.0, description="Aggregate confidence score")
    recommended_actions: list[ContainmentAction] = Field(
        default_factory=list, description="Prioritized list of containment actions"
    )
    risk_assessment: str = Field(..., description="Blast radius and business impact analysis")


class TimelineEvent(BaseModel):
    """Discrete forensic event in an incident timeline."""

    timestamp: str = Field(..., description="Event timestamp ISO string")
    event_type: str = Field(..., description="Category or event name")
    description: str = Field(..., description="Event description")
    source: str = Field(..., description="Telemetry source")
    mitre_technique_id: str | None = Field(
        default=None, description="ATT&CK technique ID e.g. T1059"
    )


class RootCauseAnalysis(BaseModel):
    """Technical root cause analysis report."""

    initial_vector: str = Field(..., description="Probable entry point or initial access vector")
    vulnerability_or_weakness: str = Field(
        ..., description="Exploited CVE or misconfiguration/credential flaw"
    )
    lateral_movement_observed: bool = Field(
        default=False, description="Whether lateral movement was detected"
    )
    data_impact: str = Field(..., description="Exfiltration or integrity impact assessment")
    evidence_chains: list[str] = Field(
        default_factory=list, description="Chain of sequential evidence facts"
    )


class IncidentNarrative(BaseModel):
    """Full forensic incident narrative output."""

    incident_id: str = Field(..., description="Unique incident identifier")
    title: str = Field(..., description="Incident report title")
    executive_summary: str = Field(..., description="C-level / executive brief")
    technical_narrative: str = Field(..., description="Detailed technical investigation findings")
    timeline: list[TimelineEvent] = Field(
        default_factory=list, description="Chronological forensic timeline"
    )
    rca: RootCauseAnalysis = Field(..., description="Root cause analysis")
    affected_assets: list[str] = Field(
        default_factory=list, description="List of hosts, servers, and networks"
    )
    affected_identities: list[str] = Field(
        default_factory=list, description="Compromised or targeted user accounts"
    )
    mitre_techniques: list[str] = Field(
        default_factory=list, description="Observed ATT&CK technique IDs"
    )


class ThreatHuntingHypothesis(BaseModel):
    """Structured threat hunting hypothesis."""

    hypothesis_id: str = Field(..., description="Unique hypothesis identifier")
    title: str = Field(..., description="Descriptive hunting hypothesis title")
    tactic: AttackTactic = Field(..., description="MITRE ATT&CK tactic")
    mitre_technique_id: str = Field(..., description="MITRE technique ID e.g. T1059.001")
    technique_name: str = Field(..., description="Human-readable ATT&CK technique name")
    hypothesis_statement: str = Field(
        ..., description="Testable threat hunting hypothesis statement"
    )
    test_queries: dict[SIEMTarget, str] = Field(
        default_factory=dict, description="Pre-constructed queries mapped to target SIEMs"
    )
    inspection_checklist: list[str] = Field(
        default_factory=list, description="Analyst verification steps"
    )
    false_positive_indicators: list[str] = Field(
        default_factory=list, description="Known benign activities matching this signature"
    )


class HuntingPlaybook(BaseModel):
    """Collection of threat hunting hypotheses and requirements."""

    playbook_id: str = Field(..., description="Playbook identifier")
    name: str = Field(..., description="Playbook name")
    objective: str = Field(..., description="Strategic hunting objective")
    hypotheses: list[ThreatHuntingHypothesis] = Field(
        default_factory=list, description="Constituent hunting hypotheses"
    )
    data_requirements: list[str] = Field(
        default_factory=list, description="Necessary log sources and event IDs"
    )


class CopilotMessage(BaseModel):
    """A single message exchanged within a copilot conversation."""

    role: MessageRole = Field(..., description="Sender role")
    content: str = Field(..., description="Text content of message")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="ISO timestamp",
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Contextual tool metadata")


class CopilotSession(BaseModel):
    """Stateful copilot conversation session."""

    session_id: str = Field(..., description="Unique session ID")
    title: str = Field(..., description="Session display title")
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
        description="Creation timestamp",
    )
    messages: list[CopilotMessage] = Field(
        default_factory=list, description="Chronological message history"
    )


class GuardrailEvaluationResult(BaseModel):
    """Result of adversarial and prompt injection inspection."""

    is_safe: bool = Field(..., description="Whether input is considered safe for processing")
    sanitized_input: str = Field(..., description="Scrubbed / sanitized prompt or input")
    detected_threats: list[str] = Field(
        default_factory=list, description="List of detected adversarial patterns"
    )
    redacted_secrets: list[str] = Field(
        default_factory=list, description="Identifiers of redacted credentials / tokens"
    )
    risk_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Evaluated adversarial risk score"
    )
