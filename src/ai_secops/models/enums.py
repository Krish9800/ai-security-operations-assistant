"""Enumerations for AI Security Operations Assistant."""

from enum import StrEnum


class SIEMTarget(StrEnum):
    """Supported SIEM and rule query targets."""

    SPL = "spl"
    ELASTICSEARCH = "elasticsearch"
    SIGMA = "sigma"
    KQL = "kql"


class Severity(StrEnum):
    """Normalized security severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ActionType(StrEnum):
    """Automated and assisted containment and triage actions."""

    ISOLATE_HOST = "isolate_host"
    REVOKE_SESSION = "revoke_session"
    BLOCK_IP = "block_ip"
    ROTATE_CREDENTIALS = "rotate_credentials"
    QUARANTINE_FILE = "quarantine_file"
    APPLY_WAF_RULE = "apply_waf_rule"
    ESCALATE_TIER2 = "escalate_tier2"


class ConfidenceLevel(StrEnum):
    """Calibrated confidence classifications."""

    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertSource(StrEnum):
    """Origin of raw security telemetry and alerts."""

    EDR = "edr"
    FIREWALL = "firewall"
    IDENTITY_PROVIDER = "identity_provider"
    CLOUD_TRAIL = "cloud_trail"
    WAF = "waf"
    DNS = "dns"
    HONEYPOT = "honeypot"


class AttackTactic(StrEnum):
    """MITRE ATT&CK Enterprise Tactics."""

    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class MessageRole(StrEnum):
    """Roles for SecOps copilot conversations."""

    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    SECURITY_TOOL = "security_tool"


class ActionStatus(StrEnum):
    """Status lifecycle for containment recommendations."""

    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
