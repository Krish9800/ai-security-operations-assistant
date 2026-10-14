"""Unit tests for forensic incident narrative and RCA generator."""

import pytest

from ai_secops.models.enums import AlertSource, Severity
from ai_secops.models.schemas import IOC, SecurityAlert
from ai_secops.narrative import IncidentNarrativeGenerator


def test_generate_narrative_empty_alerts_raises() -> None:
    """Test ValueError raised on empty alerts list."""
    gen = IncidentNarrativeGenerator()
    with pytest.raises(ValueError, match="At least one security alert is required"):
        gen.generate_narrative([])


def test_generate_narrative_single_alert() -> None:
    """Test narrative generation for a single alert."""
    alert = SecurityAlert(
        alert_id="ALT-001",
        title="Suspicious Macro Execution via Phishing",
        source=AlertSource.EDR,
        severity=Severity.HIGH,
        timestamp="2026-10-14T08:00:00Z",
        host="WS-HR-04",
        username="carol",
        iocs=[IOC(type="ip", value="198.51.100.99", reputation_score=0.9)],
    )

    gen = IncidentNarrativeGenerator()
    narrative = gen.generate_narrative([alert], incident_id="INC-PHISH-01")

    assert narrative.incident_id == "INC-PHISH-01"
    assert "Spearphishing" in narrative.rca.initial_vector
    assert narrative.rca.lateral_movement_observed is False
    assert "WS-HR-04" in narrative.affected_assets
    assert "carol" in narrative.affected_identities
    assert len(narrative.timeline) == 1
    assert len(narrative.executive_summary) > 20


def test_generate_narrative_multi_source_with_lateral_and_exfil() -> None:
    """Test multi-source correlation with lateral movement and data exfiltration."""
    alert1 = SecurityAlert(
        alert_id="ALT-101",
        title="SQL Injection Exploit Detected",
        source=AlertSource.WAF,
        severity=Severity.HIGH,
        timestamp="2026-10-14T08:00:00Z",
        source_ip="203.0.113.5",
        destination_ip="10.0.1.50",
    )
    alert2 = SecurityAlert(
        alert_id="ALT-102",
        title="Lateral Movement via PsExec Execution",
        source=AlertSource.EDR,
        severity=Severity.CRITICAL,
        timestamp="2026-10-14T08:15:00Z",
        host="SRV-APP-01",
        username="dbadmin",
    )
    alert3 = SecurityAlert(
        alert_id="ALT-103",
        title="Outbound Data Exfiltration Upload",
        source=AlertSource.FIREWALL,
        severity=Severity.CRITICAL,
        timestamp="2026-10-14T08:30:00Z",
        source_ip="10.0.1.50",
        destination_ip="198.51.100.200",
    )

    gen = IncidentNarrativeGenerator()
    narrative = gen.generate_narrative([alert1, alert2, alert3])

    assert narrative.rca.lateral_movement_observed is True
    assert "Public Web Application" in narrative.rca.initial_vector
    assert "exfiltration" in narrative.rca.data_impact.lower()
    assert len(narrative.timeline) == 3
    assert len(narrative.rca.evidence_chains) == 3
    assert "SRV-APP-01" in narrative.affected_assets
    assert "dbadmin" in narrative.affected_identities


def test_generate_narrative_password_spray_and_ransomware() -> None:
    """Test identity provider password spray and ransomware detection."""
    alert1 = SecurityAlert(
        alert_id="ALT-201",
        title="Password Spray Authentication Spike",
        source=AlertSource.IDENTITY_PROVIDER,
        timestamp="2026-10-14T07:00:00Z",
        username="svc_backup",
    )
    alert2 = SecurityAlert(
        alert_id="ALT-202",
        title="Ransomware Shadowcopy Deletion Alert",
        source=AlertSource.EDR,
        timestamp="2026-10-14T07:10:00Z",
        host="FILE-SRV-01",
    )

    gen = IncidentNarrativeGenerator()
    narrative = gen.generate_narrative([alert1, alert2])

    assert "Compromised Credentials" in narrative.rca.initial_vector
    assert "Weak password policy" in narrative.rca.vulnerability_or_weakness
    assert "integrity destruction" in narrative.rca.data_impact.lower()
