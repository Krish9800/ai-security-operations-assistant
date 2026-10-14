"""Forensic incident narrative and Root Cause Analysis (RCA) generator."""

import uuid
from typing import ClassVar

from ai_secops.models.enums import AlertSource
from ai_secops.models.schemas import (
    IncidentNarrative,
    RootCauseAnalysis,
    SecurityAlert,
    TimelineEvent,
)


class IncidentNarrativeGenerator:
    """Correlates alerts and IOCs into executive summaries and technical root cause analyses."""

    # MITRE ATT&CK technique inference mappings
    SOURCE_TECHNIQUE_MAP: ClassVar[dict[AlertSource, tuple[str, str]]] = {
        AlertSource.EDR: ("T1059.001", "PowerShell Execution"),
        AlertSource.FIREWALL: ("T1041", "Exfiltration Over C2 Channel"),
        AlertSource.IDENTITY_PROVIDER: ("T1078", "Valid Accounts Abuse"),
        AlertSource.CLOUD_TRAIL: ("T1098", "Account Manipulation"),
        AlertSource.WAF: ("T1190", "Exploit Public-Facing Application"),
        AlertSource.DNS: ("T1071.004", "DNS Tunneling Protocol"),
        AlertSource.HONEYPOT: ("T1046", "Network Service Discovery"),
    }

    def generate_narrative(
        self, alerts: list[SecurityAlert], incident_id: str | None = None
    ) -> IncidentNarrative:
        """Transform multi-source raw alerts into a comprehensive incident narrative and RCA."""
        if not alerts:
            raise ValueError("At least one security alert is required to construct a narrative.")

        inc_id = incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"

        # 1. Sort alerts chronologically
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)

        # 2. Extract entities and timeline events
        timeline: list[TimelineEvent] = []
        affected_assets: set[str] = set()
        affected_identities: set[str] = set()
        mitre_techniques: set[str] = set()

        for alert in sorted_alerts:
            tech_id, _tech_name = self.SOURCE_TECHNIQUE_MAP.get(
                alert.source, ("T1059", "Command Execution")
            )
            mitre_techniques.add(tech_id)

            if alert.host:
                affected_assets.add(alert.host)
            if alert.source_ip:
                affected_assets.add(alert.source_ip)
            if alert.destination_ip:
                affected_assets.add(alert.destination_ip)
            if alert.username:
                affected_identities.add(alert.username)

            timeline.append(
                TimelineEvent(
                    timestamp=alert.timestamp,
                    event_type=alert.title,
                    description=(
                        f"Alert from {alert.source.value.upper()}: {alert.title} on "
                        f"{alert.host or alert.source_ip or 'unknown asset'}"
                    ),
                    source=alert.source.value,
                    mitre_technique_id=tech_id,
                )
            )

        # 3. Assess lateral movement and root cause
        has_multiple_hosts = len({a.host for a in sorted_alerts if a.host}) > 1
        has_lateral_technique = any(
            "lateral" in a.title.lower() or "psexec" in a.title.lower() or "wmi" in a.title.lower()
            for a in sorted_alerts
        )
        lateral_movement_observed = has_multiple_hosts or has_lateral_technique

        # Determine initial access vector
        first_alert = sorted_alerts[0]
        initial_vector = self._infer_initial_vector(first_alert)
        vulnerability = self._infer_vulnerability(first_alert)
        data_impact = self._infer_data_impact(sorted_alerts)

        # Construct evidence chain
        evidence_chains = [
            f"T0: Initial telemetry trigger '{first_alert.title}' via {first_alert.source.value}.",
        ]
        if lateral_movement_observed:
            evidence_chains.append(
                f"T1: Cross-asset movement detected across {len(affected_assets)} entities."
            )
        if len(sorted_alerts) > 1:
            last_alert = sorted_alerts[-1]
            evidence_chains.append(
                f"TN: Escalation terminated at '{last_alert.title}' via {last_alert.source.value}."
            )

        rca = RootCauseAnalysis(
            initial_vector=initial_vector,
            vulnerability_or_weakness=vulnerability,
            lateral_movement_observed=lateral_movement_observed,
            data_impact=data_impact,
            evidence_chains=evidence_chains,
        )

        # 4. Generate Executive Brief & Technical Narrative
        exec_summary = (
            f"Security incident {inc_id} involved {len(sorted_alerts)} correlated alerts across "
            f"{len(affected_assets)} assets and {len(affected_identities)} user identities. "
            f"Initial access was identified as {initial_vector}. "
            f"Lateral movement was {'confirmed' if lateral_movement_observed else 'not observed'}. "
            f"Data impact is evaluated as: {data_impact}. Immediate containment is recommended."
        )

        accounts_desc = (
            ", ".join(sorted(affected_identities))
            if affected_identities
            else "Service accounts / Unauthenticated"
        )
        nodes_desc = ", ".join(sorted(affected_assets)) if affected_assets else "None"

        tech_narrative = (
            f"### Technical Forensic Findings for {inc_id}\n\n"
            f"- **Telemetry Origin**: Ingested {len(sorted_alerts)} distinct events ranging from "
            f"{sorted_alerts[0].timestamp} to {sorted_alerts[-1].timestamp}.\n"
            f"- **Primary Suspect Vector**: {initial_vector} ({vulnerability}).\n"
            f"- **Observed ATT&CK Tactics**: {', '.join(sorted(mitre_techniques))}.\n"
            f"- **Lateral Movement**: {'Observed' if lateral_movement_observed else 'Negative'} "
            f"across nodes: {nodes_desc}.\n"
            f"- **Targeted Accounts**: {accounts_desc}."
        )

        title = f"Forensic Investigation: {first_alert.title} ({inc_id})"

        return IncidentNarrative(
            incident_id=inc_id,
            title=title,
            executive_summary=exec_summary,
            technical_narrative=tech_narrative,
            timeline=timeline,
            rca=rca,
            affected_assets=sorted(affected_assets),
            affected_identities=sorted(affected_identities),
            mitre_techniques=sorted(mitre_techniques),
        )

    def _infer_initial_vector(self, alert: SecurityAlert) -> str:
        """Infer probable initial access vector from alert context."""
        title_lower = alert.title.lower()
        if "phish" in title_lower or "macro" in title_lower or "attachment" in title_lower:
            return "Spearphishing or Malicious Document Delivery"
        if alert.source == AlertSource.WAF or "sql" in title_lower or "exploit" in title_lower:
            return "Public Web Application Exploitation"
        if alert.source == AlertSource.IDENTITY_PROVIDER or "spray" in title_lower:
            return "Compromised Credentials / Password Spray"
        return "Unsanitized Script or Endpoint Execution"

    def _infer_vulnerability(self, alert: SecurityAlert) -> str:
        """Infer vulnerability or configuration weakness."""
        title_lower = alert.title.lower()
        if "waf" in title_lower or alert.source == AlertSource.WAF:
            return "Inadequate input validation on public ingress"
        if "password" in title_lower or alert.source == AlertSource.IDENTITY_PROVIDER:
            return "Weak password policy or absence of Multi-Factor Authentication (MFA)"
        return "Unrestricted script interpreter execution policy"

    def _infer_data_impact(self, alerts: list[SecurityAlert]) -> str:
        """Infer potential data leakage or impact."""
        for alert in alerts:
            title_lower = alert.title.lower()
            if "exfiltration" in title_lower or "upload" in title_lower:
                return "Potential sensitive data exfiltration to unauthorized destination"
            if "ransomware" in title_lower or "shadowcopy" in title_lower:
                return "Critical data integrity destruction / extortion risk"
        return "No confirmed bulk data exfiltration or integrity corruption identified"
