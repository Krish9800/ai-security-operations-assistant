"""Confidence-calibrated triage and containment recommendation engine."""

import uuid
from typing import ClassVar

from ai_secops.config.settings import get_settings
from ai_secops.models.enums import (
    ActionStatus,
    ActionType,
    AlertSource,
    ConfidenceLevel,
    Severity,
)
from ai_secops.models.schemas import (
    ContainmentAction,
    RecommendationResult,
    SecurityAlert,
)


class TriageRecommender:
    """Evaluates security alerts to propose confidence-calibrated containment recommendations."""

    # High criticality asset keywords enforcing blast radius caution
    CRITICAL_ASSET_KEYWORDS: ClassVar[set[str]] = {
        "dc-",
        "domain-controller",
        "srv-dc",
        "ad-",
        "srv-db",
        "core-db",
        "sql",
        "prod-k8s",
        "gateway",
        "iam",
    }

    def __init__(self) -> None:
        self.settings = get_settings()

    def evaluate_triage(
        self, alerts: list[SecurityAlert], incident_id: str | None = None
    ) -> RecommendationResult:
        """Analyze alerts and produce prioritized, calibrated containment actions."""
        if not alerts:
            raise ValueError("Alert list cannot be empty for triage evaluation.")

        inc_id = incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"

        # 1. Determine aggregate severity and confidence
        severity = self._compute_aggregate_severity(alerts)
        overall_confidence = self._compute_confidence(alerts)

        # 2. Generate actions
        actions: list[ContainmentAction] = []
        targeted_hosts = {a.host for a in alerts if a.host}
        targeted_users = {a.username for a in alerts if a.username}
        external_ips = {
            a.source_ip for a in alerts if a.source_ip and not self._is_private_ip(a.source_ip)
        }

        # Evaluate host containment
        for host in sorted(targeted_hosts):
            blast_radius = self._calculate_blast_radius(host)
            requires_conf = (
                blast_radius >= self.settings.blast_radius_threshold
                if self.settings.high_criticality_confirmation_required
                else False
            )
            actions.append(
                ContainmentAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type=ActionType.ISOLATE_HOST,
                    target_entity=host,
                    rationale=(
                        f"Active malicious indicators detected on host '{host}'. "
                        f"Immediate network isolation prevents lateral spreading."
                    ),
                    confidence_score=round(overall_confidence, 2),
                    confidence_level=self._to_confidence_level(overall_confidence),
                    blast_radius_score=blast_radius,
                    requires_confirmation=requires_conf,
                    status=ActionStatus.PROPOSED,
                    rollback_procedure=(
                        f"Execute endpoint agent un-quarantine command: "
                        f"`edr-cli isolate --remove --host {host}`"
                    ),
                )
            )

        # Evaluate user session revocation and credential rotation
        for user in sorted(targeted_users):
            actions.append(
                ContainmentAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type=ActionType.REVOKE_SESSION,
                    target_entity=user,
                    rationale=(
                        f"Suspected credential abuse detected for user '{user}'. "
                        f"Revoking all active tokens, OIDC grants, and Kerberos TGTs."
                    ),
                    confidence_score=round(overall_confidence, 2),
                    confidence_level=self._to_confidence_level(overall_confidence),
                    blast_radius_score=0.25,
                    requires_confirmation=False,
                    status=ActionStatus.PROPOSED,
                    rollback_procedure=(
                        f"Reactivate user session via IdP admin API or "
                        f"`idp-cli session unfreeze --user {user}`"
                    ),
                )
            )
            # If severity is critical/high, also recommend credential rotation
            if severity in (Severity.CRITICAL, Severity.HIGH):
                actions.append(
                    ContainmentAction(
                        action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                        action_type=ActionType.ROTATE_CREDENTIALS,
                        target_entity=user,
                        rationale=(
                            f"High likelihood of compromised credentials for '{user}'. "
                            f"Forcing password reset and MFA re-enrollment."
                        ),
                        confidence_score=round(min(1.0, overall_confidence + 0.05), 2),
                        confidence_level=self._to_confidence_level(overall_confidence),
                        blast_radius_score=0.20,
                        requires_confirmation=False,
                        status=ActionStatus.PROPOSED,
                        rollback_procedure=(
                            f"Issue temporary recovery bypass token or "
                            f"contact helpdesk for '{user}'"
                        ),
                    )
                )

        # Evaluate IP blocking on perimeter
        for ip in sorted(external_ips):
            actions.append(
                ContainmentAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type=ActionType.BLOCK_IP,
                    target_entity=ip,
                    rationale=(
                        f"Inbound/C2 communication identified from external IP '{ip}'. "
                        f"Block traffic across perimeter firewall ingress/egress."
                    ),
                    confidence_score=round(overall_confidence, 2),
                    confidence_level=self._to_confidence_level(overall_confidence),
                    blast_radius_score=0.15,
                    requires_confirmation=False,
                    status=ActionStatus.PROPOSED,
                    rollback_procedure=(
                        f"Remove firewall drop rule via CLI: "
                        f"`fw-admin rule delete --source-ip {ip}`"
                    ),
                )
            )

        # If no targeted entities found, recommend Tier 2 escalation
        if not actions:
            actions.append(
                ContainmentAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type=ActionType.ESCALATE_TIER2,
                    target_entity=inc_id,
                    rationale=(
                        "Insufficient entity specifics to automate isolation safely. "
                        "Escalating to Tier 2 SOC analyst for deep dive."
                    ),
                    confidence_score=round(overall_confidence, 2),
                    confidence_level=self._to_confidence_level(overall_confidence),
                    blast_radius_score=0.05,
                    requires_confirmation=False,
                    status=ActionStatus.PROPOSED,
                    rollback_procedure="Reassign ticket back to Tier 1 queue",
                )
            )

        summary = (
            f"Triage assessment for {inc_id} completed with severity {severity.value.upper()}. "
            f"Generated {len(actions)} containment action(s) with calibrated confidence "
            f"{overall_confidence:.2f}."
        )

        max_blast = max(a.blast_radius_score for a in actions)
        blast_status = "HIGH" if max_blast >= self.settings.blast_radius_threshold else "CONTROLLED"
        has_approval_gate = any(a.requires_confirmation for a in actions)
        gate_text = (
            "Human signoff is mandatory before executing containment on critical nodes."
            if has_approval_gate
            else "Containment actions can proceed autonomously."
        )
        risk_assessment = (
            f"Operational Blast Radius: {blast_status} (Peak score: {max_blast:.2f}). {gate_text}"
        )

        return RecommendationResult(
            incident_id=inc_id,
            summary=summary,
            severity=severity,
            overall_confidence=round(overall_confidence, 2),
            recommended_actions=actions,
            risk_assessment=risk_assessment,
        )

    def _compute_aggregate_severity(self, alerts: list[SecurityAlert]) -> Severity:
        """Return the highest severity among input alerts."""
        severities = [a.severity for a in alerts]
        if Severity.CRITICAL in severities:
            return Severity.CRITICAL
        if Severity.HIGH in severities:
            return Severity.HIGH
        if Severity.MEDIUM in severities:
            return Severity.MEDIUM
        if Severity.LOW in severities:
            return Severity.LOW
        return Severity.INFORMATIONAL

    def _compute_confidence(self, alerts: list[SecurityAlert]) -> float:
        """Calculate normalized confidence score based on multi-source telemetry and IOCs."""
        base_scores = {
            AlertSource.EDR: 0.85,
            AlertSource.FIREWALL: 0.75,
            AlertSource.IDENTITY_PROVIDER: 0.80,
            AlertSource.WAF: 0.70,
            AlertSource.CLOUD_TRAIL: 0.75,
            AlertSource.DNS: 0.65,
            AlertSource.HONEYPOT: 0.90,
        }

        # Average base score
        avg_base = sum(base_scores.get(a.source, 0.70) for a in alerts) / len(alerts)

        # IOC reputation boost
        all_iocs = [ioc for a in alerts for ioc in a.iocs]
        ioc_boost = 0.0
        if all_iocs:
            avg_rep = sum(i.reputation_score for i in all_iocs) / len(all_iocs)
            ioc_boost = avg_rep * 0.15

        # Volume correlation boost
        volume_boost = min(0.10, len(alerts) * 0.02)

        return min(0.99, max(0.20, avg_base + ioc_boost + volume_boost))

    def _calculate_blast_radius(self, asset: str) -> float:
        """Compute disruption / blast radius score for a given asset."""
        lower_asset = asset.lower()
        for kw in self.CRITICAL_ASSET_KEYWORDS:
            if kw in lower_asset:
                return 0.90
        return 0.30

    def _to_confidence_level(self, score: float) -> ConfidenceLevel:
        """Map numerical confidence score to qualitative enum band."""
        if score >= 0.85:
            return ConfidenceLevel.VERY_HIGH
        if score >= 0.70:
            return ConfidenceLevel.HIGH
        if score >= 0.50:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IPv4 string belongs to RFC 1918 private space."""
        clean = ip.strip()
        return (
            clean.startswith("10.")
            or clean.startswith("192.168.")
            or (
                clean.startswith("172.") and 16 <= int(clean.split(".")[1]) <= 31
                if len(clean.split(".")) > 1 and clean.split(".")[1].isdigit()
                else False
            )
            or clean.startswith("127.")
        )
