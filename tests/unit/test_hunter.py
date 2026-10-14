"""Unit tests for threat hunting hypothesis generator and planner."""

import pytest

from ai_secops.hunter import ThreatHuntingPlanner
from ai_secops.models.enums import AttackTactic, SIEMTarget


def test_generate_hypothesis_by_technique_id() -> None:
    """Test hypothesis generation directly matching technique ID."""
    planner = ThreatHuntingPlanner()
    hypo = planner.generate_hypothesis("T1059.001")

    assert hypo.mitre_technique_id == "T1059.001"
    assert hypo.tactic == AttackTactic.EXECUTION
    assert SIEMTarget.SPL in hypo.test_queries
    assert SIEMTarget.ELASTICSEARCH in hypo.test_queries
    assert SIEMTarget.SIGMA in hypo.test_queries
    assert len(hypo.inspection_checklist) >= 3
    assert len(hypo.false_positive_indicators) >= 1


@pytest.mark.parametrize(
    "keyword,expected_id",
    [
        ("powershell download cradles", "T1059.001"),
        ("credential dumping mimikatz", "T1003.001"),
        ("smb admin shares lateral movement", "T1021.002"),
        ("process injection remote thread", "T1055"),
        ("valid accounts password spray", "T1078"),
        ("completely unknown mystery topic", "T1059.001"),
    ],
)
def test_generate_hypothesis_by_keywords(keyword: str, expected_id: str) -> None:
    """Test fuzzy keyword mapping to MITRE techniques."""
    planner = ThreatHuntingPlanner()
    hypo = planner.generate_hypothesis(keyword)
    assert hypo.mitre_technique_id == expected_id


def test_generate_playbook_by_tactic() -> None:
    """Test generating full threat hunt playbook by ATT&CK tactic."""
    planner = ThreatHuntingPlanner()
    playbook = planner.generate_playbook("credential-access")

    assert "Playbook" in playbook.name
    assert len(playbook.hypotheses) >= 1
    assert any(h.mitre_technique_id == "T1003.001" for h in playbook.hypotheses)
    assert len(playbook.data_requirements) >= 1


def test_generate_playbook_fallback() -> None:
    """Test generating playbook with unrecognized theme uses curated default hypotheses."""
    planner = ThreatHuntingPlanner()
    playbook = planner.generate_playbook("unrecognized-custom-threat")

    assert len(playbook.hypotheses) == 3
    assert len(playbook.data_requirements) > 0
