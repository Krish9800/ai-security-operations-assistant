"""Unit tests for query synthesizer and validators."""

import pytest

from ai_secops.models.enums import SIEMTarget
from ai_secops.models.schemas import QuerySynthesisRequest
from ai_secops.synthesizer import QuerySynthesizer, QueryValidator


def test_validator_spl_clean() -> None:
    """Test valid SPL query passing validation."""
    query = "index=security EventCode=4625 | stats count by user | where count > 5"
    res = QueryValidator.validate(SIEMTarget.SPL, query)
    assert res.is_valid is True
    assert len(res.notes) == 0


def test_validator_spl_unbalanced_quotes_and_parens() -> None:
    """Test detection of unbalanced quotes, parens, and dangerous commands."""
    query = "index=security process='powershell.exe (EventCode=1 | delete"
    res = QueryValidator.validate(SIEMTarget.SPL, query)
    assert res.is_valid is False
    assert any("quote" in n.lower() for n in res.notes)
    assert any("parentheses" in n.lower() for n in res.notes)
    assert any("disallowed" in n.lower() for n in res.notes)


def test_validator_spl_empty_and_wildcard() -> None:
    """Test empty query and wildcard index warnings in SPL."""
    empty_res = QueryValidator.validate(SIEMTarget.SPL, "   ")
    assert empty_res.is_valid is False

    wildcard_res = QueryValidator.validate(SIEMTarget.SPL, "index=* EventCode=4624")
    assert wildcard_res.is_valid is True
    assert any("Performance warning" in n for n in wildcard_res.notes)

    root_wildcard = QueryValidator.validate(SIEMTarget.SPL, "* | stats count")
    assert root_wildcard.is_valid is True
    assert any("Performance warning" in n for n in root_wildcard.notes)


def test_validator_elasticsearch_kql_and_dsl() -> None:
    """Test validation of Elasticsearch KQL and JSON DSL."""
    kql = 'process.name: "powershell.exe" AND event.action: "start"'
    res_kql = QueryValidator.validate(SIEMTarget.ELASTICSEARCH, kql)
    assert res_kql.is_valid is True

    valid_dsl = '{"query": {"match": {"process.name": "powershell.exe"}}}'
    res_dsl = QueryValidator.validate(SIEMTarget.ELASTICSEARCH, valid_dsl)
    assert res_dsl.is_valid is True

    invalid_dsl = '{"query": {"match": }}'
    res_bad = QueryValidator.validate(SIEMTarget.ELASTICSEARCH, invalid_dsl)
    assert res_bad.is_valid is False

    non_dict_dsl = '["not", "a", "dict"]'
    res_non_dict = QueryValidator.validate(SIEMTarget.ELASTICSEARCH, non_dict_dsl)
    assert res_non_dict.is_valid is False

    no_query_dsl = '{"timestamp": "2026-10-14"}'
    res_no_query = QueryValidator.validate(SIEMTarget.ELASTICSEARCH, no_query_dsl)
    assert any("should contain 'query'" in n for n in res_no_query.notes)


def test_validator_elasticsearch_kql_errors_and_wildcard() -> None:
    """Test KQL error paths and empty check."""
    empty_res = QueryValidator.validate(SIEMTarget.ELASTICSEARCH, "")
    assert empty_res.is_valid is False

    bad_parens = QueryValidator.validate(SIEMTarget.KQL, "user.name: (alice AND bob")
    assert any("parentheses" in n.lower() for n in bad_parens.notes)

    bad_quotes = QueryValidator.validate(SIEMTarget.KQL, 'user.name: "alice')
    assert any("double quotes" in n.lower() for n in bad_quotes.notes)

    wildcard = QueryValidator.validate(SIEMTarget.KQL, "*")
    assert any("Performance warning" in n for n in wildcard.notes)


def test_validator_sigma_yaml() -> None:
    """Test Sigma YAML syntax and required attributes."""
    valid_sigma = """
title: Test Rule
logsource:
  category: process_creation
detection:
  selection:
    CommandLine: "*mimikatz*"
  condition: selection
"""
    res = QueryValidator.validate(SIEMTarget.SIGMA, valid_sigma)
    assert res.is_valid is True

    empty_sigma = QueryValidator.validate(SIEMTarget.SIGMA, "")
    assert empty_sigma.is_valid is False

    non_mapping_sigma = QueryValidator.validate(SIEMTarget.SIGMA, "- item1\n- item2")
    assert non_mapping_sigma.is_valid is False

    missing_fields = """
title: Incomplete Rule
detection:
  condition: selection
"""
    res_bad = QueryValidator.validate(SIEMTarget.SIGMA, missing_fields)
    assert res_bad.is_valid is False
    assert any("logsource" in n for n in res_bad.notes)

    bad_detection_block = """
title: Bad Detection
logsource:
  category: process
detection: "not-a-dict"
"""
    res_bad_det = QueryValidator.validate(SIEMTarget.SIGMA, bad_detection_block)
    assert any("must be a mapping" in n for n in res_bad_det.notes)

    missing_cond = """
title: Missing Condition
logsource:
  category: process
detection:
  selection:
    field: value
"""
    res_bad_cond = QueryValidator.validate(SIEMTarget.SIGMA, missing_cond)
    assert any("missing 'condition'" in n for n in res_bad_cond.notes)

    invalid_yaml = "title: [broken"
    res_invalid_yaml = QueryValidator.validate(SIEMTarget.SIGMA, invalid_yaml)
    assert any("parsing error" in n.lower() for n in res_invalid_yaml.notes)


@pytest.mark.parametrize(
    "intent_phrase,target",
    [
        ("Detect brute force failed login attempts", SIEMTarget.SPL),
        ("Detect brute force failed login attempts", SIEMTarget.ELASTICSEARCH),
        ("Detect brute force failed login attempts", SIEMTarget.SIGMA),
        ("Detect powershell encoded commands and webclient download", SIEMTarget.SPL),
        ("Detect powershell encoded commands and webclient download", SIEMTarget.ELASTICSEARCH),
        ("Detect powershell encoded commands and webclient download", SIEMTarget.SIGMA),
        ("Detect lateral movement via PsExec or WMI", SIEMTarget.SPL),
        ("Detect lateral movement via PsExec or WMI", SIEMTarget.ELASTICSEARCH),
        ("Detect lateral movement via PsExec or WMI", SIEMTarget.SIGMA),
        ("Alert on privilege escalation and mimikatz lsass access", SIEMTarget.SPL),
        ("Alert on privilege escalation and mimikatz lsass access", SIEMTarget.ELASTICSEARCH),
        ("Alert on privilege escalation and mimikatz lsass access", SIEMTarget.SIGMA),
        ("Detect high volume DNS tunneling burst", SIEMTarget.SPL),
        ("Detect high volume DNS tunneling burst", SIEMTarget.ELASTICSEARCH),
        ("Detect ransomware shadow copy deletion with vssadmin", SIEMTarget.SPL),
        ("Detect ransomware shadow copy deletion with vssadmin", SIEMTarget.ELASTICSEARCH),
        ("Detect ransomware shadow copy deletion with vssadmin", SIEMTarget.SIGMA),
        ("Find large outbound data exfiltration transfers", SIEMTarget.SPL),
        ("Find large outbound data exfiltration transfers", SIEMTarget.ELASTICSEARCH),
        ("Detect port scan and syn flood attempts", SIEMTarget.SPL),
        ("Detect port scan and syn flood attempts", SIEMTarget.ELASTICSEARCH),
        ("Search for arbitrary unknown activity", SIEMTarget.SPL),
        ("Search for arbitrary unknown activity", SIEMTarget.ELASTICSEARCH),
        ("Search for arbitrary unknown activity", SIEMTarget.SIGMA),
    ],
)
def test_all_synthesizer_permutations(intent_phrase: str, target: SIEMTarget) -> None:
    """Test synthesis across all defined security intent domains and targets."""
    synthesizer = QuerySynthesizer()
    req = QuerySynthesisRequest(prompt=intent_phrase, target=target, data_source="index=main")
    resp = synthesizer.synthesize(req)
    assert resp.target == target
    assert len(resp.query) > 0
    assert resp.validated is True
