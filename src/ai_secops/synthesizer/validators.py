"""Syntax and security validation for SIEM queries and Sigma rules."""

import json
from typing import ClassVar, NamedTuple

import yaml

from ai_secops.models.enums import SIEMTarget


class ValidationResult(NamedTuple):
    """Result of query syntax and safety validation."""

    is_valid: bool
    notes: list[str]


class QueryValidator:
    """Security and syntax validator for SPL, Elasticsearch, KQL, and Sigma."""

    # Disallowed destructive commands in SPL
    DISALLOWED_SPL_COMMANDS: ClassVar[set[str]] = {"delete", "outputcsv", "runcmd", "script"}

    @classmethod
    def validate_spl(cls, query: str) -> ValidationResult:
        """Validate Splunk Search Processing Language query."""
        notes: list[str] = []
        clean = query.strip()
        if not clean:
            return ValidationResult(is_valid=False, notes=["Query string is empty"])

        # Check balanced quotes
        single_quotes = clean.count("'")
        double_quotes = clean.count('"')
        if single_quotes % 2 != 0:
            notes.append("Unbalanced single quotes in SPL query")
        if double_quotes % 2 != 0:
            notes.append("Unbalanced double quotes in SPL query")

        # Check balanced parentheses
        if clean.count("(") != clean.count(")"):
            notes.append("Unbalanced parentheses in SPL query")

        # Check for disallowed commands (pipeline commands following pipe or starting query)
        pipe_segments = clean.split("|")
        for idx, segment in enumerate(pipe_segments):
            tokens = segment.strip().split()
            if not tokens:
                continue
            first_cmd = tokens[0].lower()
            if idx > 0 and first_cmd in cls.DISALLOWED_SPL_COMMANDS:
                notes.append(f"Disallowed or dangerous SPL command detected: '{first_cmd}'")
            elif idx == 0 and first_cmd in cls.DISALLOWED_SPL_COMMANDS:
                notes.append(f"Disallowed or dangerous SPL command detected: '{first_cmd}'")

        # Warning for unindexed wildcard root search
        if clean.startswith("*") or "index=*" in clean:
            notes.append("Performance warning: unbounded wildcard index scan")

        is_valid = len(notes) == 0 or (len(notes) == 1 and "Performance warning" in notes[0])
        return ValidationResult(is_valid=is_valid, notes=notes)

    @classmethod
    def validate_elasticsearch(cls, query: str) -> ValidationResult:
        """Validate Elasticsearch DSL or KQL query."""
        notes: list[str] = []
        clean = query.strip()
        if not clean:
            return ValidationResult(is_valid=False, notes=["Query string is empty"])

        # If it looks like JSON DSL
        if (clean.startswith("{") and clean.endswith("}")) or (
            clean.startswith("[") and clean.endswith("]")
        ):
            try:
                parsed = json.loads(clean)
                if not isinstance(parsed, dict):
                    notes.append("Elasticsearch DSL root must be a JSON object")
                elif "query" not in parsed and "aggs" not in parsed:
                    notes.append("Elasticsearch DSL should contain 'query' or 'aggs' root key")
            except json.JSONDecodeError as exc:
                notes.append(f"Invalid JSON syntax in Elasticsearch DSL: {exc.msg}")
        else:
            # KQL syntax checks
            if clean.count("(") != clean.count(")"):
                notes.append("Unbalanced parentheses in KQL query")
            if clean.count('"') % 2 != 0:
                notes.append("Unbalanced double quotes in KQL query")
            if clean == "*":
                notes.append("Performance warning: matches all documents without constraint")

        is_valid = len(notes) == 0 or all("Performance warning" in n for n in notes)
        return ValidationResult(is_valid=is_valid, notes=notes)

    @classmethod
    def validate_sigma(cls, rule_yaml: str) -> ValidationResult:
        """Validate Sigma rule YAML structure against core specification."""
        notes: list[str] = []
        clean = rule_yaml.strip()
        if not clean:
            return ValidationResult(is_valid=False, notes=["Sigma rule is empty"])

        try:
            doc = yaml.safe_load(clean)
            if not isinstance(doc, dict):
                return ValidationResult(
                    is_valid=False, notes=["Sigma rule must be a YAML dictionary"]
                )

            required_keys = ["title", "logsource", "detection"]
            for req in required_keys:
                if req not in doc:
                    notes.append(f"Missing mandatory Sigma field: '{req}'")

            detection = doc.get("detection")
            if isinstance(detection, dict):
                if "condition" not in detection:
                    notes.append("Sigma detection block missing 'condition' expression")
            else:
                notes.append("Sigma 'detection' block must be a mapping")

        except yaml.YAMLError as exc:
            notes.append(f"YAML parsing error in Sigma rule: {exc}")

        is_valid = len(notes) == 0
        return ValidationResult(is_valid=is_valid, notes=notes)

    @classmethod
    def validate(cls, target: SIEMTarget, query: str) -> ValidationResult:
        """Dispatch query validation according to the target dialect."""
        if target == SIEMTarget.SPL:
            return cls.validate_spl(query)
        if target in (SIEMTarget.ELASTICSEARCH, SIEMTarget.KQL):
            return cls.validate_elasticsearch(query)
        if target == SIEMTarget.SIGMA:
            return cls.validate_sigma(query)
        return ValidationResult(is_valid=False, notes=[f"Unsupported target: {target}"])
