"""Prompt-injection defense, secret redaction, and input sanitization guardrail."""

import re
from typing import ClassVar

from ai_secops.models.schemas import GuardrailEvaluationResult


class SecOpsGuardrail:
    """Multi-layer adversarial defense guardrail for SecOps Copilot."""

    # Patterns indicating prompt hijacking and system prompt override attempts
    PROMPT_INJECTION_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (
            r"(ignore|disregard|override|forget)\s+(all\s+)?(previous|prior|above|existing)?"
            r"\s*(instructions|prompts|directions|rules|guidelines|safety|system|guardrail)",
            "System Prompt Override (Ignore Prior Instructions)",
        ),
        (
            r"(disregard|override|forget)\s+(the\s+)?(safety|system|guardrail)",
            "Safety Guideline Evasion",
        ),
        (
            r"(you\s+are\s+now|act\s+as)\s+(an?\s+unrestricted|dan|jailbreak|root|superuser)",
            "Persona Hijacking / Jailbreak Attempt",
        ),
        (
            r"(reveal|print|leak|output|dump)\s+(the\s+)?(hidden\s+|internal\s+)?"
            r"(system\s+prompt|developer\s+mode|hidden\s+rules|secret\s+key)",
            "System Prompt Extraction Attempt",
        ),
        (
            r"(\[system\s*instruction\]|<system>|```system)",
            "Delimited Indirect Role Spoofing",
        ),
        (
            r"(execute\s+command\s*:\s*rm\s+-rf|format\s+c:)",
            "Malicious OS Command Injection in Prompt",
        ),
    ]

    # Patterns matching sensitive credentials, tokens, and PII
    SECRET_REDACTION_PATTERNS: ClassVar[list[tuple[str, str, str]]] = [
        (
            r"\b(sk-[a-zA-Z0-9]{20,})\b",
            "[REDACTED_API_KEY]",
            "OpenAI API Key",
        ),
        (
            r"\b(AKIA[0-9A-Z]{16})\b",
            "[REDACTED_AWS_KEY]",
            "AWS Access Key ID",
        ),
        (
            r"\b(ghp_[a-zA-Z0-9]{36})\b",
            "[REDACTED_GITHUB_TOKEN]",
            "GitHub Personal Access Token",
        ),
        (
            r"(?i)\b(bearer\s+[a-zA-Z0-9_\-\.]{25,})\b",
            "[REDACTED_BEARER_TOKEN]",
            "Bearer Auth Token",
        ),
        (
            r"(?i)(password|secret|passwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?",
            r"\1: [REDACTED_PASSWORD]",
            "Plaintext Password",
        ),
        (
            r"\b\d{3}-\d{2}-\d{4}\b",
            "[REDACTED_SSN]",
            "US Social Security Number",
        ),
    ]

    # Forbidden shell metacharacters for tool arguments
    SHELL_METACHAR_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"[;&|`$><]")

    def inspect_prompt(self, prompt: str) -> GuardrailEvaluationResult:
        """Inspect and sanitize analyst or telemetry input for adversarial attacks."""
        if not prompt or not prompt.strip():
            return GuardrailEvaluationResult(
                is_safe=True,
                sanitized_input="",
                detected_threats=[],
                redacted_secrets=[],
                risk_score=0.0,
            )

        detected_threats: list[str] = []
        lower_prompt = prompt.lower()

        # 1. Check prompt injection patterns
        for pattern, threat_name in self.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, lower_prompt):
                detected_threats.append(threat_name)

        # 2. Check for secret / token leaks and redact them
        sanitized, redacted_secrets = self.redact_sensitive_data(prompt)

        # 3. Calculate risk score
        risk_score = 0.0
        if detected_threats:
            risk_score = min(1.0, 0.40 * len(detected_threats) + 0.30)
        elif redacted_secrets:
            risk_score = 0.15

        is_safe = len(detected_threats) == 0

        return GuardrailEvaluationResult(
            is_safe=is_safe,
            sanitized_input=sanitized,
            detected_threats=detected_threats,
            redacted_secrets=redacted_secrets,
            risk_score=round(risk_score, 2),
        )

    def redact_sensitive_data(self, text: str) -> tuple[str, list[str]]:
        """Redact API keys, passwords, and PII from prompt or log content."""
        sanitized = text
        redacted_types: list[str] = []

        for pattern, replacement, label in self.SECRET_REDACTION_PATTERNS:
            if re.search(pattern, sanitized):
                sanitized = re.sub(pattern, replacement, sanitized)
                redacted_types.append(label)

        return sanitized, redacted_types

    def sanitize_tool_input(self, param_name: str, value: str) -> str:
        """Sanitize tool argument to prevent command injection and path traversal."""
        clean = value.strip()
        if self.SHELL_METACHAR_PATTERN.search(clean):
            raise ValueError(
                f"Disallowed command execution metacharacter in parameter '{param_name}': {value}"
            )
        if ".." in clean or clean.startswith("/etc") or clean.startswith("c:\\windows\\system32"):
            raise ValueError(
                f"Path traversal or restricted system target detected in '{param_name}'"
            )
        return clean
