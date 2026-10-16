"""Offline mock LLM provider for zero-API-key local testing and development."""

import hashlib
import time
from dataclasses import dataclass

from ai_secops.guardrails.defense import SecOpsGuardrail
from ai_secops.models.schemas import GuardrailEvaluationResult


class SecurityGuardrailException(Exception):
    """Raised when an adversarial prompt injection or sensitive leak is detected."""


@dataclass
class MockLLMResponse:
    """Simulated LLM response payload."""

    content: str
    model: str = "secops-offline-v1"
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    guardrail_result: GuardrailEvaluationResult | None = None
    refusal: bool = False


class MockSecOpsLLM:
    """Simulated offline LLM provider for SecOps automation without cloud API keys."""

    def __init__(
        self,
        enforce_guardrails: bool = True,
        simulated_latency_ms: float = 5.0,
    ) -> None:
        self.enforce_guardrails = enforce_guardrails
        self.simulated_latency_ms = simulated_latency_ms
        self.guardrail = SecOpsGuardrail()

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
    ) -> MockLLMResponse:
        """Process analyst prompt through safety guardrail and return deterministic completion."""
        start_time = time.perf_counter()

        # 1. Guardrail inspection
        guardrail_result: GuardrailEvaluationResult | None = None
        if self.enforce_guardrails:
            guardrail_result = self.guardrail.inspect_prompt(prompt)
            if not guardrail_result.is_safe:
                elapsed_ms = (time.perf_counter() - start_time) * 1000 + self.simulated_latency_ms
                return MockLLMResponse(
                    content=(
                        "Request refused: Adversarial prompt injection or security "
                        "policy violation detected ("
                        f"{', '.join(guardrail_result.detected_threats)})."
                    ),
                    prompt_tokens=len(prompt.split()),
                    completion_tokens=15,
                    total_tokens=len(prompt.split()) + 15,
                    latency_ms=round(elapsed_ms, 2),
                    guardrail_result=guardrail_result,
                    refusal=True,
                )

        # 2. Deterministic mock generation based on prompt intent
        content = self._synthesize_offline_answer(prompt)

        # 3. Compute simulated metrics
        p_tokens = len(prompt.split())
        c_tokens = len(content.split())
        elapsed_ms = (time.perf_counter() - start_time) * 1000 + self.simulated_latency_ms

        return MockLLMResponse(
            content=content,
            prompt_tokens=p_tokens,
            completion_tokens=c_tokens,
            total_tokens=p_tokens + c_tokens,
            latency_ms=round(elapsed_ms, 2),
            guardrail_result=guardrail_result,
            refusal=False,
        )

    def _synthesize_offline_answer(self, prompt: str) -> str:
        """Generate high-fidelity offline responses for security engineering tasks."""
        lower = prompt.lower()
        if "failed" in lower and "login" in lower:
            return (
                "index=security (EventCode=4625 OR action=failure) "
                "| stats count by src_ip, user | where count > 5 | sort - count"
            )
        if "powershell" in lower:
            return (
                "index=windows EventCode=4104 ScriptBlockText=*encodedcommand* "
                "| table _time, host, user, ScriptBlockText"
            )
        if "lateral" in lower:
            return (
                "index=network sourcetype=zeek:smb action=auth_success "
                "| stats dc(dst_ip) as target_count by src_ip | where target_count > 3"
            )

        # Generic hash-seeded response
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:8]
        return f"SecOps Offline Assistant Analysis [Ref: {digest}]: Verified security telemetry."
