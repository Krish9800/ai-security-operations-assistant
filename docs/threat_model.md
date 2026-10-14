# STRIDE Threat Model: AI Security Operations Assistant

## System Overview
The **AI Security Operations Assistant** (`ai-security-operations-assistant`) processes unstructured analyst inquiries, raw multi-source telemetry, and Indicators of Compromise (IOCs) to synthesize SIEM queries, formulate forensic incident narratives, propose containment actions, and plan MITRE ATT&CK threat hunting operations.

This threat model follows the **STRIDE** methodology to systematically evaluate risk vectors across data flows, trust boundaries, and execution environments.

---

## 1. Trust Boundaries & Data Flow Diagram

```mermaid
flowchart LR
    subgraph Untrusted External Zone
        Analyst[SOC Analyst / Attacker]
        RawTelemetry[Multi-Source Alert Stream]
    end

    subgraph Trust Boundary: Ingress & Guardrails
        Guardrail[SecOps Guardrail Engine]
        API[FastAPI Control Plane]
        CLI[Typer CLI Interface]
    end

    subgraph Trust Boundary: Core Processing
        Synthesizer[Query Synthesizer]
        Narrative[Incident Narrative / RCA Generator]
        Recommender[Triage & Containment Engine]
        Hunter[Threat Hunting Planner]
    end

    subgraph Trust Boundary: Storage & Infrastructure
        SQLiteWAL[(SQLite WAL Database)]
        SIEM[(Enterprise SIEM / Splunk / Elastic)]
    end

    Analyst -->|Prompts / Commands| Ingress
    RawTelemetry -->|JSON Alerts| Ingress
    Ingress[API / CLI] --> Guardrail
    Guardrail -->|Sanitized Inputs| Core Processing
    Core Processing --> SQLiteWAL
    Core Processing -.->|Validated Queries| SIEM
```

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing (Identity & Origin)
- **Threat Vector**: An attacker spoofs alert origins (e.g. forging high-fidelity EDR alerts) to trigger automated host containment of critical enterprise services.
- **Impact**: Operational denial of service by isolating production assets.
- **Mitigations**:
  - Strict Pydantic schema validation (`SecurityAlert`).
  - Source reputation weighting: multi-source cross-correlation requires alerts across distinct telemetry vectors before escalating severity.
  - Blast-radius policy gates: High criticality assets (Domain Controllers, core DBs) enforce manual human signoff.

### 2.2 Tampering (Data & Prompt Integrity)
- **Threat Vector**: Direct or indirect prompt injection (e.g. malicious instruction strings embedded in DNS query logs or phishing email bodies) attempting to hijack assistant logic or manipulate SIEM queries.
- **Impact**: Suppression of detections, extraction of secrets, or generation of unbounded queries that degrade SIEM performance.
- **Mitigations**:
  - `SecOpsGuardrail.inspect_prompt`: Regex heuristics and lexical pattern analysis detecting override keywords (`ignore previous instructions`, `reveal system prompt`, `you are now DAN`).
  - Query AST syntax validators for SPL, Elasticsearch, and Sigma prohibiting destructive commands (`delete`, `outputcsv`, `script`).
  - Parameter bounding and shell metacharacter rejection on tool arguments.

### 2.3 Repudiation (Audit Trail)
- **Threat Vector**: An analyst or rogue actor executes host containment or changes action recommendation states without an audit trail.
- **Impact**: Inability to attribute disruptive operations during forensic reviews.
- **Mitigations**:
  - SQLite Write-Ahead Logging (WAL) persistent query and recommendation audit tables (`query_logs`, `recommendations`, `sessions`, `messages`).
  - Immutable ISO 8601 UTC timestamps on all recorded actions and messages.

### 2.4 Information Disclosure (Data Leakage)
- **Threat Vector**: Sensitive credentials, API keys, passwords, or PII contained within ingested raw logs are echoed into LLM outputs or unencrypted session logs.
- **Impact**: Compromise of API tokens, service accounts, or confidential customer PII.
- **Mitigations**:
  - Pre-processing secret redaction in `SecOpsGuardrail.redact_sensitive_data`: automated scrubbing of OpenAI keys (`sk-...`), AWS access keys (`AKIA...`), GitHub PATs (`ghp_...`), Bearer tokens, and passwords prior to synthesis.
  - Hardened HTTP security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'`).

### 2.5 Denial of Service (Availability)
- **Threat Vector**: An attacker issues runaway wildcard queries (e.g. `*` without time bounds or index filters) or sends oversized payloads causing regex DoS or memory exhaustion.
- **Impact**: High SIEM CPU exhaustion or REST API unavailability.
- **Mitigations**:
  - SPL & KQL syntax validators flagging unbounded root wildcards with performance warnings.
  - Pydantic payload size bounding (`max_length=2048` on synthesis prompts, `max_length=4096` on chat prompts).
  - SQLite busy timeouts (`PRAGMA busy_timeout = 5000;`) and WAL concurrency mode.

### 2.6 Elevation of Privilege (Access Control)
- **Threat Vector**: The AI assistant autonomously executes containment actions against mission-critical servers without administrative verification.
- **Impact**: Loss of domain controllers, payment gateways, or Kubernetes clusters.
- **Mitigations**:
  - Blast Radius Engine: assets matching `CRITICAL_ASSET_KEYWORDS` (e.g. `dc-`, `srv-db`, `gateway`, `iam`) receive a score >= 0.90, automatically setting `requires_confirmation = True`.
  - Non-root container architecture: Container runs under UID 10001 (`secops`) with restricted filesystem permissions.

---

## 3. Summary of Controls Matrix

| Threat Category | Control Component | Primary Protection Mechanism |
| :--- | :--- | :--- |
| **Spoofing** | `ai_secops.models.schemas` | Pydantic strict model validation and entity cross-correlation |
| **Tampering** | `ai_secops.guardrails.defense` | Multilayer prompt injection scanner & shell metacharacter filter |
| **Repudiation** | `ai_secops.db.sqlite` | SQLite WAL query audit and recommendation event log |
| **Information Disclosure** | `ai_secops.guardrails.defense` | Automated regex token & password scrubber (`[REDACTED_*]`) |
| **Denial of Service** | `ai_secops.synthesizer.validators` | Unbounded wildcard and dangerous command rejection (`delete`) |
| **Elevation of Privilege** | `ai_secops.recommender.engine` | Blast-radius threshold check enforcing human signoff on critical infrastructure |
