"""Natural Language to SIEM and Sigma Query Synthesis Engine."""

import re
from typing import Any, ClassVar

import yaml

from ai_secops.models.enums import SIEMTarget
from ai_secops.models.schemas import QuerySynthesisRequest, QuerySynthesisResponse
from ai_secops.synthesizer.validators import QueryValidator


class QuerySynthesizer:
    """Translates analyst natural language queries into validated SIEM and Sigma queries."""

    # Pattern definitions for intent detection
    INTENT_PATTERNS: ClassVar[dict[str, str]] = {
        "failed_logins": (
            r"(failed|unsuccessful|brute\s*force|password\s*spray)"
            r".*(login|auth|logon)"
        ),
        "powershell_malicious": (r"(powershell|encodedcommand|-enc|downloadstring|webclient)"),
        "lateral_movement": r"(lateral\s*movement|psexec|wmi|remote\s*service|smb)",
        "privilege_escalation": (r"(privilege\s*escalation|mimikatz|lsass|whoami\s*/priv|sudo)"),
        "dns_tunneling": (r"(dns\s*tunnel|high\s*volume\s*dns|subdomain\s*burst|long\s*query)"),
        "ransomware": (r"(ransomware|vssadmin|shadowcopy|volume\s*shadow|encrypt|lockbit)"),
        "data_exfiltration": (r"(exfiltration|outbound\s*transfer|large\s*upload|data\s*leak)"),
        "port_scan": r"(port\s*scan|syn\s*flood|reconnaissance|nmap)",
    }

    def synthesize(self, request: QuerySynthesisRequest) -> QuerySynthesisResponse:
        """Synthesize natural language prompt into requested target query."""
        prompt = request.prompt.strip()
        target = request.target
        timeframe = request.timeframe
        datasource = request.data_source

        intent = self._detect_intent(prompt)
        query_str, explanation = self._generate_query(
            intent=intent,
            target=target,
            prompt=prompt,
            timeframe=timeframe,
            datasource=datasource,
        )

        validation = QueryValidator.validate(target, query_str)

        return QuerySynthesisResponse(
            target=target,
            query=query_str,
            explanation=explanation,
            validated=validation.is_valid,
            syntax_notes=validation.notes,
        )

    def _detect_intent(self, prompt: str) -> str:
        """Classify analyst intent using heuristic regex patterns."""
        lower_prompt = prompt.lower()
        for intent_name, pattern in self.INTENT_PATTERNS.items():
            if re.search(pattern, lower_prompt):
                return intent_name
        return "generic_security_search"

    def _generate_query(
        self,
        intent: str,
        target: SIEMTarget,
        prompt: str,
        timeframe: str,
        datasource: str | None,
    ) -> tuple[str, str]:
        """Generate query and rationale for the classified intent and target format."""
        if target == SIEMTarget.SPL:
            return self._generate_spl(intent, prompt, timeframe, datasource)
        if target in (SIEMTarget.ELASTICSEARCH, SIEMTarget.KQL):
            return self._generate_elastic(intent, prompt, timeframe, datasource)
        if target == SIEMTarget.SIGMA:
            return self._generate_sigma(intent, prompt, datasource)

        # Fallback
        return self._generate_spl(intent, prompt, timeframe, datasource)

    def _generate_spl(
        self, intent: str, prompt: str, timeframe: str, datasource: str | None
    ) -> tuple[str, str]:
        """Generate Splunk SPL query."""
        idx = datasource or "index=security"
        if intent == "failed_logins":
            query = (
                f'{idx} (EventCode=4625 OR action="failure") '
                f"| stats count by src_ip, user "
                f"| where count > 5 "
                f"| sort - count"
            )
            expl = (
                "Aggregates Windows EventCode 4625 and generic auth failure events "
                "by source IP and user, filtering for exceeding 5 attempts."
            )
        elif intent == "powershell_malicious":
            query = (
                f'{idx} (process_name="powershell.exe" OR process_name="pwsh.exe") '
                f'(CommandLine="*-enc*" OR CommandLine="*FromBase64String*" '
                f'OR CommandLine="*DownloadString*") '
                f"| table _time, host, user, CommandLine, parent_process_name"
            )
            expl = (
                "Filters execution of powershell processes with encoded or "
                "download cradle arguments."
            )
        elif intent == "lateral_movement":
            query = (
                f'{idx} (EventCode=7045 OR EventCode=4697 OR process_name="psexec.exe") '
                f"| stats count values(service_name) as services by host, user, src_ip"
            )
            expl = (
                "Identifies remote service installations and common lateral "
                "execution utilities like PsExec."
            )
        elif intent == "privilege_escalation":
            query = (
                f'{idx} (process_name="mimikatz.exe" OR '
                f'(TargetImage="*\\lsass.exe" GrantedAccess="0x1010") OR EventCode=4672) '
                f"| table _time, host, user, process_name, GrantedAccess"
            )
            expl = (
                "Detects LSASS process memory handles and privileged logon tokens "
                "associated with credential dumping."
            )
        elif intent == "dns_tunneling":
            query = (
                f'{idx} sourcetype="dns*" '
                f"| eval query_len=len(query) "
                f"| where query_len > 50 "
                f"| stats count, dc(query) as unique_subdomains by src_ip, domain "
                f"| where count > 100"
            )
            expl = (
                "Detects anomalous DNS queries featuring high subdomain cardinality "
                "and long query lengths indicating tunneling."
            )
        elif intent == "ransomware":
            query = (
                f'{idx} (CommandLine="*vssadmin* delete shadows*" '
                f'OR CommandLine="*wbadmin* delete catalog*" '
                f'OR process_name="vssadmin.exe") '
                f"| table _time, host, user, CommandLine"
            )
            expl = (
                "Surfaces shadow copy deletion attempts characteristic "
                "of ransomware defense evasion."
            )
        elif intent == "data_exfiltration":
            query = (
                f'{idx} sourcetype="firewall*" direction="outbound" '
                f"| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port "
                f"| where total_bytes > 104857600 "
                f"| eval mb_out=round(total_bytes/1048576, 2) | sort - total_bytes"
            )
            expl = "Calculates outbound data volume exceeding 100MB per connection pair."
        elif intent == "port_scan":
            query = (
                f'{idx} action="blocked" OR action="denied" '
                f"| stats dc(dest_port) as scanned_ports by src_ip "
                f"| where scanned_ports > 25 "
                f"| sort - scanned_ports"
            )
            expl = "Tracks unique rejected destination ports per source IP indicative of scanning."
        else:
            sanitized_terms = re.sub(r"[^\w\s]", "", prompt).split()
            term_filter = " AND ".join(sanitized_terms[:3]) if sanitized_terms else "action=*"
            query = f"{idx} ({term_filter}) | head 100"
            expl = f"Generic search matching keywords '{term_filter}' within data scope."

        return query, expl

    def _generate_elastic(
        self, intent: str, prompt: str, timeframe: str, datasource: str | None
    ) -> tuple[str, str]:
        """Generate Elasticsearch KQL query."""
        if intent == "failed_logins":
            query = 'event.category: "authentication" AND event.outcome: "failure"'
            expl = "KQL query matching ECS-compliant failed authentication events."
        elif intent == "powershell_malicious":
            query = (
                'process.name: ("powershell.exe", "pwsh.exe") AND '
                'process.command_line: ("*enc*", "*DownloadString*")'
            )
            expl = "KQL query targeting encoded or web-downloading PowerShell invocations."
        elif intent == "lateral_movement":
            query = 'event.code: (7045, 4697) OR process.name: ("psexec.exe", "wmic.exe")'
            expl = "KQL query tracking remote service creation and WMI execution."
        elif intent == "privilege_escalation":
            query = 'process.target.name: "lsass.exe" OR winlog.event_data.GrantedAccess: "0x1010"'
            expl = "KQL query detecting LSASS process access attempts."
        elif intent == "dns_tunneling":
            query = "dns.question.name: * AND dns.question.subdomain_length > 40"
            expl = "KQL query targeting excessively long DNS question names."
        elif intent == "ransomware":
            query = 'process.command_line: ("*vssadmin*delete*shadows*", "*wbadmin*delete*")'
            expl = "KQL query detecting shadow copy deletion commands."
        elif intent == "data_exfiltration":
            query = 'network.direction: "outbound" AND source.bytes > 104857600'
            expl = "KQL query identifying outbound network sessions exceeding 100MB."
        elif intent == "port_scan":
            query = 'event.action: ("network_traffic_denied", "firewall_drop")'
            expl = "KQL query querying dropped or denied network connection attempts."
        else:
            terms = [f'"{t}"' for t in re.sub(r"[^\w\s]", "", prompt).split()[:3]]
            query = " AND ".join(terms) if terms else "event.kind: event"
            expl = f"Generic KQL keyword query matching '{query}'."

        return query, expl

    def _generate_sigma(self, intent: str, prompt: str, datasource: str | None) -> tuple[str, str]:
        """Generate standard Sigma rule in YAML format."""
        rule_dict: dict[str, Any] = {
            "title": f"Detection for {intent.replace('_', ' ').title()}",
            "id": "e3a890b2-4d2a-44cb-8547-0193498cb001",
            "status": "experimental",
            "description": f"Generated SecOps rule based on analyst intent: {prompt}",
            "author": "AI SecOps Assistant",
            "date": "2026/10/14",
            "logsource": {
                "category": "process_creation" if "powershell" in intent else "authentication",
                "product": "windows",
            },
            "detection": {
                "selection": {
                    "EventID": 4625 if intent == "failed_logins" else 1,
                },
                "condition": "selection",
            },
            "falsepositives": [
                "Legitimate administrative operations",
                "Internal vulnerability scan",
            ],
            "level": "high" if intent in ("ransomware", "privilege_escalation") else "medium",
            "tags": (
                ["attack.execution", "attack.t1059"]
                if "powershell" in intent
                else ["attack.credential_access", "attack.t1110"]
            ),
        }

        if intent == "powershell_malicious":
            rule_dict["detection"]["selection"] = {
                "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
                "CommandLine|contains": ["-enc", "DownloadString", "FromBase64String"],
            }
        elif intent == "ransomware":
            rule_dict["detection"]["selection"] = {
                "Image|endswith": "\\vssadmin.exe",
                "CommandLine|contains|all": ["delete", "shadows"],
            }

        rule_yaml = yaml.dump(rule_dict, sort_keys=False)
        expl = f"Sigma rule detecting patterns for {intent} with high-fidelity logsource mappings."
        return rule_yaml, expl
