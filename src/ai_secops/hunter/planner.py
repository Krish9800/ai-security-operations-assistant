"""Threat hunting hypothesis generator and MITRE ATT&CK playbook planner."""

import uuid
from typing import Any, ClassVar

from ai_secops.models.enums import AttackTactic, SIEMTarget
from ai_secops.models.schemas import HuntingPlaybook, ThreatHuntingHypothesis


class ThreatHuntingPlanner:
    """Plans proactive threat hunting campaigns mapped directly to MITRE ATT&CK."""

    # Curated knowledge repository of ATT&CK hunting templates
    ATTACK_TECHNIQUES_DB: ClassVar[dict[str, dict[str, Any]]] = {
        "T1059.001": {
            "technique_name": "PowerShell Scripting",
            "tactic": AttackTactic.EXECUTION,
            "statement": (
                "Adversaries may execute obfuscated, encoded, or in-memory PowerShell commands "
                "to bypass application allowlisting and deploy secondary payloads."
            ),
            "spl": (
                "index=windows (EventCode=4104 OR EventCode=1) "
                '(process_name="powershell.exe" OR process_name="pwsh.exe") '
                '(CommandLine="*-enc*" OR CommandLine="*FromBase64String*" '
                'OR CommandLine="*DownloadString*") '
                "| stats count by host, user, parent_process_name, CommandLine"
            ),
            "elastic": (
                'process.name: ("powershell.exe", "pwsh.exe") AND '
                'process.command_line: ("*enc*", "*DownloadString*", "*FromBase64*")'
            ),
            "sigma": (
                "title: Obfuscated PowerShell Execution\n"
                "logsource:\n  category: process_creation\n  product: windows\n"
                "detection:\n  selection:\n    Image|endswith: ['\\powershell.exe', '\\pwsh.exe']\n"
                "    CommandLine|contains: ['-enc', 'DownloadString']\n  condition: selection"
            ),
            "checklist": [
                "Inspect process hierarchy (e.g., winword.exe spawning powershell.exe)",
                "Decode Base64 command strings to uncover downloaded URLs or reflection modules",
                "Cross-reference user account with standard administrative privileges",
                "Inspect ScriptBlock logs (Event ID 4104) for AMSI bypass patterns",
            ],
            "false_positives": [
                "IT management scripts deployed by Microsoft Endpoint Configuration Manager",
                "Exchange or Office 365 hybrid connector administrative scripts",
            ],
            "data_sources": ["Sysmon Event ID 1", "Windows Event ID 4104", "EDR Process Telemetry"],
        },
        "T1003.001": {
            "technique_name": "LSASS Memory Credential Dumping",
            "tactic": AttackTactic.CREDENTIAL_ACCESS,
            "statement": (
                "Adversaries may attempt to dump credentials from the Local Security Authority "
                "Subsystem Service (LSASS) process memory to harvest plaintext hashes or keys."
            ),
            "spl": (
                'index=windows EventCode=10 TargetImage="*\\lsass.exe" '
                'GrantedAccess="0x1010" OR GrantedAccess="0x1FFFFF" '
                "| stats count by host, SourceImage, GrantedAccess"
            ),
            "elastic": (
                'winlog.event_id: 10 AND winlog.event_data.TargetImage: "*lsass.exe" '
                'AND winlog.event_data.GrantedAccess: ("0x1010", "0x1FFFFF")'
            ),
            "sigma": (
                "title: LSASS Process Access\n"
                "logsource:\n  category: process_access\n  product: windows\n"
                "detection:\n  selection:\n    TargetImage|endswith: '\\lsass.exe'\n"
                "    GrantedAccess: ['0x1010', '0x1FFFFF']\n  condition: selection"
            ),
            "checklist": [
                "Verify legitimacy of SourceImage initiating handle creation to lsass.exe",
                "Inspect call trace for dbgcore.dll, dbghelp.dll, or mimikatz artifacts",
                "Check for mini-dump file creation (*.dmp) in temp folders",
                "Verify if Credential Guard is active on target endpoints",
            ],
            "false_positives": [
                "Legitimate antivirus / EDR scanners querying LSASS handles",
                "Active Directory migration tools during planned domain restructuring",
            ],
            "data_sources": ["Sysmon Event ID 10", "Windows Event ID 4656", "EDR Process Access"],
        },
        "T1078": {
            "technique_name": "Valid Accounts Abuse",
            "tactic": AttackTactic.INITIAL_ACCESS,
            "statement": (
                "Adversaries may obtain and leverage legitimate credentials of existing accounts "
                "to gain initial access, maintain persistence, or bypass detection controls."
            ),
            "spl": (
                "index=security EventCode=4624 LogonType=10 "
                "| stats dc(src_ip) as ip_count, values(src_ip) as ips by user, host "
                "| where ip_count > 3"
            ),
            "elastic": (
                "event.code: 4624 AND winlog.event_data.LogonType: 10 "
                'AND NOT source.ip: ("10.*", "192.168.*")'
            ),
            "sigma": (
                "title: Remote Interactive Logon from Multiple Sources\n"
                "logsource:\n  category: authentication\n  product: windows\n"
                "detection:\n  selection:\n    EventID: 4624\n    LogonType: 10\n"
                "  condition: selection"
            ),
            "checklist": [
                "Correlate source IP geolocation with known employee locations",
                "Review concurrent session timestamps for impossible travel velocity",
                "Inspect subsequent activities initiated during the authenticated session",
                "Verify whether MFA prompt was challenged and answered",
            ],
            "false_positives": [
                "Remote employees using commercial VPN services with changing egress nodes",
                "Automated scheduled batch tasks running under service account identities",
            ],
            "data_sources": ["Windows Event ID 4624", "Okta / Azure AD Sign-in Logs", "VPN Logs"],
        },
        "T1021.002": {
            "technique_name": "SMB / Windows Admin Shares",
            "tactic": AttackTactic.LATERAL_MOVEMENT,
            "statement": (
                "Adversaries may leverage SMB service and administrative shares (C$, ADMIN$) "
                "to move laterally and transfer payloads between enterprise systems."
            ),
            "spl": (
                "index=security (EventCode=5140 OR EventCode=5145) "
                '(ShareName="*\\\\C$" OR ShareName="*\\\\ADMIN$") '
                "| stats count values(RelativeTargetName) as accessed_files by src_ip, host, user"
            ),
            "elastic": (
                "winlog.event_id: (5140, 5145) AND "
                'winlog.event_data.ShareName: ("*\\\\C$", "*\\\\ADMIN$")'
            ),
            "sigma": (
                "title: Administrative Share Access\n"
                "logsource:\n  category: file_event\n  product: windows\n"
                "detection:\n  selection:\n    EventID: [5140, 5145]\n"
                "    ShareName|contains: ['\\\\C$', '\\\\ADMIN$']\n  condition: selection"
            ),
            "checklist": [
                "Determine if accessing user is a member of Domain Admins or Local Admins",
                "Inspect created files in \\ADMIN$\\ or \\C$\\Windows\\Temp",
                "Correlate with subsequent service creation (Event ID 7045)",
                "Evaluate host network isolation state",
            ],
            "false_positives": [
                "Vulnerability scanners conducting authenticated credentialed scans",
                "Automated enterprise backup solutions traversing administrative shares",
            ],
            "data_sources": ["Windows Event ID 5140 / 5145", "Network SMB Flow Telemetry"],
        },
        "T1055": {
            "technique_name": "Process Injection",
            "tactic": AttackTactic.DEFENSE_EVASION,
            "statement": (
                "Adversaries may inject code into legitimate processes to evade defenses "
                "and hide malicious execution inside trusted address spaces."
            ),
            "spl": (
                "index=windows EventCode=8 "
                '(TargetImage="*\\explorer.exe" OR TargetImage="*\\svchost.exe") '
                "| stats count by host, SourceImage, TargetImage, StartAddress"
            ),
            "elastic": (
                "winlog.event_id: 8 AND winlog.event_data.TargetImage: "
                '("*\\\\explorer.exe", "*\\\\svchost.exe")'
            ),
            "sigma": (
                "title: Remote Thread Injection\n"
                "logsource:\n  category: create_remote_thread\n  product: windows\n"
                "detection:\n  selection:\n    EventID: 8\n"
                "    TargetImage|endswith: ['\\explorer.exe', '\\svchost.exe']\n"
                "  condition: selection"
            ),
            "checklist": [
                "Inspect SourceImage reputation and digital code signature",
                "Verify memory permissions (PAGE_EXECUTE_READWRITE) in target process",
                "Check for suspicious thread start addresses not backed by mapped DLLs",
                "Inspect network connections initiated immediately after thread creation",
            ],
            "false_positives": [
                "Third-party desktop enhancement and screen recording utilities",
                "Endpoint monitoring and DLP client hooks",
            ],
            "data_sources": ["Sysmon Event ID 8", "EDR Memory Inspection Logs"],
        },
    }

    def generate_hypothesis(self, query: str) -> ThreatHuntingHypothesis:
        """Generate a structured threat hunting hypothesis given a technique ID or topic."""
        clean = query.strip().upper()

        # Check direct technique ID match
        tech_id = clean
        if tech_id not in self.ATTACK_TECHNIQUES_DB:
            # Search by keyword or partial match
            tech_id = self._match_technique_by_keyword(query.lower())

        item = self.ATTACK_TECHNIQUES_DB[tech_id]

        queries = {
            SIEMTarget.SPL: item["spl"],
            SIEMTarget.ELASTICSEARCH: item["elastic"],
            SIEMTarget.SIGMA: item["sigma"],
        }

        return ThreatHuntingHypothesis(
            hypothesis_id=f"HYP-{uuid.uuid4().hex[:6].upper()}",
            title=f"Hunting {item['technique_name']} ({tech_id})",
            tactic=item["tactic"],
            mitre_technique_id=tech_id,
            technique_name=item["technique_name"],
            hypothesis_statement=item["statement"],
            test_queries=queries,
            inspection_checklist=item["checklist"],
            false_positive_indicators=item["false_positives"],
        )

    def generate_playbook(self, tactic_or_theme: str) -> HuntingPlaybook:
        """Construct a multi-hypothesis threat hunting playbook around a tactic or theme."""
        theme_clean = tactic_or_theme.strip().lower()
        selected_tech_ids: list[str] = []

        for tid, data in self.ATTACK_TECHNIQUES_DB.items():
            tactic_val = data["tactic"].value.lower()
            name_val = data["technique_name"].lower()
            if theme_clean in tactic_val or theme_clean in name_val or theme_clean in tid.lower():
                selected_tech_ids.append(tid)

        if not selected_tech_ids:
            # If no direct theme matches, include the primary top 3 techniques
            selected_tech_ids = ["T1059.001", "T1003.001", "T1078"]

        hypotheses = [self.generate_hypothesis(tid) for tid in selected_tech_ids]

        all_sources: set[str] = set()
        for tid in selected_tech_ids:
            all_sources.update(self.ATTACK_TECHNIQUES_DB[tid]["data_sources"])

        playbook_title = f"Threat Hunt Playbook: {tactic_or_theme.replace('-', ' ').title()}"
        objective = (
            f"Proactively uncover stealthy adversary activities aligning with '{tactic_or_theme}' "
            f"using hypothesis-driven behavioral queries and structured inspection gates."
        )

        return HuntingPlaybook(
            playbook_id=f"PB-{uuid.uuid4().hex[:6].upper()}",
            name=playbook_title,
            objective=objective,
            hypotheses=hypotheses,
            data_requirements=sorted(all_sources),
        )

    def _match_technique_by_keyword(self, keyword: str) -> str:
        """Match query string against techniques repository."""
        if "power" in keyword or "script" in keyword or "enc" in keyword:
            return "T1059.001"
        if "cred" in keyword or "lsass" in keyword or "dump" in keyword or "mimi" in keyword:
            return "T1003.001"
        if "smb" in keyword or "share" in keyword or "lateral" in keyword:
            return "T1021.002"
        if "inject" in keyword or "thread" in keyword or "memory" in keyword:
            return "T1055"
        if "account" in keyword or "logon" in keyword or "spray" in keyword:
            return "T1078"
        # Fallback to T1059.001
        return "T1059.001"
