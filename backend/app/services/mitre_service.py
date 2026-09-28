from typing import List, Dict, Any


MITRE_ATTACK_DB = [
    {
        "technique_id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may use PowerShell to perform commands and download executable payloads.",
        "platforms": ["Windows"],
        "data_sources": ["Command: Command Execution", "Process: Process Creation"],
        "keywords": ["powershell", "powershell.exe", "-enc", "-nop", "-w hidden", "downloadstring", "iex"]
    },
    {
        "technique_id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access credentials by dumping the memory of the LSASS process.",
        "platforms": ["Windows"],
        "data_sources": ["Process: Process Access", "Command: Command Execution"],
        "keywords": ["lsass", "comsvcs.dll", "minidump", "rundll32", "mimikatz", "lsass.dmp"]
    },
    {
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer web protocols (HTTP/HTTPS) to bypass network security controls.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Network Traffic: Network Traffic Flow", "Network Traffic: Application Log"],
        "keywords": ["http", "https", "outbound", "tls", "c2", "beacon", "443"]
    },
    {
        "technique_id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails containing malicious links to gain initial access.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Application Log: Application Log", "Network Traffic: Web Traffic"],
        "keywords": ["phish", "email", "spearphishing", "payroll", "login.php", "inbound link"]
    },
    {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may obtain and use credentials of existing valid accounts to access networks.",
        "platforms": ["Windows", "Linux", "Cloud"],
        "data_sources": ["User Account: Account Authentication"],
        "keywords": ["valid account", "sso", "login", "user authentication"]
    }
]


class MitreService:
    @staticmethod
    def get_all_techniques() -> List[Dict[str, Any]]:
        return MITRE_ATTACK_DB

    @staticmethod
    def get_technique(technique_id: str) -> Dict[str, Any]:
        for tech in MITRE_ATTACK_DB:
            if tech["technique_id"].upper() == technique_id.upper():
                return tech
        return None

    @classmethod
    def map_evidence_to_mitre(cls, evidence_text: str) -> List[Dict[str, Any]]:
        """
        Maps raw evidence string/command lines against MITRE ATT&CK techniques with candidate hypotheses,
        confidence scores, rationale, and explicit analyst validation notice.
        """
        text_lower = evidence_text.lower()
        hypotheses = []

        for tech in MITRE_ATTACK_DB:
            matched_keywords = [kw for kw in tech["keywords"] if kw in text_lower]
            if matched_keywords:
                score = min(1.0, 0.4 + 0.2 * len(matched_keywords))
                hypotheses.append({
                    "technique_id": tech["technique_id"],
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "confidence": round(score, 2),
                    "rationale": f"Observed evidence matched ATT&CK keywords [{', '.join(matched_keywords)}].",
                    "evidence_refs": matched_keywords,
                    "requires_analyst_validation": True,
                    "data_version": "v14.1"
                })

        # Sort by confidence
        hypotheses.sort(key=lambda x: x["confidence"], reverse=True)
        return hypotheses
