from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx
from sqlalchemy.orm import Session

from app.models.mitre import MitreTechnique


MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MITRE_TECHNIQUE_URL = "https://attack.mitre.org/techniques/{id}/"

BUNDLED_TECHNIQUES = [
    {
        "technique_id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may use PowerShell to perform commands and download executable payloads.",
        "platforms": ["Windows"],
        "data_sources": ["Command: Command Execution", "Process: Process Creation"],
        "keywords": ["powershell", "powershell.exe", "-enc", "-nop", "-w hidden", "downloadstring", "iex"],
    },
    {
        "technique_id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access credentials by dumping the memory of the LSASS process.",
        "platforms": ["Windows"],
        "data_sources": ["Process: Process Access", "Command: Command Execution"],
        "keywords": ["lsass", "comsvcs.dll", "minidump", "rundll32", "mimikatz", "lsass.dmp"],
    },
    {
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer web protocols (HTTP/HTTPS) to bypass network security controls.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Network Traffic: Network Traffic Flow"],
        "keywords": ["http", "https", "outbound", "tls", "c2", "beacon", "443"],
    },
    {
        "technique_id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails containing malicious links to gain initial access.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Application Log: Application Log"],
        "keywords": ["phish", "email", "spearphishing", "payroll", "login.php", "inbound link"],
    },
    {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and use credentials of existing valid accounts to access networks.",
        "platforms": ["Windows", "Linux", "Cloud"],
        "data_sources": ["User Account: Account Authentication"],
        "keywords": ["valid account", "sso", "login", "user authentication", "brute force"],
    },
    {
        "technique_id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to interact with remote network shares using SMB.",
        "platforms": ["Windows"],
        "data_sources": ["Network Share: Network Share Access"],
        "keywords": ["psexec", "smb", "admin$", "c$", "lateral"],
    },
    {
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["File: File Modification"],
        "keywords": ["encrypted", "ransomware", "ransom"],
    },
    {
        "technique_id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Network Traffic: Network Traffic Content"],
        "keywords": ["exfil", "dns tunneling", "data transfer"],
    },
    {
        "technique_id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for persistence.",
        "platforms": ["Windows"],
        "data_sources": ["Command: Command Execution"],
        "keywords": ["schtasks", "scheduled task"],
    },
    {
        "technique_id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses.",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["Process: Process Modification"],
        "keywords": ["process hollowing", "process injection", "remote thread"],
    },
    {
        "technique_id": "T1505.003",
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may backdoor web servers with web shells to establish persistent access.",
        "platforms": ["Windows", "Linux"],
        "data_sources": ["File: File Creation"],
        "keywords": ["webshell", "aspx", "proxyshell"],
    },
    {
        "technique_id": "T1003.003",
        "name": "OS Credential Dumping: NTDS",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access or create a copy of the Active Directory domain database.",
        "platforms": ["Windows"],
        "data_sources": ["Command: Command Execution"],
        "keywords": ["ntdsutil", "ntds.dit", "ifm"],
    },
    {
        "technique_id": "T1562.001",
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "description": "Adversaries may modify or disable security tools, including endpoint antivirus configuration and exclusions, to evade detection.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Application Log: Application Log", "Command: Command Execution"],
        "keywords": ["configuration has changed", "real-time protection", "tamper protection", "exclusion"],
    },
]


class MitreService:
    ATTACK_VERSION_FALLBACK = "bundled-offline"

    @staticmethod
    def _from_row(row: MitreTechnique) -> Dict[str, Any]:
        return {
            "technique_id": row.id,
            "name": row.name,
            "tactic": row.tactic or "",
            "description": row.description or "",
            "platforms": row.platforms or [],
            "data_sources": row.data_sources or [],
            "keywords": row.keywords or [],
            "data_version": row.data_version,
            "source_url": row.source_url,
            "retrieved_at": row.retrieved_at.isoformat() if row.retrieved_at else None,
            "is_bundled_fallback": row.is_bundled_fallback == "true",
        }

    @classmethod
    def ensure_bundled(cls, db: Session) -> int:
        created = 0
        for tech in BUNDLED_TECHNIQUES:
            existing = db.query(MitreTechnique).filter(MitreTechnique.id == tech["technique_id"]).first()
            if existing:
                continue
            db.add(
                MitreTechnique(
                    id=tech["technique_id"],
                    name=tech["name"],
                    tactic=tech["tactic"],
                    tactics=[tech["tactic"]],
                    description=tech["description"],
                    platforms=tech["platforms"],
                    data_sources=tech["data_sources"],
                    keywords=tech["keywords"],
                    source_url=MITRE_TECHNIQUE_URL.format(id=tech["technique_id"].replace(".", "/")),
                    data_version=cls.ATTACK_VERSION_FALLBACK,
                    is_bundled_fallback="true",
                )
            )
            created += 1
        if created:
            db.commit()
        return created

    @classmethod
    def get_all_techniques(cls, db: Optional[Session] = None) -> List[Dict[str, Any]]:
        if db is not None:
            cls.ensure_bundled(db)
            rows = db.query(MitreTechnique).order_by(MitreTechnique.id.asc()).all()
            if rows:
                return [cls._from_row(r) for r in rows]
        return [{**t, "data_version": cls.ATTACK_VERSION_FALLBACK, "source_url": MITRE_TECHNIQUE_URL.format(id=t["technique_id"].replace(".", "/")), "is_bundled_fallback": True} for t in BUNDLED_TECHNIQUES]

    @classmethod
    def get_technique(cls, technique_id: str, db: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        if db is not None:
            row = db.query(MitreTechnique).filter(MitreTechnique.id == technique_id.upper()).first()
            if row:
                return cls._from_row(row)
        for tech in BUNDLED_TECHNIQUES:
            if tech["technique_id"].upper() == technique_id.upper():
                return {**tech, "data_version": cls.ATTACK_VERSION_FALLBACK, "is_bundled_fallback": True}
        return None

    @classmethod
    def map_evidence_to_mitre(cls, evidence_text: str, db: Optional[Session] = None) -> List[Dict[str, Any]]:
        text_lower = (evidence_text or "").lower()
        hypotheses = []
        catalog = cls.get_all_techniques(db)
        for tech in catalog:
            keywords = tech.get("keywords") or []
            if not keywords:
                continue
            matched_keywords = [kw for kw in keywords if kw and kw.lower() in text_lower]
            if matched_keywords:
                score = min(1.0, 0.4 + 0.2 * len(matched_keywords))
                hypotheses.append({
                    "technique_id": tech["technique_id"],
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "confidence": round(score, 2),
                    "rationale": f"Observed evidence matched ATT&CK keywords [{', '.join(matched_keywords)}]. Candidate mapping pending analyst confirmation.",
                    "evidence_refs": matched_keywords,
                    "requires_analyst_validation": True,
                    "status": "candidate",
                    "data_version": tech.get("data_version"),
                    "source": tech.get("source_url"),
                    "source_url": tech.get("source_url"),
                })
        hypotheses.sort(key=lambda x: x["confidence"], reverse=True)
        return hypotheses

    @classmethod
    def sync_enterprise_attack(cls, db: Session) -> Dict[str, Any]:
        response = httpx.get(MITRE_STIX_URL, timeout=90.0, follow_redirects=True)
        response.raise_for_status()
        bundle = response.json()
        objects = bundle.get("objects") or []
        version = bundle.get("spec_version") or bundle.get("id") or "stix"
        retrieved = datetime.now(timezone.utc)
        tactic_by_id: Dict[str, str] = {}
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                short = (obj.get("x_mitre_shortname") or obj.get("name") or "").replace("-", " ").title()
                tactic_by_id[obj.get("id")] = obj.get("name") or short

        created = 0
        updated = 0
        for obj in objects:
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            ext = obj.get("external_references") or []
            attack_id = None
            for ref in ext:
                if ref.get("source_name") == "mitre-attack" and str(ref.get("external_id", "")).startswith("T"):
                    attack_id = ref.get("external_id")
                    break
            if not attack_id:
                continue
            name = obj.get("name") or attack_id
            phases = [p.get("phase_name", "").replace("-", " ").title() for p in (obj.get("kill_chain_phases") or [])]
            tactic = phases[0] if phases else None
            keywords = [name.lower()]
            aliases = obj.get("x_mitre_aliases") or []
            keywords.extend([a.lower() for a in aliases if a])
            source_url = MITRE_TECHNIQUE_URL.format(id=attack_id.replace(".", "/"))
            row = db.query(MitreTechnique).filter(MitreTechnique.id == attack_id).first()
            payload = dict(
                name=name,
                tactic=tactic,
                tactics=phases,
                description=(obj.get("description") or "")[:4000],
                platforms=obj.get("x_mitre_platforms") or [],
                data_sources=obj.get("x_mitre_data_sources") or [],
                keywords=list(dict.fromkeys(keywords))[:20],
                source_url=source_url,
                stix_id=obj.get("id"),
                data_version=str(obj.get("x_mitre_version") or version),
                retrieved_at=retrieved,
                is_bundled_fallback="false",
            )
            if row:
                for key, val in payload.items():
                    if key == "keywords" and row.keywords:
                        payload_keywords = list(dict.fromkeys((row.keywords or []) + val))[:30]
                        setattr(row, "keywords", payload_keywords)
                    else:
                        setattr(row, key, val)
                updated += 1
            else:
                db.add(MitreTechnique(id=attack_id, **payload))
                created += 1
        db.commit()
        return {
            "created": created,
            "updated": updated,
            "source_url": MITRE_STIX_URL,
            "retrieved_at": retrieved.isoformat(),
            "total": db.query(MitreTechnique).count(),
        }
