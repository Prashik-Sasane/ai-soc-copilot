import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.services.mitre_service import MitreService


def _text(event: SecurityEvent) -> str:
    parts = [
        event.process_name or "",
        event.command_line or "",
        event.raw_data or "",
        event.event_type or "",
        event.domain or "",
        event.file_hash or "",
    ]
    return " ".join(parts).lower()


def _phrase(text: str, phrase: str) -> bool:
    return phrase in text


_TOKEN_PATTERNS: Dict[str, "re.Pattern[str]"] = {}


def _has(text: str, token: str) -> bool:
    """Whole-token match so short strings such as `c2` or the `-enc` switch cannot
    match inside GUIDs, base64 blobs, or identifiers like `UTF8Encoding` / `-Encoding`.
    Raw substring matching on these tokens produced false 'C2 egress' alerts on benign
    PowerShell telemetry, so ambiguous tokens must be matched on token boundaries."""
    pattern = _TOKEN_PATTERNS.get(token)
    if pattern is None:
        pattern = re.compile(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])")
        _TOKEN_PATTERNS[token] = pattern
    return pattern.search(text) is not None


def _has_any(text: str, tokens: List[str]) -> bool:
    return any(_has(text, t) for t in tokens)


def _defender_specific_signal(text: str) -> bool:
    """True when a Defender status event carries a specific, higher-severity signal.
    Used so the generic low-severity status rule does not double-report the same event."""
    return (
        _phrase(text, "configuration has changed")
        or _phrase(text, "error trying to update security intelligence")
        or (_phrase(text, "real-time protection") and _has_any(text, ["disabled", "turned off", "expired", "off"]))
    )


DETECTION_RULES: List[Dict[str, Any]] = [
    # --- Endpoint antivirus (real Microsoft Defender / AV events) ---
    {
        "id": "DET_MALWARE_DETECTED",
        "name": "Malware Detected by Endpoint AV",
        "severity": "critical",
        "source": "endpoint_av",
        "title": "Endpoint antivirus detected malware",
        "match": lambda e: (e.event_type or "") in {"malware_detection", "malware"},
    },
    {
        "id": "DET_MALWARE_ACTION",
        "name": "Endpoint AV Remediation Action",
        "severity": "high",
        "source": "endpoint_av",
        "title": "Endpoint antivirus took action on a threat",
        "match": lambda e: (e.event_type or "") == "malware_action",
    },
    {
        "id": "DET_DEFENDER_PROTECTION_OFF",
        "name": "Endpoint Protection Disabled",
        "severity": "high",
        "source": "endpoint_av",
        "title": "Endpoint protection appears disabled or tampered",
        "match": lambda e: _phrase(_text(e), "real-time protection")
        and _has_any(_text(e), ["disabled", "turned off", "expired", "off"]),
    },
    {
        "id": "DET_DEFENDER_CONFIG_CHANGE",
        "name": "Endpoint Protection Configuration Change",
        "severity": "medium",
        "source": "endpoint_av",
        "title": "Endpoint protection configuration changed",
        "match": lambda e: (e.event_type or "") == "defender_config_change"
        or _phrase(_text(e), "configuration has changed"),
    },
    {
        "id": "DET_DEFENDER_EXCLUSION",
        "name": "Windows Defender Exclusion Added",
        "severity": "high",
        "source": "edr",
        "title": "PowerShell added a Windows Defender exclusion",
        "match": lambda e: (e.event_type or "") in {"powershell_module", "powershell_script_block"}
        and (_phrase(_text(e), "add-mppreference") or _phrase(_text(e), "set-mppreference"))
        and _has_any(_text(e), ["-exclusionpath", "-exclusionprocess", "-exclusionextension"]),
    },
    {
        "id": "DET_DEFENDER_UPDATE_ERROR",
        "name": "Endpoint Protection Update Error",
        "severity": "medium",
        "source": "endpoint_av",
        "title": "Endpoint protection failed to update security intelligence",
        "match": lambda e: _phrase(_text(e), "error trying to update security intelligence"),
    },
    {
        "id": "DET_DEFENDER_STATUS",
        "name": "Endpoint Protection Status Update",
        "severity": "low",
        "source": "endpoint_av",
        "title": "Endpoint protection status update",
        "match": lambda e: (e.event_type or "") == "defender_status"
        and not _defender_specific_signal(_text(e)),
    },
    # --- Endpoint detection (EDR-style) ---
    {
        "id": "DET_POWERSHELL_ENC",
        "name": "Encoded / Obfuscated PowerShell",
        "severity": "high",
        "source": "edr",
        "title": "Encoded or obfuscated PowerShell execution",
        "match": lambda e: "powershell" in _text(e)
        and (
            _has(_text(e), "-encodedcommand")
            or _has(_text(e), "-enc")
            or _phrase(_text(e), "frombase64string")
            or _phrase(_text(e), "downloadstring")
        ),
    },
    {
        "id": "DET_LSASS_DUMP",
        "name": "LSASS Memory Dump",
        "severity": "critical",
        "source": "edr",
        "title": "Potential LSASS credential dumping",
        "match": lambda e: _has_any(_text(e), ["minidump", "comsvcs.dll", "mimikatz", "procdump", "pplblade"])
        or ((e.event_type or "") == "process_access" and _phrase(_text(e), "lsass"))
        or ((e.event_type or "") == "file_create" and _phrase(_text(e), "lsass") and _phrase(_text(e), ".dmp"))
        or (
            (e.event_type or "") in {"process_creation", "powershell_script_block"}
            and _phrase(_text(e), "lsass")
            and _has_any(_text(e), ["dump", "sekurlsa", "privilege::debug"])
        ),
    },
    {
        "id": "DET_RANSOM_ENCRYPT",
        "name": "Mass File Encryption Pattern",
        "severity": "critical",
        "source": "edr",
        "title": "Ransomware-like mass file modification",
        "match": lambda e: _phrase(_text(e), ".encrypted")
        or _phrase(_text(e), "ransomware")
        or _phrase(_text(e), "high entropy file"),
    },
    {
        "id": "DET_NTDS",
        "name": "Active Directory Database Access",
        "severity": "critical",
        "source": "edr",
        "title": "Possible NTDS.dit credential theft",
        "match": lambda e: _phrase(_text(e), "ntdsutil")
        or _phrase(_text(e), "ntds.dit")
        or _has(_text(e), "ifm"),
    },
    {
        "id": "DET_WEBSHELL",
        "name": "Webshell Upload or Execution",
        "severity": "high",
        "source": "edr",
        "title": "Possible webshell activity",
        "match": lambda e: _phrase(_text(e), "webshell")
        or _phrase(_text(e), "proxyshell")
        or _phrase(_text(e), ".aspx")
        or _phrase(_text(e), "w3wp.exe"),
    },
    {
        "id": "DET_USB_EXEC",
        "name": "Removable Media Execution",
        "severity": "medium",
        "source": "edr",
        "title": "Execution from removable media",
        "match": lambda e: _has(_text(e), "usb")
        or _phrase(_text(e), "removable")
        or _phrase(_text(e), "e:\\"),
    },
    # --- Network / firewall ---
    {
        "id": "DET_C2_EGRESS",
        "name": "Suspicious Outbound C2",
        "severity": "high",
        "source": "firewall",
        "title": "Suspicious outbound network connection",
        "match": lambda e: (e.event_type or "") in {"network_conn", "reverse_shell"}
        or _phrase(_text(e), "beacon")
        or _phrase(_text(e), "ja3")
        or _phrase(_text(e), "reverse shell")
        or _has(_text(e), "c2"),
    },
    {
        "id": "DET_DNS_TUNNEL",
        "name": "Suspicious DNS Activity",
        "severity": "high",
        "source": "dns",
        "title": "Suspicious DNS query or tunneling pattern",
        "match": lambda e: (e.event_type or "") in {"dns_query", "dns_tunnel"}
        and (
            _phrase(_text(e), "high entropy")
            or _phrase(_text(e), "tunnel")
            or _phrase(_text(e), "dga")
            or _phrase(_text(e), "txt record")
        ),
    },
    # --- Identity / email ---
    {
        "id": "DET_BRUTE_FORCE",
        "name": "Authentication Brute Force",
        "severity": "high",
        "source": "identity",
        "title": "Brute-force authentication activity",
        "match": lambda e: (e.event_type or "") == "brute_force" or _phrase(_text(e), "brute force"),
    },
    {
        "id": "DET_FAILED_LOGON",
        "name": "Failed Authentication",
        "severity": "medium",
        "source": "identity",
        "title": "Failed authentication attempt",
        "match": lambda e: (e.event_type or "") in {"failed_logon", "failed_login"},
    },
    {
        "id": "DET_LATERAL_MOVE",
        "name": "Lateral Movement",
        "severity": "high",
        "source": "identity",
        "title": "Possible lateral movement",
        "match": lambda e: (e.event_type or "") == "lateral_movement"
        or _phrase(_text(e), "psexec")
        or _phrase(_text(e), "wmiexec")
        or _phrase(_text(e), "smb lateral"),
    },
    {
        "id": "DET_PHISHING_LINK",
        "name": "Phishing Delivery",
        "severity": "medium",
        "source": "email_gateway",
        "title": "Suspicious inbound phishing link",
        "match": lambda e: _phrase(_text(e), "phish")
        or _phrase(_text(e), "spearphish")
        or _phrase(_text(e), "login.php")
        or (e.event_type or "") in {"phishing_delivery", "email"},
    },
]


class DetectionService:
    @classmethod
    def evaluate_event(cls, event: SecurityEvent) -> List[Dict[str, Any]]:
        hits = [rule for rule in DETECTION_RULES if rule["match"](event)]
        if not hits and event.severity in {"high", "critical"}:
            hits.append({
                "id": "DET_SEVERITY_THRESHOLD",
                "name": "High-severity source event",
                "severity": event.severity,
                "source": event.source,
                "title": f"High-severity {event.event_type} from {event.source}",
                "match": lambda _e: True,
            })
        return hits

    @classmethod
    def process_events(
        cls, db: Session, events: List[SecurityEvent], tenant_id: str
    ) -> List[Alert]:
        created: List[Alert] = []
        for event in events:
            for rule in cls.evaluate_event(event):
                existing = (
                    db.query(Alert)
                    .filter(
                        Alert.tenant_id == tenant_id,
                        Alert.detection_rule_id == rule["id"],
                    )
                    .all()
                )
                duplicate = False
                for alert in existing:
                    if event.id in (alert.event_ids or []):
                        duplicate = True
                        break
                if duplicate:
                    continue

                evidence_blob = " ".join(
                    filter(None, [event.command_line, event.raw_data, event.process_name, event.event_type])
                )
                mitre = MitreService.map_evidence_to_mitre(evidence_blob)
                alert = Alert(
                    id=f"alt_{uuid.uuid4().hex[:10]}",
                    title=rule["title"],
                    description=(
                        f"Detection rule `{rule['name']}` matched event `{event.event_id}` "
                        f"on asset `{event.hostname or 'unknown'}`. "
                        f"Evidence: {(event.raw_data or '')[:400]}"
                    ),
                    severity=rule["severity"],
                    status="new",
                    source=event.source or rule["source"],
                    rule_name=rule["name"],
                    detection_rule_id=rule["id"],
                    event_ids=[event.id],
                    asset_id=event.hostname,
                    affected_user=event.user,
                    mitre_candidates=[
                        {
                            "technique_id": m["technique_id"],
                            "name": m["name"],
                            "status": "candidate",
                            "confidence": m["confidence"],
                            "rationale": m["rationale"],
                            "data_version": m.get("data_version"),
                            "source": m.get("source"),
                        }
                        for m in mitre[:5]
                    ],
                    tenant_id=tenant_id,
                    is_simulated=event.is_simulated,
                    created_at=event.timestamp or datetime.now(timezone.utc),
                )
                db.add(alert)
                created.append(alert)
        db.commit()
        return created
