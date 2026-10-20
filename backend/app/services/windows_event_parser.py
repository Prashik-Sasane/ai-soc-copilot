"""Parse Windows Event XML exports used by public SOC replay datasets."""

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(parent: Optional[ET.Element], name: str) -> Optional[str]:
    if parent is None:
        return None
    for child in parent.iter():
        if _local_name(child.tag) == name and child.text:
            return child.text.strip()
    return None


def _windows_event_to_record(event: ET.Element) -> Optional[Dict[str, Any]]:
    system = next((node for node in event if _local_name(node.tag) == "System"), None)
    if system is None:
        return None

    system_fields = {_local_name(node.tag): node for node in system}
    event_id_text = _text(system, "EventID")
    if not event_id_text or not event_id_text.isdigit():
        return None
    event_id = int(event_id_text)
    provider_node = system_fields.get("Provider")
    provider = provider_node.attrib.get("Name", "Windows") if provider_node is not None else "Windows"
    record_node = system_fields.get("EventRecordID")
    record_id = record_node.text.strip() if record_node is not None and record_node.text else "unknown"
    time_node = system_fields.get("TimeCreated")
    timestamp = time_node.attrib.get("SystemTime") if time_node is not None else None
    computer = _text(system, "Computer") or "unknown"
    channel = _text(system, "Channel") or ""

    fields: Dict[str, str] = {}
    for node in event.iter():
        if _local_name(node.tag) == "Data" and node.text:
            key = node.attrib.get("Name") or f"Data{len(fields)}"
            fields[key] = node.text.strip()

    message = _text(event, "Message")
    provider_lower = provider.lower()
    if "sysmon" in provider_lower:
        source = "edr"
        event_type = {
            1: "process_creation",
            3: "network_connection",
            10: "process_access",
            11: "file_create",
            22: "dns_query",
        }.get(event_id)
    elif "defender" in provider_lower:
        source = "endpoint_av"
        event_type = {
            1116: "malware_detection",
            1117: "malware_action",
            5001: "defender_status",
            5007: "defender_config_change",
        }.get(event_id)
    elif "ntlm" in provider_lower or "ntlm" in channel.lower():
        source = "identity"
        # 8004 records NTLM authentication auditing; preserve it as telemetry without
        # asserting that the authentication failed or was a brute-force attempt.
        event_type = {8004: "ntlm_authentication"}.get(event_id)
    elif "powershell" in provider_lower:
        source = "edr"
        event_type = {4103: "powershell_module", 4104: "powershell_script_block"}.get(event_id)
    else:
        source = "identity"
        event_type = {4625: "failed_logon", 4688: "process_creation"}.get(event_id)
    if not event_type:
        return None

    process_name = (
        fields.get("Image") or fields.get("NewProcessName") or fields.get("ProcessName")
        or fields.get("Path") or fields.get("Application")
    )
    command_line = (
        fields.get("CommandLine") or fields.get("ProcessCommandLine")
        or fields.get("ScriptBlockText") or fields.get("Payload")
    )
    user = (
        fields.get("User") or fields.get("UserName")
        or fields.get("TargetUserName") or fields.get("SubjectUserName")
    )
    domain = fields.get("QueryName") or fields.get("DomainName")
    hashes = fields.get("Hashes") or fields.get("SHA256") or fields.get("SHA1")
    src_port = fields.get("SourcePort")
    dst_port = fields.get("DestinationPort")
    raw = {
        "channel": channel,
        "provider": provider,
        "windows_event_id": event_id,
        "record_id": record_id,
        "message": message,
        "event_data": fields,
    }
    safe_record = re.sub(r"[^A-Za-z0-9_.:-]", "_", record_id)
    return {
        "event_id": f"{computer}:{provider}:{safe_record}",
        "timestamp": timestamp,
        "source": source,
        "event_type": event_type,
        "severity": "low",
        "hostname": computer,
        "user": user,
        "process_name": process_name,
        "command_line": command_line,
        "domain": domain,
        "file_hash": hashes,
        "src_ip": fields.get("SourceIp") or fields.get("IpAddress"),
        "dst_ip": fields.get("DestinationIp"),
        "src_port": int(src_port) if src_port and src_port.isdigit() else None,
        "dst_port": int(dst_port) if dst_port and dst_port.isdigit() else None,
        "raw_data": json.dumps(raw, ensure_ascii=False),
    }


def parse_windows_event_xml(content: str) -> List[Dict[str, Any]]:
    """Parse one or more concatenated Windows Event XML records."""
    if not content.strip():
        return []
    content = re.sub(r"<\?xml[^>]*\?>", "", content, flags=re.IGNORECASE)
    try:
        if re.match(r"\s*<Events(?:\s|>)", content, flags=re.IGNORECASE):
            root = ET.fromstring(content)
        else:
            root = ET.fromstring(f"<Events>{content}</Events>")
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Windows Event XML: {exc}") from exc
    records = []
    for node in root:
        if _local_name(node.tag) != "Event":
            continue
        record = _windows_event_to_record(node)
        if record:
            records.append(record)
    return records
