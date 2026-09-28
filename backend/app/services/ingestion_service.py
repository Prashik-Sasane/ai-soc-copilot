import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.schemas.event import SecurityEventCreate, IngestionBatchResponse


class EventIngestionService:
    @staticmethod
    def parse_timestamp(ts_str: Any) -> datetime:
        if isinstance(ts_str, datetime):
            return ts_str
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def normalize_record(raw: Dict[str, Any], tenant_id: str = "tenant_default", is_simulated: bool = False) -> SecurityEvent:
        event_id = raw.get("event_id") or raw.get("id") or f"evt_{uuid.uuid4().hex[:12]}"
        timestamp = EventIngestionService.parse_timestamp(raw.get("timestamp") or raw.get("time") or raw.get("@timestamp"))
        source = str(raw.get("source") or raw.get("log_source") or raw.get("provider") or "syslog").lower()
        event_type = str(raw.get("event_type") or raw.get("action") or raw.get("category") or "activity").lower()
        severity = str(raw.get("severity") or raw.get("level") or "low").lower()

        # Extract common entities
        src_ip = raw.get("src_ip") or raw.get("source_ip") or raw.get("client_ip")
        dst_ip = raw.get("dst_ip") or raw.get("destination_ip") or raw.get("server_ip")
        src_port = raw.get("src_port") or raw.get("source_port")
        dst_port = raw.get("dst_port") or raw.get("destination_port")
        domain = raw.get("domain") or raw.get("query_domain") or raw.get("host")
        user = raw.get("user") or raw.get("username") or raw.get("account")
        process_name = raw.get("process_name") or raw.get("process") or raw.get("image")
        command_line = raw.get("command_line") or raw.get("cmdline") or raw.get("command")
        file_hash = raw.get("file_hash") or raw.get("hash") or raw.get("sha256") or raw.get("md5")
        hostname = raw.get("hostname") or raw.get("computer_name") or raw.get("device_name")

        raw_str = json.dumps(raw) if isinstance(raw, dict) else str(raw)

        return SecurityEvent(
            id=f"evt_db_{uuid.uuid4().hex[:12]}",
            event_id=str(event_id),
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity if severity in ["low", "medium", "high", "critical"] else "low",
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            src_port=int(src_port) if src_port and str(src_port).isdigit() else None,
            dst_port=int(dst_port) if dst_port and str(dst_port).isdigit() else None,
            domain=str(domain) if domain else None,
            user=str(user) if user else None,
            process_name=str(process_name) if process_name else None,
            command_line=str(command_line) if command_line else None,
            file_hash=str(file_hash) if file_hash else None,
            hostname=str(hostname) if hostname else None,
            raw_data=raw_str,
            metadata_json=raw if isinstance(raw, dict) else {},
            tenant_id=tenant_id,
            is_simulated="true" if is_simulated else "false"
        )

    @classmethod
    def ingest_records(
        cls, db: Session, records: List[Dict[str, Any]], tenant_id: str = "tenant_default", is_simulated: bool = False
    ) -> IngestionBatchResponse:
        accepted = 0
        rejected = 0
        errors = []
        job_id = f"job_{uuid.uuid4().hex[:10]}"

        for idx, item in enumerate(records):
            try:
                event_obj = cls.normalize_record(item, tenant_id=tenant_id, is_simulated=is_simulated)
                
                # Simple deduplication check by event_id in tenant
                existing = db.query(SecurityEvent).filter(
                    SecurityEvent.event_id == event_obj.event_id,
                    SecurityEvent.tenant_id == tenant_id
                ).first()

                if existing:
                    # Update timestamp or skip
                    rejected += 1
                    errors.append(f"Record #{idx+1}: Duplicate event_id {event_obj.event_id}")
                    continue

                db.add(event_obj)
                accepted += 1
            except Exception as e:
                rejected += 1
                errors.append(f"Record #{idx+1} parsing error: {str(e)}")

        db.commit()
        return IngestionBatchResponse(
            total_received=len(records),
            accepted_count=accepted,
            rejected_count=rejected,
            errors=errors[:10],  # Return up to top 10 error strings
            job_id=job_id
        )

    @classmethod
    def parse_file_content(cls, content_str: str, filename: str) -> List[Dict[str, Any]]:
        filename = filename.lower()
        records = []
        if filename.endswith(".jsonl") or filename.endswith(".ndjson"):
            for line in content_str.strip().splitlines():
                if line.strip():
                    records.append(json.loads(line))
        elif filename.endswith(".json"):
            parsed = json.loads(content_str)
            records = parsed if isinstance(parsed, list) else [parsed]
        elif filename.endswith(".csv"):
            csv_reader = csv.DictReader(io.StringIO(content_str))
            for row in csv_reader:
                records.append(dict(row))
        else:
            # Fallback JSON parsing
            parsed = json.loads(content_str)
            records = parsed if isinstance(parsed, list) else [parsed]
        return records
