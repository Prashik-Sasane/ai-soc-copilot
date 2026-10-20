import csv
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.models.event import SecurityEvent
from app.models.ingest import IngestParseError, IngestSource
from app.schemas.event import IngestionBatchResponse
from app.services.detection_service import DetectionService
from app.services.correlation_engine import CorrelationEngine


class EventIngestionService:
    @staticmethod
    def parse_timestamp(ts_str: Any) -> Tuple[Optional[datetime], Optional[str]]:
        if isinstance(ts_str, datetime):
            ts = ts_str
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts, None
        if not ts_str:
            return None, "missing_timestamp"
        raw = str(ts_str).strip()
        for candidate in (raw, raw.replace("Z", "+00:00"), raw.replace(" ", "T")):
            try:
                ts = datetime.fromisoformat(candidate)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                return ts, None
            except ValueError:
                continue
        try:
            ts = datetime.fromtimestamp(float(raw), tz=timezone.utc)
            return ts, None
        except (ValueError, OSError, OverflowError):
            return None, "unparseable_timestamp"

    @staticmethod
    def validate_timestamp(ts: datetime) -> Optional[str]:
        now = datetime.now(timezone.utc)
        if ts - now > timedelta(hours=settings.MAX_EVENT_FUTURE_HOURS):
            return "timestamp_too_far_in_future"
        if now - ts > timedelta(days=settings.MAX_EVENT_AGE_DAYS):
            return "timestamp_too_old"
        return None

    @staticmethod
    def _first(raw: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in raw and raw[key] not in (None, ""):
                return raw[key]
            # nested Elastic-style
            if "." in key:
                cur: Any = raw
                ok = True
                for part in key.split("."):
                    if isinstance(cur, dict) and part in cur:
                        cur = cur[part]
                    else:
                        ok = False
                        break
                if ok and cur not in (None, ""):
                    return cur
        return None

    @classmethod
    def flatten_vendor_fields(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Map common SIEM/EDR field names onto the internal event schema without claiming a vendor poller."""
        flattened = dict(raw)
        src_ip = cls._first(raw, "src_ip", "source_ip", "client_ip", "src", "source.ip", "src_ip_addr", "SourceAddress")
        dst_ip = cls._first(raw, "dst_ip", "destination_ip", "server_ip", "dst", "destination.ip", "DestinationAddress")
        if src_ip:
            flattened["src_ip"] = src_ip
        if dst_ip:
            flattened["dst_ip"] = dst_ip
        flattened["src_port"] = cls._first(raw, "src_port", "source_port", "source.port", "SourcePort")
        flattened["dst_port"] = cls._first(raw, "dst_port", "destination_port", "destination.port", "DestinationPort")
        flattened["domain"] = cls._first(raw, "domain", "query_domain", "dns.question.name", "query", "url.domain")
        flattened["user"] = cls._first(raw, "user", "username", "account", "user.name", "User")
        flattened["process_name"] = cls._first(raw, "process_name", "process", "image", "process.name", "Image")
        flattened["command_line"] = cls._first(raw, "command_line", "cmdline", "command", "process.command_line", "CommandLine")
        flattened["file_hash"] = cls._first(raw, "file_hash", "hash", "sha256", "md5", "file.hash.sha256")
        flattened["hostname"] = cls._first(raw, "hostname", "computer_name", "device_name", "host.name", "host", "Computer")
        flattened["event_type"] = cls._first(raw, "event_type", "action", "category", "event.action", "EventID")
        flattened["source"] = cls._first(raw, "source", "log_source", "provider", "event.module", "Vendor")
        flattened["severity"] = cls._first(raw, "severity", "level", "event.severity")
        flattened["event_id"] = cls._first(raw, "event_id", "id", "event.id", "_id")
        flattened["timestamp"] = cls._first(raw, "timestamp", "time", "@timestamp", "TimeGenerated", "event_time")
        return flattened

    @classmethod
    def compute_event_id(cls, raw: Dict[str, Any], timestamp: datetime) -> str:
        provided = raw.get("event_id") or raw.get("id")
        if provided:
            return str(provided)
        basis = json.dumps(
            {
                "ts": timestamp.isoformat(),
                "source": raw.get("source"),
                "type": raw.get("event_type"),
                "host": raw.get("hostname"),
                "user": raw.get("user"),
                "cmd": raw.get("command_line"),
                "raw": raw.get("raw_data") or raw,
            },
            sort_keys=True,
            default=str,
        )
        return "evt_" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def normalize_record(
        cls,
        raw: Dict[str, Any],
        tenant_id: str = "tenant_default",
        is_simulated: bool = False,
        ingest_source_id: Optional[str] = None,
    ) -> Tuple[SecurityEvent, List[str]]:
        warnings: List[str] = []
        mapped = cls.flatten_vendor_fields(raw if isinstance(raw, dict) else {})
        timestamp, ts_warn = cls.parse_timestamp(mapped.get("timestamp"))
        if ts_warn:
            warnings.append(ts_warn)
            timestamp = datetime.now(timezone.utc)
        else:
            ts_invalid = cls.validate_timestamp(timestamp)  # type: ignore[arg-type]
            # Public incident/replay datasets can be historical. Keep future-time
            # protection, but do not reject old records explicitly marked simulated.
            if is_simulated and ts_invalid == "timestamp_too_old":
                ts_invalid = None
            if ts_invalid:
                raise ValueError(ts_invalid)

        source = str(mapped.get("source") or "syslog").lower()
        event_type = str(mapped.get("event_type") or "activity").lower()
        severity = str(mapped.get("severity") or "low").lower()
        if severity not in {"low", "medium", "high", "critical"}:
            warnings.append("severity_normalized")
            severity = "low"

        event_id = cls.compute_event_id(mapped, timestamp)
        src_ip = mapped.get("src_ip")
        dst_ip = mapped.get("dst_ip")
        src_port = mapped.get("src_port")
        dst_port = mapped.get("dst_port")
        raw_str = json.dumps(raw) if isinstance(raw, dict) else str(raw)
        idempotency_key = hashlib.sha256(f"{tenant_id}:{event_id}".encode("utf-8")).hexdigest()

        event = SecurityEvent(
            id=f"evt_db_{uuid.uuid4().hex[:12]}",
            event_id=str(event_id),
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity,
            ingest_source_id=ingest_source_id,
            idempotency_key=idempotency_key,
            parse_warnings=warnings,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            src_port=int(src_port) if src_port is not None and str(src_port).isdigit() else None,
            dst_port=int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None,
            domain=str(mapped.get("domain")) if mapped.get("domain") else None,
            user=str(mapped.get("user")) if mapped.get("user") else None,
            process_name=str(mapped.get("process_name")) if mapped.get("process_name") else None,
            command_line=str(mapped.get("command_line")) if mapped.get("command_line") else None,
            file_hash=str(mapped.get("file_hash")) if mapped.get("file_hash") else None,
            hostname=str(mapped.get("hostname")) if mapped.get("hostname") else None,
            raw_data=raw_str,
            metadata_json={
                **(mapped if isinstance(mapped, dict) else {}),
                "ingest_source_id": ingest_source_id,
                "is_simulated": is_simulated,
            },
            tenant_id=tenant_id,
            is_simulated="true" if is_simulated else "false",
        )
        return event, warnings

    @classmethod
    def _touch_source(
        cls,
        db: Session,
        *,
        tenant_id: str,
        source_id: str,
        accepted: int,
        rejected: int,
        error: Optional[str] = None,
        connector_type: str = "webhook",
    ) -> None:
        rec = (
            db.query(IngestSource)
            .filter(IngestSource.tenant_id == tenant_id, IngestSource.source_id == source_id)
            .first()
        )
        now = datetime.now(timezone.utc)
        if not rec:
            rec = IngestSource(
                id=f"src_{uuid.uuid4().hex[:10]}",
                source_id=source_id,
                display_name=source_id,
                connector_type=connector_type,
                status="connected" if accepted else ("error" if error else "waiting"),
                tenant_id=tenant_id,
                events_accepted=0,
                events_rejected=0,
            )
            db.add(rec)
        rec.events_accepted = (rec.events_accepted or 0) + accepted
        rec.events_rejected = (rec.events_rejected or 0) + rejected
        if accepted:
            rec.last_event_at = now
            rec.status = "connected"
            rec.last_error = None
        elif error:
            rec.status = "error"
            rec.last_error = error
        rec.updated_at = now

    @classmethod
    def ingest_records(
        cls,
        db: Session,
        records: List[Dict[str, Any]],
        tenant_id: str = "tenant_default",
        is_simulated: bool = False,
        ingest_source_id: str = "api",
        run_detection: bool = True,
        run_correlation: bool = True,
        connector_type: str = "webhook",
    ) -> IngestionBatchResponse:
        accepted = 0
        rejected = 0
        duplicates = 0
        errors: List[str] = []
        job_id = f"job_{uuid.uuid4().hex[:10]}"
        stored: List[SecurityEvent] = []

        for idx, item in enumerate(records):
            if not isinstance(item, dict):
                rejected += 1
                msg = f"Record #{idx + 1}: expected JSON object"
                errors.append(msg)
                db.add(
                    IngestParseError(
                        id=f"perr_{uuid.uuid4().hex[:10]}",
                        source_id=ingest_source_id,
                        job_id=job_id,
                        record_index=idx,
                        error_type="schema",
                        message=msg,
                        raw_preview=str(item)[:500],
                        tenant_id=tenant_id,
                    )
                )
                continue
            try:
                event_obj, warnings = cls.normalize_record(
                    item,
                    tenant_id=tenant_id,
                    is_simulated=is_simulated,
                    ingest_source_id=ingest_source_id,
                )
                existing = (
                    db.query(SecurityEvent)
                    .filter(
                        SecurityEvent.event_id == event_obj.event_id,
                        SecurityEvent.tenant_id == tenant_id,
                    )
                    .first()
                )
                if existing:
                    rejected += 1
                    duplicates += 1
                    errors.append(f"Record #{idx + 1}: duplicate event_id {event_obj.event_id}")
                    continue
                db.add(event_obj)
                db.flush()
                stored.append(event_obj)
                accepted += 1
                if warnings:
                    errors.append(f"Record #{idx + 1} warnings: {', '.join(warnings)}")
            except IntegrityError:
                db.rollback()
                rejected += 1
                duplicates += 1
                errors.append(f"Record #{idx + 1}: duplicate event_id (integrity)")
            except Exception as e:
                rejected += 1
                msg = f"Record #{idx + 1} parsing error: {str(e)}"
                errors.append(msg)
                db.add(
                    IngestParseError(
                        id=f"perr_{uuid.uuid4().hex[:10]}",
                        source_id=ingest_source_id,
                        job_id=job_id,
                        record_index=idx,
                        error_type="parse_error",
                        message=str(e),
                        raw_preview=json.dumps(item, default=str)[:500],
                        tenant_id=tenant_id,
                    )
                )

        cls._touch_source(
            db,
            tenant_id=tenant_id,
            source_id=ingest_source_id,
            accepted=accepted,
            rejected=rejected,
            error=errors[0] if rejected and not accepted else None,
            connector_type=connector_type,
        )
        db.commit()

        alerts_created = 0
        incidents_created = 0
        if run_detection and stored:
            alerts = DetectionService.process_events(db, stored, tenant_id)
            alerts_created = len(alerts)
            if run_correlation and alerts:
                incidents = CorrelationEngine.correlate_alerts(
                    db=db,
                    tenant_id=tenant_id,
                    time_window_minutes=settings.CORRELATION_WINDOW_MINUTES,
                )
                incidents_created = len(incidents)

        return IngestionBatchResponse(
            total_received=len(records),
            accepted_count=accepted,
            rejected_count=rejected,
            errors=errors[:25],
            job_id=job_id,
            duplicate_count=duplicates,
            alerts_created=alerts_created,
            incidents_created=incidents_created,
            ingest_source_id=ingest_source_id,
            is_simulated=is_simulated,
        )

    @classmethod
    def parse_file_content(cls, content_str: str, filename: str) -> List[Dict[str, Any]]:
        filename = filename.lower()
        records: List[Dict[str, Any]] = []
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
            parsed = json.loads(content_str)
            records = parsed if isinstance(parsed, list) else [parsed]
        return records
