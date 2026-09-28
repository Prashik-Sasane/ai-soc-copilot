import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.indicator import Indicator
from app.core.config import settings

# Local threat intelligence database fixture for reliable demo & offline operation
KNOWN_THREAT_DATABASE = {
    "198.51.100.44": {
        "type": "ip",
        "reputation_score": 88.5,
        "risk_level": "high",
        "threat_actor": "APT-29 Sim",
        "source": "ThreatFox / VirusTotal Mock",
        "tags": ["c2", "cobalt-strike", "tls-beacon"],
        "confidence": 0.95
    },
    "c2-command-node.ru": {
        "type": "domain",
        "reputation_score": 92.0,
        "risk_level": "critical",
        "threat_actor": "APT-29 Sim",
        "source": "AlienVault OTX Mock",
        "tags": ["phishing", "c2-domain", "dns-tunneling"],
        "confidence": 0.98
    },
    "phish-payroll-update.net": {
        "type": "domain",
        "reputation_score": 78.0,
        "risk_level": "high",
        "threat_actor": "Unknown Phishing Campaign",
        "source": "PhishTank Mock",
        "tags": ["credential-harvesting", "phishing"],
        "confidence": 0.85
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "type": "hash",
        "reputation_score": 10.0,
        "risk_level": "clean",
        "threat_actor": "N/A (Empty Hash)",
        "source": "NSRL / Local DB",
        "tags": ["empty-file"],
        "confidence": 1.0
    }
}


class ThreatIntelService:
    @staticmethod
    def detect_indicator_type(val: str) -> str:
        val = val.strip()
        # IP regex
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
            return "ip"
        # Domain regex
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", val) and not val.startswith("http"):
            return "domain"
        # URL regex
        if val.startswith("http://") or val.startswith("https://"):
            return "url"
        # Hash regex (MD5/SHA1/SHA256)
        if re.match(r"^[a-fA-F0-9]{32,64}$", val):
            return "hash"
        return "unknown"

    @classmethod
    def enrich_indicator(
        cls, db: Session, indicator_val: str, indicator_type: Optional[str] = None, tenant_id: str = "tenant_default"
    ) -> Indicator:
        indicator_val = indicator_val.strip()
        if not indicator_type or indicator_type == "unknown":
            indicator_type = cls.detect_indicator_type(indicator_val)

        # Check DB cache
        cached = db.query(Indicator).filter(
            Indicator.indicator_value == indicator_val,
            Indicator.tenant_id == tenant_id
        ).first()

        if cached:
            return cached

        # Check local threat database fixture
        known = KNOWN_THREAT_DATABASE.get(indicator_val)
        now = datetime.now(timezone.utc)

        if known:
            ind = Indicator(
                id=f"ind_{uuid.uuid4().hex[:10]}",
                indicator_value=indicator_val,
                indicator_type=known["type"],
                reputation_score=known["reputation_score"],
                risk_level=known["risk_level"],
                threat_actor=known["threat_actor"],
                source_attribution=known["source"],
                first_seen=now,
                last_seen=now,
                raw_enrichment={"tags": known["tags"], "provider": known["source"]},
                confidence=known["confidence"],
                tenant_id=tenant_id
            )
        else:
            # Neutral / unknown indicator
            ind = Indicator(
                id=f"ind_{uuid.uuid4().hex[:10]}",
                indicator_value=indicator_val,
                indicator_type=indicator_type,
                reputation_score=0.0,
                risk_level="unknown",
                threat_actor=None,
                source_attribution="Local Threat Intelligence Adapter",
                first_seen=now,
                last_seen=now,
                raw_enrichment={"status": "No malicious records found in threat intel feeds"},
                confidence=0.5,
                tenant_id=tenant_id
            )

        db.add(ind)
        db.commit()
        db.refresh(ind)
        return ind
