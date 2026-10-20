import base64
import ipaddress
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from app.models.indicator import Indicator
from app.core.config import settings


class ThreatIntelService:
    @staticmethod
    def detect_indicator_type(value: str) -> str:
        value = value.strip()
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
        if value.startswith(("http://", "https://")):
            return "url"
        if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
            return "hash"
        if re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}", value):
            return "domain"
        return "unknown"

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 20:
            return "medium"
        return "clean" if score == 0 else "low"

    @classmethod
    def _query_virustotal(cls, value: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        if not settings.VT_API_KEY or indicator_type not in {"ip", "domain", "url", "hash"}:
            return None
        collection = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}.get(indicator_type)
        if indicator_type == "url":
            identifier = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            collection = "urls"
        else:
            identifier = value
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/{collection}/{quote(identifier, safe='')}",
            headers={"x-apikey": settings.VT_API_KEY},
            timeout=15.0,
        )
        if response.status_code == 404:
            return {"provider": "VirusTotal", "score": None, "tags": [], "threat_actor": None, "raw": {"status": "not_found"}}
        response.raise_for_status()
        attrs = response.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v or 0) for v in stats.values())
        score = round(100 * (malicious + suspicious * 0.5) / total, 1) if total else None
        classification = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
        tags = attrs.get("tags", [])
        return {
            "provider": "VirusTotal",
            "score": score,
            "tags": tags[:30] if isinstance(tags, list) else [],
            "threat_actor": classification or (attrs.get("threat_names") or [None])[0],
            "raw": {"last_analysis_stats": stats, "reputation": attrs.get("reputation"), "tags": tags[:30]},
        }

    @classmethod
    def _query_otx(cls, value: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        if not settings.OTX_API_KEY or indicator_type not in {"ip", "domain", "url", "hash"}:
            return None
        otx_type = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}[indicator_type]
        response = httpx.get(
            f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{quote(value, safe='')}/general",
            headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
            timeout=15.0,
        )
        if response.status_code == 404:
            return {"provider": "AlienVault OTX", "score": None, "tags": [], "threat_actor": None, "raw": {"status": "not_found"}}
        response.raise_for_status()
        data = response.json()
        pulses = data.get("pulse_info", {}).get("pulses", [])
        tags = sorted({tag for pulse in pulses for tag in pulse.get("tags", [])})
        actors = [pulse.get("adversary") for pulse in pulses if pulse.get("adversary")]
        count = int(data.get("pulse_info", {}).get("count", len(pulses)))
        # OTX exposes pulse counts rather than a normalized reputation score;
        # this is a disclosed local proxy, while the raw count is preserved.
        score = min(95.0, 20.0 + count * 5.0) if count else None
        return {
            "provider": "AlienVault OTX",
            "score": score,
            "tags": tags[:30],
            "threat_actor": actors[0] if actors else None,
            "raw": {"pulse_count": count, "tags": tags[:30], "pulses": [{"name": p.get("name"), "adversary": p.get("adversary")} for p in pulses[:10]]},
        }

    @classmethod
    def enrich_indicator(
        cls, db: Session, indicator_val: str, indicator_type: Optional[str] = None, tenant_id: str = "tenant_default"
    ) -> Indicator:
        value = indicator_val.strip()
        kind = indicator_type if indicator_type and indicator_type != "unknown" else cls.detect_indicator_type(value)
        cached = db.query(Indicator).filter(
            Indicator.indicator_value == value,
            Indicator.tenant_id == tenant_id,
        ).first()
        now = datetime.now(timezone.utc)
        ttl = timedelta(minutes=max(1, settings.TI_CACHE_TTL_MINUTES))
        if cached and cached.cached_until:
            until = cached.cached_until
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            if until > now and cached.lookup_status in {"ok", "not_found", "not_configured"}:
                return cached
        if cached and cached.raw_enrichment and cached.last_seen:
            last_seen = cached.last_seen
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            if now - last_seen < ttl and cached.lookup_status in {"ok", "not_found", "not_configured"}:
                return cached

        provider_results: List[Dict[str, Any]] = []
        errors = []
        for query_provider in (cls._query_virustotal, cls._query_otx):
            try:
                result = query_provider(value, kind)
                if result:
                    provider_results.append(result)
            except httpx.HTTPError as exc:
                errors.append(f"{query_provider.__name__.removeprefix('_query_')}: {exc.__class__.__name__}")

        lookup_status = "ok"
        provider_name = None
        if provider_results:
            provider_scores = [result["score"] for result in provider_results if result["score"] is not None]
            score = round(max(provider_scores), 1) if provider_scores else 0.0
            tags = sorted({tag for result in provider_results for tag in result["tags"]})
            actor = next((result["threat_actor"] for result in provider_results if result.get("threat_actor")), None)
            sources = [result["provider"] for result in provider_results]
            provider_name = " + ".join(sources)
            raw = {
                "providers": sources,
                "provider_data": {r["provider"]: r["raw"] for r in provider_results},
                "tags": tags,
                "looked_up_at": now.isoformat(),
            }
            if errors:
                raw["provider_errors"] = errors
            if provider_scores:
                confidence = min(0.99, 0.6 + 0.15 * len(provider_results))
                risk_level = cls._risk_level(score)
            else:
                confidence = 0.2
                risk_level = "unknown"
                lookup_status = "not_found"
            source = provider_name
        else:
            score = 0.0
            actor = None
            tags = []
            if not settings.VT_API_KEY and not settings.OTX_API_KEY:
                lookup_status = "not_configured"
                source = "No configured live threat intelligence provider"
                raw = {"providers": [], "status": "not_configured", "looked_up_at": now.isoformat()}
            elif errors:
                lookup_status = "provider_unavailable"
                source = "Threat intelligence provider unavailable"
                raw = {"providers": [], "status": "provider_unavailable", "provider_errors": errors, "looked_up_at": now.isoformat()}
            else:
                lookup_status = "not_found"
                source = "No provider returned a record"
                raw = {"providers": [], "status": "not_found", "looked_up_at": now.isoformat()}
            risk_level = "unknown"
            confidence = 0.0

        cached_until = now + timedelta(minutes=max(1, settings.TI_CACHE_TTL_MINUTES))
        if cached:
            cached.indicator_type = kind
            cached.reputation_score = score
            cached.risk_level = risk_level
            cached.lookup_status = lookup_status
            cached.threat_actor = actor
            cached.source_attribution = source
            cached.provider_name = provider_name
            cached.last_seen = now
            cached.cached_until = cached_until
            cached.raw_enrichment = raw
            cached.confidence = confidence
            ind = cached
        else:
            ind = Indicator(
                id=f"ind_{uuid.uuid4().hex[:10]}",
                indicator_value=value,
                indicator_type=kind,
                reputation_score=score,
                risk_level=risk_level,
                lookup_status=lookup_status,
                threat_actor=actor,
                source_attribution=source,
                provider_name=provider_name,
                first_seen=now,
                last_seen=now,
                cached_until=cached_until,
                raw_enrichment=raw,
                confidence=confidence,
                tenant_id=tenant_id,
            )
            db.add(ind)
        db.commit()
        db.refresh(ind)
        return ind
