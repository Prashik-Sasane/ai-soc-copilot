import uuid
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, TypedDict
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.models.investigation import InvestigationHistory
from app.services.rag_service import RAGService
from app.services.mitre_service import MitreService
from app.services.threat_intel_service import ThreatIntelService


class InvestigationState(TypedDict):
    query: str
    tenant_id: str
    user_id: str
    incident_id: Optional[str]
    alert_id: Optional[str]
    indicator_value: Optional[str]
    retrieved_events: List[Dict[str, Any]]
    retrieved_alerts: List[Dict[str, Any]]
    retrieved_indicators: List[Dict[str, Any]]
    retrieved_rag_chunks: List[Dict[str, Any]]
    mitre_hypotheses: List[Dict[str, Any]]
    summary: str
    findings: List[str]
    cited_evidence: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    confidence: float
    limitations: List[str]
    error: Optional[str]


class AISocCopilotWorkflow:
    """
    LangGraph-structured explicit investigation workflow.
    Nodes:
    1. query_understanding: Parse user intent & extract entities
    2. evidence_retrieval: Fetch relational events/alerts + RAG playbooks
    3. context_assembly: Sanitize prompt injection & tenant isolation
    4. analysis_mitre: Map evidence to MITRE ATT&CK tactics/techniques
    5. response_generation: Formulate evidence-grounded response with citations
    """

    @classmethod
    def sanitize_untrusted_input(cls, text: str) -> str:
        """Defends against prompt injection in log entries or user text."""
        if not text:
            return ""
        # Neutralize common system prompt override attempts
        sanitized = re.sub(r"(ignore previous instructions|system prompt:|override security policy)", "[REDACTED_PROMPT_INJECTION_ATTEMPT]", text, flags=re.IGNORECASE)
        return sanitized

    @classmethod
    def node_query_understanding(cls, state: InvestigationState) -> InvestigationState:
        q = state["query"].lower()
        state["findings"] = []
        state["limitations"] = []
        
        # Detect intent flags
        if "explain" in q or "summary" in q or "summarize" in q:
            state["findings"].append("Intent: Explanation & Context Summary")
        elif "recommend" in q or "next step" in q or "action" in q:
            state["findings"].append("Intent: Prioritized Investigative & Response Guidance")
        elif "evidence" in q or "show" in q:
            state["findings"].append("Intent: Evidence Deep-Dive")
        else:
            state["findings"].append("Intent: General Security Triage Query")

        return state

    @classmethod
    def node_evidence_retrieval(cls, state: InvestigationState, db: Session) -> InvestigationState:
        tenant_id = state["tenant_id"]
        
        # 1. Retrieve Incident & attached alerts/events
        retrieved_events = []
        retrieved_alerts = []
        retrieved_indicators = []

        if state["incident_id"]:
            inc = db.query(Incident).filter(Incident.id == state["incident_id"], Incident.tenant_id == tenant_id).first()
            if inc and inc.alert_ids:
                alerts = db.query(Alert).filter(Alert.id.in_(inc.alert_ids), Alert.tenant_id == tenant_id).all()
                for a in alerts:
                    retrieved_alerts.append({
                        "id": a.id,
                        "title": a.title,
                        "severity": a.severity,
                        "source": a.source,
                        "rule_name": a.rule_name,
                        "asset_id": a.asset_id
                    })
                    if a.event_ids:
                        evts = db.query(SecurityEvent).filter(SecurityEvent.id.in_(a.event_ids), SecurityEvent.tenant_id == tenant_id).all()
                        for e in evts:
                            retrieved_events.append({
                                "id": e.id,
                                "event_id": e.event_id,
                                "source": e.source,
                                "event_type": e.event_type,
                                "user": e.user,
                                "src_ip": e.src_ip,
                                "dst_ip": e.dst_ip,
                                "process_name": e.process_name,
                                "command_line": cls.sanitize_untrusted_input(e.command_line),
                                "domain": e.domain,
                                "raw_data": cls.sanitize_untrusted_input(e.raw_data)
                            })
            if inc and inc.indicator_ids:
                inds = db.query(Indicator).filter(Indicator.id.in_(inc.indicator_ids), Indicator.tenant_id == tenant_id).all()
                for ind in inds:
                    retrieved_indicators.append({
                        "id": ind.id,
                        "value": ind.indicator_value,
                        "type": ind.indicator_type,
                        "reputation_score": ind.reputation_score,
                        "risk_level": ind.risk_level,
                        "threat_actor": ind.threat_actor
                    })

        elif state["alert_id"]:
            alt = db.query(Alert).filter(Alert.id == state["alert_id"], Alert.tenant_id == tenant_id).first()
            if alt:
                retrieved_alerts.append({
                    "id": alt.id,
                    "title": alt.title,
                    "severity": alt.severity,
                    "source": alt.source,
                    "rule_name": alt.rule_name,
                    "asset_id": alt.asset_id
                })
                if alt.event_ids:
                    evts = db.query(SecurityEvent).filter(SecurityEvent.id.in_(alt.event_ids), SecurityEvent.tenant_id == tenant_id).all()
                    for e in evts:
                        retrieved_events.append({
                            "id": e.id,
                            "event_id": e.event_id,
                            "source": e.source,
                            "event_type": e.event_type,
                            "user": e.user,
                            "command_line": cls.sanitize_untrusted_input(e.command_line),
                            "raw_data": cls.sanitize_untrusted_input(e.raw_data)
                        })

        if not retrieved_events and not retrieved_alerts:
            # Fallback: fetch recent events
            evts = db.query(SecurityEvent).filter(SecurityEvent.tenant_id == tenant_id).order_by(SecurityEvent.created_at.desc()).limit(5).all()
            for e in evts:
                retrieved_events.append({
                    "id": e.id,
                    "event_id": e.event_id,
                    "source": e.source,
                    "event_type": e.event_type,
                    "user": e.user,
                    "command_line": cls.sanitize_untrusted_input(e.command_line),
                    "raw_data": cls.sanitize_untrusted_input(e.raw_data)
                })

        # 2. Query RAG Knowledge Base Chunks
        rag_chunks = RAGService.search_similar_chunks(db=db, query=state["query"], top_k=2, tenant_id=tenant_id)

        state["retrieved_events"] = retrieved_events
        state["retrieved_alerts"] = retrieved_alerts
        state["retrieved_indicators"] = retrieved_indicators
        state["retrieved_rag_chunks"] = rag_chunks

        return state

    @classmethod
    def node_analysis_mitre(cls, state: InvestigationState) -> InvestigationState:
        combined_text = state["query"] + " "
        for e in state["retrieved_events"]:
            combined_text += f"{e.get('process_name', '')} {e.get('command_line', '')} {e.get('raw_data', '')} "
        for a in state["retrieved_alerts"]:
            combined_text += f"{a.get('title', '')} {a.get('rule_name', '')} "

        mitre_hypotheses = MitreService.map_evidence_to_mitre(combined_text)
        state["mitre_hypotheses"] = mitre_hypotheses
        return state

    @classmethod
    def node_response_generation(cls, state: InvestigationState, db: Session) -> InvestigationState:
        events = state["retrieved_events"]
        alerts = state["retrieved_alerts"]
        indicators = state["retrieved_indicators"]
        rag_chunks = state["retrieved_rag_chunks"]
        mitre = state["mitre_hypotheses"]

        citations = []
        findings = list(state["findings"])
        recommendations = []

        # 1. Build Citations from retrieved events & RAG
        for e in events:
            citations.append({
                "citation_id": f"cit_evt_{e['id'][-6:]}",
                "source_type": "event",
                "source_id": e["id"],
                "title": f"Security Event: {e['event_type']} ({e['source']})",
                "snippet": e.get("raw_data")[:180] if e.get("raw_data") else f"Event ID {e['event_id']}",
                "relevance_score": 0.95
            })

        for r in rag_chunks:
            citations.append({
                "citation_id": f"cit_kb_{r['chunk_id'][-6:]}",
                "source_type": "knowledge_base",
                "source_id": r["chunk_id"],
                "title": f"Playbook: {r['title']} - Section {r['section']}",
                "snippet": r["content"][:180],
                "relevance_score": r["relevance_score"]
            })

        # 2. Formulate Findings & Summary
        if alerts:
            alert_titles = ", ".join([a["title"] for a in alerts[:2]])
            summary = f"Investigation analyzed {len(alerts)} alert(s) [{alert_titles}] and {len(events)} associated security event(s)."
        else:
            summary = f"Investigation evaluated {len(events)} security events against active playbooks and threat intelligence feeds."

        if indicators:
            high_risk = [i for i in indicators if i.get("risk_level") in ["high", "critical"]]
            if high_risk:
                findings.append(f"Identified {len(high_risk)} high-risk indicator(s): {', '.join([i['value'] for i in high_risk])}")

        if mitre:
            top_tech = mitre[0]
            findings.append(f"Primary MITRE ATT&CK candidate: {top_tech['technique_id']} ({top_tech['name']}) under tactic {top_tech['tactic']} (Confidence: {top_tech['confidence']*100:.0f}%).")

        # 3. Formulate Prioritized Recommendations (Investigative vs Response)
        recommendations.append({
            "category": "investigative",
            "title": "Validate command line arguments and parent process tree",
            "description": "Examine EDR telemetry for parent process spawning suspicious execution.",
            "priority": "high",
            "requires_approval": False
        })
        recommendations.append({
            "category": "response",
            "title": "Network Containment / Host Isolation",
            "description": "Isolate host from local subnet via EDR agent if malicious C2 or credential dumping is confirmed.",
            "priority": "high",
            "requires_approval": True
        })

        limitations = [
            "MITRE ATT&CK mappings are automated hypotheses requiring Tier 2 analyst validation.",
            "External threat intelligence feed reputation scores reflect current cached snapshot data."
        ]

        state["summary"] = summary
        state["findings"] = findings
        state["cited_evidence"] = citations
        state["recommendations"] = recommendations
        state["confidence"] = 0.88 if events or alerts else 0.65
        state["limitations"] = limitations

        # Save to InvestigationHistory DB
        hist = InvestigationHistory(
            id=f"inv_{uuid.uuid4().hex[:10]}",
            query=state["query"],
            incident_id=state["incident_id"],
            alert_id=state["alert_id"],
            user_id=state["user_id"],
            workflow_state="completed",
            summary=summary,
            response_json={
                "summary": summary,
                "findings": findings,
                "limitations": limitations
            },
            cited_evidence=citations,
            mitre_mappings=mitre,
            confidence=state["confidence"],
            tenant_id=state["tenant_id"]
        )
        db.add(hist)
        db.commit()

        return state

    @classmethod
    def run_investigation(
        cls, db: Session, query: str, user_id: str, tenant_id: str = "tenant_default", incident_id: Optional[str] = None, alert_id: Optional[str] = None
    ) -> Dict[str, Any]:
        state: InvestigationState = {
            "query": query,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "incident_id": incident_id,
            "alert_id": alert_id,
            "indicator_value": None,
            "retrieved_events": [],
            "retrieved_alerts": [],
            "retrieved_indicators": [],
            "retrieved_rag_chunks": [],
            "mitre_hypotheses": [],
            "summary": "",
            "findings": [],
            "cited_evidence": [],
            "recommendations": [],
            "confidence": 0.0,
            "limitations": [],
            "error": None
        }

        # Execute explicit state graph pipeline nodes
        state = cls.node_query_understanding(state)
        state = cls.node_evidence_retrieval(state, db=db)
        state = cls.node_analysis_mitre(state)
        state = cls.node_response_generation(state, db=db)

        return {
            "investigation_id": f"inv_{uuid.uuid4().hex[:8]}",
            "query": state["query"],
            "summary": state["summary"],
            "findings": state["findings"],
            "mitre_mappings": state["mitre_hypotheses"],
            "cited_evidence": state["cited_evidence"],
            "recommendations": state["recommendations"],
            "confidence": state["confidence"],
            "limitations": state["limitations"],
            "timestamp": datetime.now(timezone.utc)
        }
