import uuid
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, TypedDict
from sqlalchemy.orm import Session
from langgraph.graph import END, StateGraph

from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.models.investigation import InvestigationHistory
from app.services.rag_service import RAGService
from app.services.mitre_service import MitreService
from app.services.llm_service import LLMService
from app.services.vector_service import VectorService


class InvestigationState(TypedDict):
    query: str
    tenant_id: str
    user_id: str
    incident_id: Optional[str]
    alert_id: Optional[str]
    indicator_value: Optional[str]
    target_hostname: Optional[str]
    target_user: Optional[str]
    incident_context: Dict[str, Any]
    excluded_evidence: List[Dict[str, Any]]
    finding_details: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    missing_data: List[str]
    confidence_rationale: str
    status: str
    investigation_id: str
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
        query = state["query"]
        state["findings"] = []
        state["limitations"] = []

        # Accept identifiers supplied in the request or included in the analyst's text.
        if not state["alert_id"]:
            found = re.search(r"\balt_[A-Za-z0-9_-]+\b", query, re.I)
            state["alert_id"] = found.group(0) if found else None
        if not state["incident_id"]:
            found = re.search(r"\binc_[A-Za-z0-9_-]+\b", query, re.I)
            state["incident_id"] = found.group(0) if found else None

        # Hostnames are constraints for structured telemetry lookup, not RAG hints only.
        host_match = re.search(
            r"\b(?:host(?:name)?|asset)\s*(?:is|=|:)?\s*([A-Za-z0-9][A-Za-z0-9._-]*)",
            query, re.I,
        ) or re.search(r"\bon\s+([A-Za-z0-9][A-Za-z0-9._-]*)", query, re.I)
        state["target_hostname"] = host_match.group(1).rstrip(".,;") if host_match else None
        user_match = re.search(r"\buser\s*(?:is|=|:)?\s*([A-Za-z0-9_.@\\-]+)", query, re.I)
        state["target_user"] = user_match.group(1).rstrip(".,;") if user_match else None

        return state

    @classmethod
    def node_evidence_retrieval(cls, state: InvestigationState, db: Session) -> InvestigationState:
        tenant_id = state["tenant_id"]
        retrieved_events: List[Dict[str, Any]] = []
        retrieved_alerts: List[Dict[str, Any]] = []
        retrieved_indicators: List[Dict[str, Any]] = []
        state["excluded_evidence"] = []
        target_host = (state.get("target_hostname") or "").casefold()
        incident = None
        alerts: List[Alert] = []

        if state["incident_id"]:
            incident = db.query(Incident).filter(
                Incident.id == state["incident_id"], Incident.tenant_id == tenant_id
            ).first()
            if incident:
                query = db.query(Alert).filter(
                    Alert.tenant_id == tenant_id, Alert.id.in_(incident.alert_ids or [])
                )
                if state["alert_id"]:
                    query = query.filter(Alert.id == state["alert_id"])
                alerts = query.order_by(Alert.created_at.desc()).all()
            else:
                state["limitations"].append("The requested incident ID was not found in this tenant.")
        elif state["alert_id"]:
            alert = db.query(Alert).filter(
                Alert.id == state["alert_id"], Alert.tenant_id == tenant_id
            ).first()
            if alert:
                alerts = [alert]
            else:
                state["limitations"].append("The requested alert ID was not found in this tenant.")
        elif state.get("target_hostname"):
            # A hostname-only investigation uses exact structured filtering.
            alert_query = db.query(Alert).filter(
                Alert.tenant_id == tenant_id,
                Alert.asset_id.ilike(state["target_hostname"]),
            )
            if state.get("target_user"):
                alert_query = alert_query.filter(Alert.affected_user.ilike(state["target_user"]))
            alerts = alert_query.order_by(Alert.created_at.desc()).limit(50).all()

        allowed_event_ids = set()
        for alert in alerts:
            alert_host = (alert.asset_id or "").casefold()
            if target_host and alert_host != target_host:
                state["excluded_evidence"].append({
                    "source_type": "alert", "source_id": alert.id,
                    "hostname": alert.asset_id, "reason": "requested_hostname_mismatch",
                })
                continue
            if state.get("target_user") and (alert.affected_user or "").casefold() != state["target_user"].casefold():
                state["excluded_evidence"].append({
                    "source_type": "alert", "source_id": alert.id,
                    "user": alert.affected_user, "reason": "requested_user_mismatch",
                })
                continue
            retrieved_alerts.append({
                "id": alert.id, "title": alert.title, "severity": alert.severity,
                "status": alert.status, "source": alert.source, "rule_name": alert.rule_name,
                "asset_id": alert.asset_id, "affected_user": alert.affected_user,
                "incident_id": alert.incident_id, "event_ids": list(alert.event_ids or []),
                "created_at": alert.created_at, "mitre_candidates": alert.mitre_candidates or [],
            })
            allowed_event_ids.update(alert.event_ids or [])

        if incident:
            state["incident_context"] = {
                "incident_id": incident.id, "title": incident.title, "status": incident.status,
                "severity": incident.severity, "alert_ids": list(incident.alert_ids or []),
            }
            if incident.indicator_ids:
                indicators = db.query(Indicator).filter(
                    Indicator.id.in_(incident.indicator_ids), Indicator.tenant_id == tenant_id
                ).all()
                retrieved_indicators.extend([{
                    "id": i.id, "value": i.indicator_value, "type": i.indicator_type,
                    "reputation_score": i.reputation_score, "risk_level": i.risk_level,
                    "threat_actor": i.threat_actor, "source_attribution": i.source_attribution,
                } for i in indicators])

        # Host-only lookups may include events not already attached to an alert.
        if state.get("target_hostname") and not state["incident_id"] and not state["alert_id"]:
            host_events = db.query(SecurityEvent).filter(
                SecurityEvent.tenant_id == tenant_id,
                SecurityEvent.hostname.ilike(state["target_hostname"]),
                *([SecurityEvent.user.ilike(state["target_user"])] if state.get("target_user") else []),
            ).order_by(SecurityEvent.timestamp.desc()).limit(100).all()
            allowed_event_ids.update(event.id for event in host_events)

        if allowed_event_ids:
            events = db.query(SecurityEvent).filter(
                SecurityEvent.tenant_id == tenant_id,
                SecurityEvent.id.in_(allowed_event_ids),
            ).order_by(SecurityEvent.timestamp.asc()).limit(200).all()
            for event in events:
                event_host = (event.hostname or "").casefold()
                event_user = (event.user or "").casefold()
                if target_host and event_host != target_host:
                    state["excluded_evidence"].append({
                        "source_type": "event", "source_id": event.id,
                        "hostname": event.hostname, "reason": "requested_hostname_mismatch_or_missing",
                    })
                    continue
                if state.get("target_user") and event_user != state["target_user"].casefold():
                    state["excluded_evidence"].append({
                        "source_type": "event", "source_id": event.id,
                        "user": event.user, "reason": "requested_user_mismatch",
                    })
                    continue
                metadata = event.metadata_json if isinstance(event.metadata_json, dict) else {}
                retrieved_events.append({
                    "id": event.id, "event_id": event.event_id, "timestamp": event.timestamp,
                    "hostname": event.hostname, "source": event.source, "event_type": event.event_type,
                    "severity": event.severity, "user": event.user, "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip, "process_name": event.process_name,
                    "command_line": cls.sanitize_untrusted_input(event.command_line),
                    "domain": event.domain, "file_hash": event.file_hash,
                    "process_id": metadata.get("process_id") or metadata.get("process.pid"),
                    "parent_process_name": metadata.get("parent_process_name") or metadata.get("parent.process.name"),
                    "parent_process_id": metadata.get("parent_process_id") or metadata.get("parent.process.pid"),
                    "raw_data": cls.sanitize_untrusted_input(event.raw_data),
                })

        if state.get("indicator_value"):
            indicator = db.query(Indicator).filter(
                Indicator.tenant_id == tenant_id,
                Indicator.indicator_value == state["indicator_value"],
            ).first()
            if indicator:
                retrieved_indicators.append({
                    "id": indicator.id, "value": indicator.indicator_value, "type": indicator.indicator_type,
                    "reputation_score": indicator.reputation_score, "risk_level": indicator.risk_level,
                    "threat_actor": indicator.threat_actor, "source_attribution": indicator.source_attribution,
                })

        if target_host and state["excluded_evidence"]:
            state["limitations"].append(
                f"Evidence for another or unknown host was excluded. Requested host: {state['target_hostname']}."
            )
        if not retrieved_events and not retrieved_alerts:
            state["limitations"].append(
                "No matching tenant-scoped alert, incident, or event record was found for the supplied identifiers/entities."
            )

        # Knowledge RAG is separate from exact telemetry retrieval and cannot establish that an attack occurred.
        rag_chunks = RAGService.search_similar_chunks(
            db=db, query=state["query"], top_k=3, tenant_id=tenant_id
        )

        state["retrieved_events"] = retrieved_events
        state["retrieved_alerts"] = retrieved_alerts
        state["retrieved_indicators"] = retrieved_indicators
        state["retrieved_rag_chunks"] = rag_chunks

        return state

    @classmethod
    def node_analysis_mitre(cls, state: InvestigationState) -> InvestigationState:
        # Map only retrieved security telemetry/alert evidence. Analyst wording and
        # knowledge documents must not create a technique candidate by themselves.
        combined_text = ""
        for e in state["retrieved_events"]:
            combined_text += f"{e.get('process_name', '')} {e.get('command_line', '')} {e.get('raw_data', '')} "
        for a in state["retrieved_alerts"]:
            combined_text += f"{a.get('title', '')} {a.get('rule_name', '')} "

        mitre_hypotheses = MitreService.map_evidence_to_mitre(combined_text) if combined_text.strip() else []
        event_refs = [f"cit_evt_{e['id'][-6:]}" for e in state["retrieved_events"]]
        alert_refs = [f"cit_alt_{a['id'][-6:]}" for a in state["retrieved_alerts"]]
        mitre_hypotheses = [{
            "technique_id": item["technique_id"],
            "technique_name": item["name"],
            "tactic": item["tactic"],
            "status": "candidate",
            # Existing keyword matching is not calibrated; expose it only as a match score.
            "confidence": None,
            "match_score": item["confidence"],
            "rationale": item["rationale"],
            "evidence_refs": list(dict.fromkeys(alert_refs + event_refs)),
            "requires_analyst_validation": True,
            "data_version": item.get("data_version"),
            "source": item.get("source"),
        } for item in mitre_hypotheses]
        state["mitre_hypotheses"] = mitre_hypotheses
        return state

    @classmethod
    def node_context_assembly(cls, state: InvestigationState) -> InvestigationState:
        # Telemetry is untrusted data. Sanitize it before any provider sees the context.
        for event in state["retrieved_events"]:
            event["command_line"] = cls.sanitize_untrusted_input(event.get("command_line") or "")
            event["raw_data"] = cls.sanitize_untrusted_input(event.get("raw_data") or "")
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

        for a in alerts:
            citations.append({
                "citation_id": f"cit_alt_{a['id'][-6:]}",
                "source_type": "alert",
                "source_id": a["id"],
                "title": f"Alert: {a['title']}",
                "snippet": f"{a.get('rule_name') or 'rule unknown'} on {a.get('asset_id') or 'unknown asset'}",
                "relevance_score": None,
                "hostname": a.get("asset_id"),
                "timestamp": a.get("created_at").isoformat() if a.get("created_at") else None,
            })
        for e in events:
            citations.append({
                "citation_id": f"cit_evt_{e['id'][-6:]}",
                "source_type": "event",
                "source_id": e["id"],
                "title": f"Security Event: {e['event_type']} ({e['source']})",
                "snippet": (e.get("raw_data") or f"Event ID {e['event_id']}")[:180],
                "relevance_score": None,
                "hostname": e.get("hostname"),
                "timestamp": e.get("timestamp").isoformat() if e.get("timestamp") else None,
            })
        for ind in indicators:
            citations.append({
                "citation_id": f"cit_ind_{ind['id'][-6:]}",
                "source_type": "indicator",
                "source_id": ind["id"],
                "title": f"Indicator {ind['type']}: {ind['value']}",
                "snippet": f"Lookup status/risk: {ind.get('risk_level', 'unknown')}",
                "relevance_score": None,
            })
        for r in rag_chunks:
            citations.append({
                "citation_id": f"cit_kb_{r['chunk_id'][-6:]}",
                "source_type": "knowledge_base",
                "source_id": r["chunk_id"],
                "title": f"Knowledge: {r['title']} - {r['section']}",
                "snippet": r["content"][:180],
                "relevance_score": r["relevance_score"],
                "source_ref": r.get("source_ref"),
                "score_type": "cosine_similarity",
            })

        evidence_weak = not events and not alerts
        if alerts:
            alert_titles = ", ".join([a["title"] for a in alerts[:2]])
            summary = (
                f"Investigation analyzed {len(alerts)} alert(s) [{alert_titles}] and {len(events)} associated security event(s). "
                f"Recommendations below are taken from retrieved knowledge text when available."
            )
        elif events:
            summary = f"Investigation evaluated {len(events)} security events against tenant-isolated knowledge sources."
        else:
            summary = (
                "Insufficient bound evidence for this query. No incident/alert context was provided or found. "
                "Do not treat the following as a live investigation result."
            )
            findings.append("Evidence unavailable or too weak to support a high-confidence assessment.")

        if indicators:
            high_risk = [i for i in indicators if i.get("risk_level") in ["high", "critical"]]
            unknown = [i for i in indicators if i.get("risk_level") in ["unknown", "not_found"]]
            if high_risk:
                findings.append(
                    f"Identified {len(high_risk)} high-risk indicator(s): {', '.join([i['value'] for i in high_risk])} "
                    f"(see indicator citations)."
                )
            if unknown:
                findings.append(
                    f"{len(unknown)} indicator(s) have unknown/not-found reputation and must not be treated as clean."
                )

        if mitre:
            top_tech = mitre[0]
            findings.append(
                f"Primary MITRE ATT&CK candidate (not confirmed): {top_tech['technique_id']} ({top_tech['technique_name']}) "
                f"under tactic {top_tech['tactic']}; validate against the cited telemetry."
            )

        # Recommendations come from the retrieved source text, so an analyst can
        # verify each action against the knowledge-base citations above.
        seen_actions = set()
        for chunk in rag_chunks:
            for line in chunk.get("content", "").splitlines():
                action_match = re.match(r"^\s*(?:\d+[.)]|[-*]|Required Action:)\s+(.+)$", line, re.I)
                if not action_match:
                    continue
                action = action_match.group(1).strip().strip("` ")
                normalized = re.sub(r"\W+", " ", action.lower()).strip()
                if len(action) < 18 or normalized in seen_actions:
                    continue
                seen_actions.add(normalized)
                is_response = bool(re.search(r"\b(isolate|block|quarantin|disable|reset|revoke|contain|remove)\b", action, re.I))
                recommendations.append({
                    "category": "response" if is_response else "investigative",
                    "title": action[:100],
                    "description": f"Retrieved from {chunk['title']} ({chunk.get('section') or 'source text'}). Verify against the cited source and local procedures. Response actions remain recommendations until an authorized analyst approves them.",
                    "priority": "high" if is_response else "medium",
                    "requires_approval": is_response,
                    "citation_id": f"cit_kb_{chunk['chunk_id'][-6:]}",
                    "rationale": "This step appears in the retrieved knowledge source; confirm it applies to the observed endpoint and local policy.",
                    "evidence_refs": [f"cit_kb_{chunk['chunk_id'][-6:]}"],
                    "prerequisites": ["Analyst validates the target and local response policy."],
                    "expected_outcome": "Documented investigative or response progress; this recommendation is not an executed action.",
                    "status": "proposed",
                })
                if len(recommendations) >= 4:
                    break
            if len(recommendations) >= 4:
                break
        if not recommendations and events:
            event_refs = [f"cit_evt_{e['id'][-6:]}" for e in events[:3]]
            recommendations.append({
                "category": "investigative",
                "title": "Retrieve process ancestry and access details",
                "description": "The stored event does not contain enough lineage/access context to validate the observed process behavior.",
                "priority": "high",
                "requires_approval": False,
                "rationale": "The available event has a process observation but does not include verified parent-process or access-mask details.",
                "evidence_refs": event_refs,
                "prerequisites": ["Query the endpoint telemetry source for the same host and event time."],
                "expected_outcome": "Confirm or refute the process relationship using endpoint records.",
                "status": "proposed",
            })
        if not recommendations:
            recommendations.append({
                "category": "investigative",
                "title": "Gather and validate incident-specific evidence",
                "description": "No retrieved knowledge source contained an explicit response step. Confirm affected assets, process lineage, and indicator reputation before taking action.",
                "priority": "medium",
                "requires_approval": False,
                "rationale": "No direct security record was retrieved for this query.",
                "evidence_refs": [],
                "prerequisites": ["Supply an alert ID, incident ID, or exact hostname."],
                "expected_outcome": "Retrieve tenant-scoped records before drawing an incident conclusion.",
                "status": "proposed",
            })

        embedding_mode = VectorService.embedding_mode()
        findings_text = "\n".join(f"- {f}" for f in findings) or "- (none)"
        citation_lines = "\n".join(
            f"- {c['citation_id']} ({c['source_type']}): {c['title']} [source_id={c['source_id']}]"
            for c in citations[:12]
        ) or "- (none)"
        llm_result = LLMService.summarize(
            "You are a SOC investigation assistant. Write a concise, analyst-ready summary of the "
            "evidence below in 2-4 sentences. Use only the facts provided. Do not invent or echo "
            "citation IDs, ATT&CK IDs, hosts, or IOCs.\n\n"
            f"Analyst question: {state['query']}\n\n"
            f"Evidence summary: {summary}\n\n"
            f"Findings:\n{findings_text}\n\n"
            f"Citation index (reference only, do not repeat verbatim):\n{citation_lines}\n\n"
            "Respond with the summary prose only."
        )
        llm_text = (llm_result.get("text") or "").strip()
        # Guard against degenerate model output (e.g. a mirrored prompt fragment):
        # only accept a substantive summary; otherwise keep the evidence template.
        llm_used = bool(llm_result.get("used")) and len(llm_text) >= 40
        if llm_used:
            summary = llm_text
        elif llm_result.get("error"):
            findings.append(f"LLM summary skipped ({llm_result['error']}); using evidence template instead.")
        elif llm_result.get("used"):
            findings.append("LLM returned an unusable summary; using evidence template instead.")

        limitations = list(state.get("limitations") or [])
        limitations.extend([
            "MITRE ATT&CK mappings are candidate hypotheses requiring analyst validation.",
            "RAG retrieves approved knowledge; it does not train or fine-tune a model.",
            "Response actions are recommendations until an authorized analyst approves them.",
        ])
        if embedding_mode == "offline_hash":
            limitations.append("Knowledge retrieval is running in explicit offline/demo hash-embedding mode, not semantic embeddings.")
        if not llm_used:
            limitations.append("No configured LLM provider was used for this summary.")
        if evidence_weak:
            limitations.append("Evidence was weak or unavailable; confidence was lowered.")

        # This is a measurable field-coverage score, not a probability or vector score.
        coverage_fields = ("hostname", "timestamp", "source", "event_type", "user", "process_name", "command_line")
        expected = len(events) * len(coverage_fields)
        present = sum(bool(event.get(field)) for event in events for field in coverage_fields)
        confidence = round(present / expected, 2) if expected else 0.0
        confidence_rationale = (
            f"Structured telemetry field coverage: {present}/{expected} observed fields. "
            "This is a completeness measure, not a probability of compromise; RAG similarity is excluded."
        )
        missing_data = []
        if not alerts:
            missing_data.append("No matching alert record was retrieved.")
        if not events:
            missing_data.append("No directly correlated event record was retrieved.")
        if not any(e.get("hostname") for e in events):
            missing_data.append("Affected hostname is unavailable in retrieved event telemetry.")
        if not any(e.get("user") for e in events):
            missing_data.append("Affected user is unavailable in retrieved event telemetry.")
        if not any(e.get("parent_process_name") or e.get("parent_process_id") for e in events):
            missing_data.append("Parent process/ancestry telemetry is unavailable.")
        if not any(e.get("process_id") for e in events):
            missing_data.append("Process ID telemetry is unavailable.")
        if not rag_chunks:
            missing_data.append("No tenant knowledge-base guidance matched this query.")

        timeline = [{
            "timestamp": e.get("timestamp").isoformat() if e.get("timestamp") else None,
            "title": f"{e.get('event_type') or 'Security event'} on {e.get('hostname') or 'unknown host'}",
            "event_type": e.get("event_type"),
            "hostname": e.get("hostname"),
            "user": e.get("user"),
            "process_name": e.get("process_name"),
            "command_line": e.get("command_line"),
            "evidence_ref": f"cit_evt_{e['id'][-6:]}",
        } for e in events]
        finding_details = []
        for index, alert in enumerate(alerts):
            event_refs = [f"cit_evt_{event['id'][-6:]}" for event in events if event["id"] in alert.get("event_ids", [])]
            refs = [f"cit_alt_{alert['id'][-6:]}"] + event_refs
            finding_details.append({
                "finding_id": f"finding_{index + 1:03d}",
                "title": alert["title"],
                "status": "suspected",
                "severity": alert.get("severity"),
                "description": alert.get("rule_name") or alert["title"],
                "rationale": "A tenant-scoped alert record and only its host-validated linked events support this finding. Analyst validation is required.",
                "evidence_refs": refs,
                "missing_data": [value for value in missing_data if any(token in value.lower() for token in ("process", "parent", "user"))],
            })
        if not finding_details:
            for index, event in enumerate(events):
                finding_details.append({
                    "finding_id": f"finding_{index + 1:03d}",
                    "title": f"Observed {event['event_type']}",
                    "status": "observed",
                    "severity": event.get("severity"),
                    "description": "This is a source event observation, not a confirmed malicious finding.",
                    "rationale": "The record was retrieved by exact tenant and hostname filters.",
                    "evidence_refs": [f"cit_evt_{event['id'][-6:]}"],
                    "missing_data": [],
                })

        requested_host = state.get("target_hostname")
        excluded = bool(state.get("excluded_evidence"))
        status = "entity_mismatch" if excluded and not (events or alerts) else (
            "needs_validation" if events or alerts else "no_evidence"
        )
        incident_context = dict(state.get("incident_context") or {})
        if alerts and not incident_context.get("alert_id"):
            primary_alert = alerts[0]
            incident_context.update({
                "alert_id": primary_alert["id"],
                "incident_id": primary_alert.get("incident_id"),
                "hostname": primary_alert.get("asset_id"),
                "affected_user": primary_alert.get("affected_user"),
                "severity": primary_alert.get("severity"),
                "alert_status": primary_alert.get("status"),
            })
        incident_context.setdefault("hostname", requested_host or next((e.get("hostname") for e in events if e.get("hostname")), None))
        state["finding_details"] = finding_details
        state["timeline"] = timeline
        state["missing_data"] = missing_data
        state["confidence_rationale"] = confidence_rationale
        state["status"] = status
        state["incident_context"] = incident_context

        state["summary"] = summary
        state["findings"] = findings
        state["cited_evidence"] = citations
        state["recommendations"] = recommendations
        state["confidence"] = confidence
        state["limitations"] = limitations
        state["error"] = None

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
                "limitations": limitations,
                "llm_used": llm_used,
                "llm_provider": llm_result.get("provider"),
                "embedding_mode": embedding_mode,
                "status": status,
                "incident": incident_context,
                "finding_details": finding_details,
                "timeline": timeline,
                "missing_data": missing_data,
                "confidence_rationale": confidence_rationale,
            },
            cited_evidence=citations,
            mitre_mappings=mitre,
            confidence=confidence,
            tenant_id=state["tenant_id"]
        )
        db.add(hist)
        db.commit()
        state["investigation_id"] = hist.id
        return state

    @classmethod
    def run_investigation(
        cls, db: Session, query: str, user_id: str, tenant_id: str = "tenant_default",
        incident_id: Optional[str] = None, alert_id: Optional[str] = None,
        indicator_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        state: InvestigationState = {
            "query": query,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "incident_id": incident_id,
            "alert_id": alert_id,
            "indicator_value": None,
            "target_hostname": None,
            "target_user": None,
            "incident_context": {},
            "excluded_evidence": [],
            "finding_details": [],
            "timeline": [],
            "missing_data": [],
            "confidence_rationale": "",
            "status": "no_evidence",
            "investigation_id": "",
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

        state["indicator_value"] = indicator_value
        graph = StateGraph(InvestigationState)
        graph.add_node("query_understanding", cls.node_query_understanding)
        graph.add_node("structured_retrieval", lambda current: cls.node_evidence_retrieval(current, db=db))
        graph.add_node("context_assembly", cls.node_context_assembly)
        graph.add_node("mitre_candidates", cls.node_analysis_mitre)
        graph.add_node("report_generation", lambda current: cls.node_response_generation(current, db=db))
        graph.set_entry_point("query_understanding")
        graph.add_edge("query_understanding", "structured_retrieval")
        graph.add_edge("structured_retrieval", "context_assembly")
        graph.add_edge("context_assembly", "mitre_candidates")
        graph.add_edge("mitre_candidates", "report_generation")
        graph.add_edge("report_generation", END)
        state = graph.compile().invoke(state)

        return {
            "investigation_id": state.get("investigation_id") or "",
            "query": state["query"],
            "summary": state["summary"],
            "findings": state["findings"],
            "mitre_mappings": state["mitre_hypotheses"],
            "cited_evidence": state["cited_evidence"],
            "recommendations": state["recommendations"],
            "confidence": state["confidence"],
            "limitations": state["limitations"],
            "llm_used": not any("No configured LLM provider was used" in x for x in state.get("limitations") or []),
            "embedding_mode": VectorService.embedding_mode(),
            "timestamp": datetime.now(timezone.utc)
            ,"status": state["status"]
            ,"incident": state["incident_context"]
            ,"executive_summary": state["summary"]
            ,"finding_details": state["finding_details"]
            ,"timeline": state["timeline"]
            ,"indicators": state["retrieved_indicators"]
            ,"missing_data": state["missing_data"]
            ,"confidence_rationale": state["confidence_rationale"]
            ,"sources": [
                {key: citation.get(key) for key in ("citation_id", "source_type", "source_id", "title", "source_ref", "score_type", "relevance_score")}
                for citation in state["cited_evidence"]
            ]
        }
