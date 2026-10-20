from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.mitre import MitreTechniqueRead, MitreMappingHypothesis
from app.services.mitre_service import MitreService

router = APIRouter()


@router.get("/techniques", response_model=List[MitreTechniqueRead])
def get_mitre_techniques(db: Session = Depends(get_db)):
    return MitreService.get_all_techniques(db)


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueRead)
def get_mitre_technique(technique_id: str, db: Session = Depends(get_db)):
    tech = MitreService.get_technique(technique_id, db)
    if not tech:
        raise HTTPException(status_code=404, detail="Technique not found in MITRE ATT&CK reference data.")
    return tech


@router.post("/map", response_model=List[MitreMappingHypothesis])
def map_evidence(evidence_payload: dict, db: Session = Depends(get_db)):
    text = evidence_payload.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="Evidence text payload required.")
    return MitreService.map_evidence_to_mitre(text, db)


@router.post("/sync")
def sync_mitre_attack(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    import httpx
    try:
        result = MitreService.sync_enterprise_attack(db)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Could not sync MITRE ATT&CK: {exc}") from exc
    return {"message": "MITRE ATT&CK enterprise catalog synced.", **result}


@router.get("/matrix")
def get_mitre_matrix(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    tenant_id = current_user.tenant_id

    all_techniques = MitreService.get_all_techniques(db)

    tactic_order = [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]

    incidents = db.query(Incident).filter(Incident.tenant_id == tenant_id).all()
    alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id).all()

    evidence_text_parts = []
    for inc in incidents:
        evidence_text_parts.append(inc.title or "")
        evidence_text_parts.append(inc.description or "")
        for t in inc.mitre_techniques or []:
            evidence_text_parts.append(t)
    for alt in alerts:
        evidence_text_parts.append(alt.title or "")
        evidence_text_parts.append(alt.description or "")
        evidence_text_parts.append(alt.rule_name or "")
    evidence_text = " ".join(evidence_text_parts)

    mappings = MitreService.map_evidence_to_mitre(evidence_text) if evidence_text.strip() else []

    detected_techniques_map: Dict[str, Dict[str, Any]] = {}

    def _add_ref(dmap: Dict, tid: str, key: str, ref: str):
        if tid not in dmap:
            return
        if key not in dmap[tid]:
            dmap[tid][key] = []
        if ref and ref not in dmap[tid][key]:
            dmap[tid][key].append(ref)

    for m in mappings:
        sev = "low"
        if m["confidence"] >= 0.8:
            sev = "critical"
        elif m["confidence"] >= 0.6:
            sev = "high"
        elif m["confidence"] >= 0.4:
            sev = "medium"
        detected_techniques_map[m["technique_id"]] = {
            "technique_id": m["technique_id"],
            "technique_name": m["name"],
            "tactic": m["tactic"],
            "confidence": m["confidence"],
            "severity": sev,
            "rationale": m.get("rationale", ""),
            "related_incident_ids": [],
            "related_alert_ids": [],
        }

    for inc in incidents:
        hit_text = f" {inc.title or ''} {inc.description or ''} ".lower()
        for tech_id in inc.mitre_techniques or []:
            t = MitreService.get_technique(tech_id, db)
            if t and tech_id not in detected_techniques_map:
                detected_techniques_map[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": t["name"],
                    "tactic": t["tactic"],
                    "confidence": 1.0,
                    "severity": inc.severity,
                    "rationale": "Explicitly tagged on incident",
                    "related_incident_ids": [],
                    "related_alert_ids": [],
                }
            if tech_id in detected_techniques_map:
                detected_techniques_map[tech_id]["severity"] = (
                    inc.severity if inc.severity else detected_techniques_map[tech_id].get("severity")
                )
                _add_ref(detected_techniques_map, tech_id, "related_incident_ids", inc.id)

        for m in mappings:
            tid = m["technique_id"]
            kw_any = any(
                (kw and kw in hit_text) for kw in (MitreService.get_technique(tid, db) or {}).get("keywords", [])
            )
            if tid in detected_techniques_map and kw_any:
                _add_ref(detected_techniques_map, tid, "related_incident_ids", inc.id)

    for alt in alerts:
        hit_text = f" {alt.title or ''} {alt.description or ''} {alt.rule_name or ''} ".lower()
        for m in mappings:
            tid = m["technique_id"]
            kw_any = any(
                (kw and kw in hit_text) for kw in (MitreService.get_technique(tid, db) or {}).get("keywords", [])
            )
            if tid in detected_techniques_map and kw_any:
                _add_ref(detected_techniques_map, tid, "related_alert_ids", alt.id)
                if alt.incident_id:
                    _add_ref(detected_techniques_map, tid, "related_incident_ids", alt.incident_id)

    for tid in detected_techniques_map:
        detected_techniques_map[tid]["related_incident_ids"] = list(
            dict.fromkeys(detected_techniques_map[tid].get("related_incident_ids") or [])
        )[:5]
        detected_techniques_map[tid]["related_alert_ids"] = list(
            dict.fromkeys(detected_techniques_map[tid].get("related_alert_ids") or [])
        )[:5]
        detected_techniques_map[tid]["detection_method"] = (
            "Incident tag"
            if detected_techniques_map[tid].get("rationale") == "Explicitly tagged on incident"
            else "Keyword correlation across alerts and incidents"
        )

    tactic_to_techniques: Dict[str, List[Dict[str, Any]]] = {}
    for tactic in tactic_order:
        tactic_to_techniques[tactic] = []

    for tech in all_techniques:
        primary_tactic = tech["tactic"].split(",")[0].strip()
        if primary_tactic not in tactic_to_techniques:
            tactic_to_techniques[primary_tactic] = []
        detected = detected_techniques_map.get(tech["technique_id"])
        entry = {
            "technique_id": tech["technique_id"],
            "name": tech["name"],
            "description": tech["description"],
            "platforms": tech.get("platforms", []),
            "detected": detected is not None,
            "severity": detected["severity"] if detected else None,
            "confidence": detected["confidence"] if detected else None,
            "rationale": detected["rationale"] if detected else None,
            "related_incident_ids": detected["related_incident_ids"] if detected else [],
            "related_alert_ids": detected["related_alert_ids"] if detected else [],
            "detection_method": detected["detection_method"] if detected else None,
        }
        tactic_to_techniques[primary_tactic].append(entry)

    tactics = []
    for tactic in tactic_order:
        techs = tactic_to_techniques.get(tactic, [])
        detected_count = sum(1 for t in techs if t["detected"])
        tactics.append({
            "id": tactic,
            "name": tactic,
            "count": detected_count,
            "techniques": techs,
        })

    return {
        "tactics": tactics,
        "summary": {
            "total_techniques": len(all_techniques),
            "detected_techniques": len(detected_techniques_map),
            "incidents_scanned": len(incidents),
            "alerts_scanned": len(alerts),
        },
    }
