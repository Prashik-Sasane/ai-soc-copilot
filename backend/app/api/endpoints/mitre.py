from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from app.schemas.mitre import MitreTechniqueRead, MitreMappingHypothesis
from app.services.mitre_service import MitreService

router = APIRouter()


@router.get("/techniques", response_model=List[MitreTechniqueRead])
def get_mitre_techniques():
    return MitreService.get_all_techniques()


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueRead)
def get_mitre_technique(technique_id: str):
    tech = MitreService.get_technique(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail="Technique not found in MITRE ATT&CK reference data.")
    return tech


@router.post("/map", response_model=List[MitreMappingHypothesis])
def map_evidence(evidence_payload: dict):
    text = evidence_payload.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="Evidence text payload required.")
    return MitreService.map_evidence_to_mitre(text)
