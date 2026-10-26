# AI SOC Copilot investigation pipeline

## Why RAG belongs here

SOC investigations need both incident facts and operational guidance. Alerts, endpoint events, users, timestamps, and incident status are exact records, so the Copilot retrieves them with tenant-scoped database filters. RAG is useful for the separate question, “What approved procedure or threat reference applies to these facts?” It finds relevant chunks from the tenant's knowledge base and returns source references that an analyst can verify.

RAG helps keep guidance current as playbooks and threat references change, and makes the answer traceable to retrieved sources. It does not train or fine-tune a model, create incident facts, prove a detection, or execute containment. The optional language model currently summarizes the evidence; it does not replace database retrieval or rule-based MITRE candidate mapping.

## What happens after an analyst clicks Investigate

1. The frontend sends the analyst's text and optional `alert_id`/`incident_id` to `POST /api/v1/copilot/query` with the logged-in user's bearer token.
2. The backend limits alert, incident, and event reads to the user's tenant. Identifier-based investigations retrieve the requested object and its linked records. A hostname in the query becomes an exact host filter; evidence from a different or unknown host is excluded and reported.
3. In a separate step, the backend embeds the query, ranks that tenant's knowledge chunks by cosine similarity, and retrieves up to three chunks. Only these knowledge citations have a similarity score. The score is not attack confidence.
4. MITRE techniques are emitted as candidates only when retrieved alert/event text matches the current mapping logic. A candidate requires analyst validation.
5. The response includes evidence-linked findings, a timeline, missing fields, knowledge-source citations, proposed next steps, and explicit limitations. The investigation is saved to history.

The graph is implemented with LangGraph `StateGraph`. Retrieval itself is currently a project-specific SQL plus cosine-similarity service. `langchain-core` is a dependency, but this workflow does not use a LangChain retriever or chain; the API should not claim that it does.

## Response shape

The endpoint preserves the original fields (`summary`, `findings`, `mitre_mappings`, `cited_evidence`, `recommendations`, and `confidence`) and adds structured investigation fields:

```json
{
  "investigation_id": "inv_…",
  "status": "needs_validation",
  "incident": {
    "alert_id": "alt_…",
    "incident_id": null,
    "hostname": "WORKSTATION-089",
    "affected_user": "analyst",
    "severity": "high",
    "alert_status": "new"
  },
  "executive_summary": "A short summary based only on retrieved evidence.",
  "finding_details": [{
    "finding_id": "finding_001",
    "title": "Observed alert title",
    "status": "suspected",
    "severity": "high",
    "description": "What the record says",
    "rationale": "Why this record supports the finding",
    "evidence_refs": ["cit_alt_…", "cit_evt_…"],
    "missing_data": ["Parent process/ancestry telemetry is unavailable."]
  }],
  "timeline": [{
    "timestamp": "2026-10-26T10:20:00Z",
    "title": "process_creation on WORKSTATION-089",
    "evidence_ref": "cit_evt_…"
  }],
  "mitre_mappings": [{
    "technique_id": "T1059.001",
    "technique_name": "PowerShell",
    "status": "candidate",
    "match_score": 0.5,
    "confidence": null,
    "evidence_refs": ["cit_evt_…"]
  }],
  "cited_evidence": [{
    "citation_id": "cit_kb_…",
    "source_type": "knowledge_base",
    "source_id": "chk_…",
    "title": "Approved playbook: response guidance",
    "snippet": "Retrieved source excerpt",
    "relevance_score": 0.73,
    "score_type": "cosine_similarity",
    "source_ref": "https://…"
  }],
  "recommendations": [{
    "category": "investigative",
    "title": "Validate the process ancestry",
    "rationale": "Why this step is suggested",
    "evidence_refs": ["cit_evt_…"],
    "prerequisites": ["Analyst validates the target"],
    "expected_outcome": "Confirm or refute the process relationship",
    "status": "proposed",
    "requires_approval": false
  }],
  "missing_data": ["Process ID telemetry is unavailable."],
  "confidence": 0.86,
  "confidence_rationale": "Structured telemetry field coverage: 6/7 observed fields. This is completeness, not compromise probability.",
  "embedding_mode": "semantic",
  "llm_used": true
}
```

An alert/event citation has no vector relevance score because it is selected by exact record filters. A knowledge citation may have `relevance_score` and `source_ref`. `confidence` is a telemetry-field coverage measure, and the MITRE `match_score` is a rule match score; neither is a calibrated probability.

## Configuration and limits

- `EMBEDDING_PROVIDER=gemini` plus `GEMINI_API_KEY` enables semantic embeddings. The default `mock` provider is deterministic offline hash embedding and must not be presented as semantic RAG.
- The LLM provider is optional. With no configured provider the workflow returns an evidence-template summary.
- Knowledge results are limited to the authenticated tenant. Their quality depends on the documents ingested, source metadata, and embedding provider.
- The current MITRE mapper is keyword-based. It proposes candidates and needs analyst review; it is not a full ATT&CK behavioral correlation engine.
- Recommendations are proposals. This workflow does not isolate hosts, block indicators, close incidents, or perform other response actions.
- The current login uses email/password and JWT but has no MFA flow. The investigation pipeline also does not yet collect authoritative identity-provider password-policy or MFA-enrollment data. Do not infer that an account has a weak password or lacks MFA from a generic login event alone.

For a scoped defensive identity-security extension and an AI IDE implementation prompt, see [`SECURITY_ASSESSMENT_IDE_PROMPT.md`](../SECURITY_ASSESSMENT_IDE_PROMPT.md).
