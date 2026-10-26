# AI IDE prompt: add safe identity security assessment to AI SOC Copilot

Copy and paste this into your AI IDE:

```text
You are working in my existing project named AI SOC Copilot (repository: ai-soc-copilot). Extend it with an end-to-end, evidence-grounded Identity Security Assessment capability focused on password-policy risk, MFA coverage, and suspicious authentication activity.

First inspect the existing architecture and instructions (AGENTS.md, README, backend/frontend structure, database models, ingestion routes, detection rules, authentication, tenant isolation, audit logging, and tests). Preserve existing behavior and project conventions. Do not replace working components with mock/demo implementations. Before changing code, report what data the current project actually has and identify missing authoritative identity-provider sources.

GOAL AND DATA SOURCES
1. Treat authentication facts and configuration posture as different data:
   - Event telemetry: successful/failed sign-ins, MFA challenge/result, MFA-denied or fatigue signals, password-reset events, account lockouts, source IP/device/location, identity-provider risk signals, and relevant Windows identity events.
   - Configuration posture: tenant password policy, MFA registration/enforcement coverage, conditional-access/authentication policy, privileged-account exceptions, break-glass accounts, and policy/configuration snapshots.
2. Prefer supported, read-only connectors or documented import formats for Microsoft Entra ID, Okta, and Keycloak. Make each integration optional and clearly show connection/permission/data-freshness status. Support normalized JSON/CSV fixtures for local development, labeled as simulated. Never label fixtures or replayed public attack data as live.
3. Add source, tenant, event time, ingestion time, provider record ID, simulation flag, and provenance to normalized records. Enforce tenant scoping in every query and test cross-tenant isolation.

DETECTIONS AND ASSESSMENTS
Implement explainable, versioned rules for:
- Weak password-policy configuration (for example minimum length or prohibited-password controls) using the provider's policy configuration, with configurable policy thresholds and a citation to the setting. Never claim an individual user's password is weak based only on sign-in logs.
- Missing or unenforced MFA, low enrollment coverage, privileged accounts without MFA, and risky/excessive MFA exclusions. Exempt approved break-glass accounts only when explicitly configured and display the exception.
- Repeated failed sign-ins, password-spray-like patterns, impossible-travel/provider risk events, MFA push fatigue/denial, suspicious successful login following failures, and suspicious authentication after password reset. Use documented, configurable windows and thresholds; correlate on actual account, IP, device, and timestamps. Do not infer a brute-force attack from one failure.
- Map relevant findings to MITRE ATT&CK as candidates with evidence and data-source coverage; do not claim confirmation from a keyword match alone.

Every result must distinguish observed facts, policy findings, heuristics, and analyst hypotheses. Include severity rationale, rule ID/version, contributing events/configuration, time window, counts and thresholds, source/provider, timestamps, evidence references, confidence semantics, false-positive considerations, and missing/stale data. Never fabricate risk values or label missing telemetry as safe.

SAFE PASSWORD HANDLING
- Never ingest, display, log, store, or send plaintext passwords, password hashes, reset tokens, or MFA secrets to the LLM, vector store, logs, or analytics. Redact sensitive fields at ingestion and API serialization.
- Assess password strength through policy settings, approved breach-screening provider status, and password-reset/security telemetry. Do not ask users for real passwords, attempt credential guesses, crack hashes, or perform password spraying against real services.
- Add secure app-login MFA only if it fits the existing product requirements: implement a proper enrollment and challenge flow using a maintained TOTP/WebAuthn library, recovery codes hashed at rest, rate limits, audit events, secure secret encryption, migration/backward compatibility, and tests. Do not simulate a successful second factor or silently bypass it. Keep SOC-analyst MFA requirements separate from findings about monitored customer tenants.

SOC COPILOT AND RAG
- Keep exact tenant-scoped SQL retrieval as the source for alert/event facts. Use RAG only for approved, tenant-scoped policy documents, provider documentation, and response playbooks. Add source/version/retrieval date citations and a relevance score labeled as retrieval relevance, never incident confidence.
- LangGraph should orchestrate: request validation -> tenant-scoped posture/event retrieval -> evidence validation/correlation -> optional RAG guidance retrieval -> candidate detection mapping -> structured report -> audit/history. Keep risky response actions human-approved and unexecuted by default.
- If LangChain is added, use it for actual document/retriever abstractions and explain its role. Do not claim LangChain is used just because it is installed. Do not let LLM/RAG invent sign-in events, policy settings, severity, or MITRE evidence.

FRONTEND
Add an Identity Security workspace showing MFA coverage, privileged-account exceptions, password-policy findings, authentication trends, source freshness, and evidence-backed alerts. Every statistic must come from API data and show its denominator/time window. Provide drill-down from a finding to the underlying records and policy settings. Clearly label simulated fixtures. Show missing provider permissions/data as unknown, not zero risk.

API AND QUALITY
- Add typed request/response schemas and documented endpoints.
- Make imports idempotent, validate timestamps and provider payloads, redact secrets, and return record-level validation errors without echoing sensitive fields.
- Add tests for thresholds and time-window boundaries, MFA exclusion handling, identity correlation, malformed/stale input, secret redaction, tenant isolation, and frontend loading/empty/error states. Use synthetic local fixtures only.
- Run focused backend tests, frontend type checking, and relevant existing checks. Fix regressions. Update setup/configuration docs with least-privilege read-only connector permissions, environment variables, migration steps, and safe local demo instructions. Never put real tokens or credentials in source control.

ETHICAL AND AUTHORIZATION BOUNDARIES
This feature is for defensive monitoring and authorized assessment of systems/accounts the organization owns or is explicitly permitted to assess. Do not add exploit execution, credential harvesting, password guessing/cracking, MFA bypass, stealth, persistence, or testing against third-party accounts/services. For active security tests, require an explicitly configured lab or documented authorization and use synthetic test identities. Record who initiated an assessment and its scope.

DELIVERABLES
Implement the feature in the existing AI SOC Copilot codebase; do not only provide a plan. Summarize changed files, data sources actually supported, what is still unavailable, setup steps, API response example, security limitations, and test results. Be honest if an integration cannot be completed without provider credentials or permissions; build a documented connector interface and safe fixture path rather than inventing live data.
```

This is mainly a defensive identity-security and configuration assessment feature. It is ethical hacking only when active tests are explicitly authorized and kept within the approved scope; the prompt deliberately excludes real-world password guessing and MFA bypass.
