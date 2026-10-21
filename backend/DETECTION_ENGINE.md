# Detection engine notes

## Rule configuration

The engine loads app/detection/rules.v1.json at evaluation time. The document has an explicit version and a constrained JSON condition language (all, any, event-type membership, text checks, token checks, and a process/command check). The loader validates IDs, severities, ATT&CK ID syntax, and operators; invalid configuration fails closed. Rule files cannot execute Python.

Review rule changes with positive and negative fixtures before shipping. For rollback, restore the previous reviewed rule file and its version from source control, then restart the backend. Runtime edits and tenant-authored rules are not supported; there is no rule-change audit table yet.

## Risk score

The 0–100 value is a heuristic risk score, not a calibrated probability of compromise. It starts from rule severity points (low=15, medium=35, high=60, critical=80) and multiplies by 0.65 + 0.35 × evidence-policy confidence. A base-severity floor prevents this provisional scoring from silently downgrading a critical rule. Thresholds are environment settings: RISK_MEDIUM_THRESHOLD=25, RISK_HIGH_THRESHOLD=50, and RISK_CRITICAL_THRESHOLD=75; values must be ordered from 0 through 100.

The event schema does not currently supply trustworthy asset criticality, business impact, process lineage, access-right masks, file-change rates, or validated threat-intelligence context for every alert. Those fields are recorded as unknown/not used; the displayed confidence values are policy-derived estimates and must not be interpreted as calibrated probabilities. Tune scoring only against analyst-reviewed outcomes.

## Persistence and rollout

detection_hits has a unique constraint on (tenant_id, event_db_id, rule_id). This makes repeated and concurrent event evaluation idempotent while preserving existing alert IDs and response fields. The caller owns the SQLAlchemy transaction; event inserts use per-record savepoints.

This repository currently has no Alembic migration history. Startup uses Base.metadata.create_all() for new tables and reconcile_schema() for additive columns. Deploy against a database backup first; verify the new detection_hits table and the five nullable alert columns (base_severity, risk_score, confidence, risk_factors, detection_rule_version) before processing events. Roll back the application and rule file from source control. The schema changes are additive and can remain in place during an application rollback; no destructive down migration is supplied.

Correlation reuses the existing entity/time-window incident grouper, capped by CORRELATION_MAX_ALERTS (default 2000 latest alerts per tenant run). It is not a stream processor and does not yet implement sequence-specific rules such as failed-logon-to-success, LSASS access-to-dump, or file-change-rate detection. No broker or new infrastructure was added.

## Validation

Run focused checks from backend with an isolated SQLite database:

    $env:TEST_DATABASE_URL = "sqlite:///./test_detection_review.db"
    python -m pytest -q tests/test_detection_engine.py

For existing API tests, set DATABASE_URL to the same disposable test database as well as TEST_DATABASE_URL, because app startup probes DATABASE_URL. Remove only the test database created for the run after confirming that it is disposable.
