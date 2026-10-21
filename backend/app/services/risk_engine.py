"""Explainable heuristic risk scoring; scores are not probabilities of compromise."""
from typing import Any, Dict

from app.core.config import settings

SEVERITY_POINTS = {"low": 15, "medium": 35, "high": 60, "critical": 80}
CONFIDENCE_BY_POLICY = {
    "explicit_detection": 0.90,
    "explicit_action": 0.85,
    "explicit_event_type": 0.75,
    "specific_command": 0.80,
    "specific_behavior": 0.70,
    "structured_text": 0.60,
    "source_severity": 0.55,
}


class RiskEngine:
    @staticmethod
    def score(base_severity: str, confidence_policy: str, *, evidence_present: bool = True) -> Dict[str, Any]:
        """Compute a transparent provisional score from rule severity and evidence quality.

        No asset criticality, impact, TI, or cross-event behavior is inferred because the
        normalized schema does not yet provide reliable values for those dimensions.
        """
        severity = str(base_severity or "").lower()
        if severity not in SEVERITY_POINTS:
            severity = "low"
        confidence = CONFIDENCE_BY_POLICY.get(confidence_policy, 0.50) if evidence_present else 0.0
        # Preserve a meaningful floor for explicit high-confidence detections.
        raw_score = SEVERITY_POINTS[severity] * (0.65 + 0.35 * confidence)
        score = max(0, min(100, round(raw_score)))
        thresholds = (
            int(settings.RISK_MEDIUM_THRESHOLD),
            int(settings.RISK_HIGH_THRESHOLD),
            int(settings.RISK_CRITICAL_THRESHOLD),
        )
        if not (0 <= thresholds[0] <= thresholds[1] <= thresholds[2] <= 100):
            raise ValueError("Risk thresholds must be ordered integers between 0 and 100.")
        final = "critical" if score >= thresholds[2] else "high" if score >= thresholds[1] else "medium" if score >= thresholds[0] else "low"
        # Keep confirmed rule severity floor: weak score math cannot downgrade a critical rule.
        rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if rank[severity] > rank[final]:
            final = severity
        return {
            "base_severity": severity,
            "risk_score": score,
            "confidence": round(confidence, 2),
            "severity": final,
            "risk_factors": {
                "rule_base_severity": severity,
                "evidence_policy": confidence_policy,
                "evidence_present": evidence_present,
                "asset_criticality": "unknown",
                "potential_impact": "unknown",
                "threat_intelligence": "not_used",
                "correlated_activity": "not_used",
                "score_label": "heuristic_not_calibrated_probability",
            },
        }
