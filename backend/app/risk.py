"""Transparent internal remediation-priority heuristic (not CVSS)."""

SEVERITY_IMPACT = {"critical": 95, "high": 80, "medium": 60, "low": 30, "info": 10}
SEVERITY_LIKELIHOOD = {"critical": 90, "high": 75, "medium": 60, "low": 40, "info": 20}
CONFIDENCE_VALUE = {"high": 90, "medium": 65, "low": 35}


def calculate_priority_score(
    severity: str,
    confidence: str,
    *,
    exposure: int = 75,
    asset_criticality: int = 50,
) -> int:
    """Return a 0-100 internal score; this is not a CVSS score or substitute."""
    if not 0 <= exposure <= 100 or not 0 <= asset_criticality <= 100:
        raise ValueError("exposure and asset_criticality must be between 0 and 100")
    impact = SEVERITY_IMPACT.get(severity.lower(), 10)
    likelihood = SEVERITY_LIKELIHOOD.get(severity.lower(), 20)
    confidence_value = CONFIDENCE_VALUE.get(confidence.lower(), 35)
    score = (
        0.35 * impact
        + 0.25 * likelihood
        + 0.15 * exposure
        + 0.15 * asset_criticality
        + 0.10 * confidence_value
    )
    return max(0, min(100, round(score)))
