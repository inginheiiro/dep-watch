"""
Score calculation and license classification for the Infra Dependency Monitor.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def classify_license(
    spdx: str,
    github_repo: str,
    known_licenses: dict,
    high_risk: set,
    medium_risk: set,
    low_risk: set,
) -> tuple[int, str, str]:
    """Classify a license by risk level.

    Returns:
        (risk_value, risk_label, actual_license)
        risk_value: 0=low, 1=medium, 2=high, 3=unknown
    """
    if github_repo and github_repo in known_licenses:
        info = known_licenses[github_repo]
        return info["risk"], info["risk_label"], info["license"]

    if not spdx or spdx in ("unknown", "NOASSERTION", "OTHER", ""):
        return 3, "unknown", "unknown"

    spdx_upper = spdx.upper()
    for lic in high_risk:
        if lic.upper() in spdx_upper:
            return 2, "high", spdx
    for lic in medium_risk:
        if lic.upper() in spdx_upper:
            return 1, "medium", spdx
    for lic in low_risk:
        if lic.upper() in spdx_upper:
            return 0, "low", spdx

    return 3, "unknown", spdx


def calc_health(github: dict, scorecard: float, vulns: dict) -> float:
    """Calculate health score (0-100).

    Based on security score, vulnerabilities, archived status, and release freshness.
    """
    score = 100.0
    score -= (10 - scorecard) * 4
    score -= vulns.get("critical", 0) * 15
    score -= vulns.get("high", 0) * 10
    score -= vulns.get("medium", 0) * 3

    if github.get("archived"):
        score -= 20

    if github.get("release_date"):
        try:
            rd = datetime.fromisoformat(github["release_date"].replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - rd).days
            if days > 365:
                score -= 10
            elif days > 180:
                score -= 5
        except (ValueError, TypeError):
            pass

    return max(0.0, min(100.0, score))


def calc_sustainability(github: dict, license_risk: int, libs_io: dict) -> float:
    """Calculate sustainability score (0-100).

    Based on license risk, bus factor, activity, funding, and popularity.
    """
    score = 100.0

    if license_risk == 2:
        score -= 35
    elif license_risk == 1:
        score -= 20
    elif license_risk == 3:
        score -= 25

    contribs = github.get("contributors", 0)
    if contribs <= 1:
        score -= 25
    elif contribs <= 3:
        score -= 15
    elif contribs <= 10:
        score -= 5

    if github.get("last_commit"):
        try:
            lc = datetime.fromisoformat(github["last_commit"].replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - lc).days
            if days > 180:
                score -= 20
            elif days > 90:
                score -= 10
            elif days > 30:
                score -= 5
        except (ValueError, TypeError):
            pass

    if not github.get("has_funding"):
        score -= 10

    if libs_io.get("dependents", 0) < 100:
        score -= 10
    elif libs_io.get("dependents", 0) < 1000:
        score -= 5

    return max(0.0, min(100.0, score))
