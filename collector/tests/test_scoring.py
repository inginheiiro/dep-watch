"""
Tests for scoring module (license classification, health, sustainability).
"""

import pytest
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# License Classification
# ---------------------------------------------------------------------------

from scoring import classify_license, calc_health, calc_sustainability

KNOWN = {
    "redis/redis": {"license": "RSALv2/SSPL/AGPL-3.0", "risk": 1, "risk_label": "medium"},
    "postgres/postgres": {"license": "PostgreSQL", "risk": 0, "risk_label": "low"},
}
HIGH = {"SSPL-1.0", "BSL-1.1", "Elastic-2.0"}
MEDIUM = {"AGPL-3.0", "GPL-3.0"}
LOW = {"MIT", "Apache-2.0", "BSD-3-Clause"}


class TestClassifyLicense:
    def test_known_license_override(self):
        risk, label, lic = classify_license("NOASSERTION", "redis/redis", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 1
        assert label == "medium"
        assert lic == "RSALv2/SSPL/AGPL-3.0"

    def test_known_license_postgres(self):
        risk, label, lic = classify_license("unknown", "postgres/postgres", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 0
        assert label == "low"
        assert lic == "PostgreSQL"

    def test_mit_is_low_risk(self):
        risk, label, lic = classify_license("MIT", "some/repo", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 0
        assert label == "low"
        assert lic == "MIT"

    def test_apache_is_low_risk(self):
        risk, label, lic = classify_license("Apache-2.0", None, KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 0
        assert label == "low"

    def test_agpl_is_medium_risk(self):
        risk, label, lic = classify_license("AGPL-3.0", "x/y", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 1
        assert label == "medium"

    def test_sspl_is_high_risk(self):
        risk, label, lic = classify_license("SSPL-1.0", "x/y", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 2
        assert label == "high"

    def test_bsl_is_high_risk(self):
        risk, label, lic = classify_license("BSL-1.1", "x/y", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 2
        assert label == "high"

    def test_unknown_spdx_returns_unknown(self):
        risk, label, lic = classify_license("unknown", "x/y", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 3
        assert label == "unknown"
        assert lic == "unknown"

    def test_empty_spdx_returns_unknown(self):
        risk, label, lic = classify_license("", "x/y", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 3
        assert label == "unknown"

    def test_noassertion_returns_unknown(self):
        risk, label, lic = classify_license("NOASSERTION", "x/y", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 3
        assert label == "unknown"

    def test_none_spdx_returns_unknown(self):
        risk, label, lic = classify_license(None, "x/y", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 3
        assert label == "unknown"

    def test_unrecognized_license_returns_unknown(self):
        risk, label, lic = classify_license("SomeCorporate-1.0", "x/y", KNOWN, HIGH, MEDIUM, LOW)
        assert risk == 3
        assert label == "unknown"
        assert lic == "SomeCorporate-1.0"


# ---------------------------------------------------------------------------
# Health Score
# ---------------------------------------------------------------------------

class TestCalcHealth:
    def test_perfect_score(self):
        github = {"archived": False, "release_date": datetime.now(timezone.utc).isoformat()}
        score = calc_health(github, scorecard=10.0, vulns={"critical": 0, "high": 0, "medium": 0})
        assert score == 100.0

    def test_zero_scorecard_deducts_40(self):
        github = {}
        score = calc_health(github, scorecard=0.0, vulns={"critical": 0, "high": 0, "medium": 0})
        assert score == 60.0

    def test_critical_vulns_deduct_15_each(self):
        github = {}
        score = calc_health(github, scorecard=10.0, vulns={"critical": 2, "high": 0, "medium": 0})
        assert score == 70.0

    def test_high_vulns_deduct_10_each(self):
        github = {}
        score = calc_health(github, scorecard=10.0, vulns={"critical": 0, "high": 3, "medium": 0})
        assert score == 70.0

    def test_archived_deducts_20(self):
        github = {"archived": True}
        score = calc_health(github, scorecard=10.0, vulns={"critical": 0, "high": 0, "medium": 0})
        assert score == 80.0

    def test_old_release_deducts_10(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        github = {"release_date": old_date}
        score = calc_health(github, scorecard=10.0, vulns={"critical": 0, "high": 0, "medium": 0})
        assert score == 90.0

    def test_stale_release_deducts_5(self):
        stale_date = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        github = {"release_date": stale_date}
        score = calc_health(github, scorecard=10.0, vulns={"critical": 0, "high": 0, "medium": 0})
        assert score == 95.0

    def test_score_never_below_zero(self):
        github = {"archived": True}
        score = calc_health(github, scorecard=0.0, vulns={"critical": 10, "high": 10, "medium": 10})
        assert score == 0.0

    def test_empty_github_data(self):
        score = calc_health({}, scorecard=5.0, vulns={})
        assert score == 80.0  # 100 - (10-5)*4


# ---------------------------------------------------------------------------
# Sustainability Score
# ---------------------------------------------------------------------------

class TestCalcSustainability:
    def test_perfect_score(self):
        now = datetime.now(timezone.utc).isoformat()
        github = {"contributors": 100, "last_commit": now, "has_funding": True}
        score = calc_sustainability(github, license_risk=0, libs_io={"dependents": 10000})
        assert score == 100.0

    def test_high_risk_license_deducts_35(self):
        now = datetime.now(timezone.utc).isoformat()
        github = {"contributors": 100, "last_commit": now, "has_funding": True}
        score = calc_sustainability(github, license_risk=2, libs_io={"dependents": 10000})
        assert score == 65.0

    def test_medium_risk_license_deducts_20(self):
        now = datetime.now(timezone.utc).isoformat()
        github = {"contributors": 100, "last_commit": now, "has_funding": True}
        score = calc_sustainability(github, license_risk=1, libs_io={"dependents": 10000})
        assert score == 80.0

    def test_unknown_license_deducts_25(self):
        now = datetime.now(timezone.utc).isoformat()
        github = {"contributors": 100, "last_commit": now, "has_funding": True}
        score = calc_sustainability(github, license_risk=3, libs_io={"dependents": 10000})
        assert score == 75.0

    def test_single_contributor_deducts_25(self):
        now = datetime.now(timezone.utc).isoformat()
        github = {"contributors": 1, "last_commit": now, "has_funding": True}
        score = calc_sustainability(github, license_risk=0, libs_io={"dependents": 10000})
        assert score == 75.0

    def test_few_contributors_deducts_15(self):
        now = datetime.now(timezone.utc).isoformat()
        github = {"contributors": 3, "last_commit": now, "has_funding": True}
        score = calc_sustainability(github, license_risk=0, libs_io={"dependents": 10000})
        assert score == 85.0

    def test_inactive_180_days_deducts_20(self):
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        github = {"contributors": 100, "last_commit": old, "has_funding": True}
        score = calc_sustainability(github, license_risk=0, libs_io={"dependents": 10000})
        assert score == 80.0

    def test_no_funding_deducts_10(self):
        now = datetime.now(timezone.utc).isoformat()
        github = {"contributors": 100, "last_commit": now, "has_funding": False}
        score = calc_sustainability(github, license_risk=0, libs_io={"dependents": 10000})
        assert score == 90.0

    def test_low_dependents_deducts_10(self):
        now = datetime.now(timezone.utc).isoformat()
        github = {"contributors": 100, "last_commit": now, "has_funding": True}
        score = calc_sustainability(github, license_risk=0, libs_io={"dependents": 50})
        assert score == 90.0

    def test_medium_dependents_deducts_5(self):
        now = datetime.now(timezone.utc).isoformat()
        github = {"contributors": 100, "last_commit": now, "has_funding": True}
        score = calc_sustainability(github, license_risk=0, libs_io={"dependents": 500})
        assert score == 95.0

    def test_worst_case_scenario(self):
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        github = {"contributors": 1, "last_commit": old, "has_funding": False}
        score = calc_sustainability(github, license_risk=2, libs_io={"dependents": 10})
        assert score == 0.0

    def test_score_never_below_zero(self):
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        github = {"contributors": 0, "last_commit": old, "has_funding": False}
        score = calc_sustainability(github, license_risk=2, libs_io={"dependents": 0})
        assert score == 0.0
