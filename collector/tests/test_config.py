"""
Tests for configuration loading and OSV package name resolution.
"""

import pytest
import yaml
from pathlib import Path


CONFIG_FILE = Path(__file__).parent.parent / "projects.yml"


class TestProjectsYml:
    @pytest.fixture(autouse=True)
    def load_config(self):
        with open(CONFIG_FILE, "r") as f:
            self.config = yaml.safe_load(f)

    def test_config_loads_successfully(self):
        assert self.config is not None

    def test_has_projects(self):
        assert "projects" in self.config
        assert len(self.config["projects"]) > 0

    def test_has_known_licenses(self):
        assert "known_licenses" in self.config

    def test_has_license_classifications(self):
        assert "license_classifications" in self.config
        lc = self.config["license_classifications"]
        assert "high_risk" in lc
        assert "medium_risk" in lc
        assert "low_risk" in lc

    def test_all_projects_have_required_fields(self):
        for pid, cfg in self.config["projects"].items():
            assert "github" in cfg, f"{pid} missing 'github'"
            assert "category" in cfg, f"{pid} missing 'category'"
            assert "/" in cfg["github"], f"{pid} github must be 'owner/repo' format"

    def test_categories_are_valid(self):
        valid = {"infrastructure", "frontend", "backend"}
        for pid, cfg in self.config["projects"].items():
            assert cfg["category"] in valid, f"{pid} has invalid category '{cfg['category']}'"

    def test_known_licenses_have_required_fields(self):
        for repo, info in self.config["known_licenses"].items():
            assert "license" in info, f"{repo} missing 'license'"
            assert "risk" in info, f"{repo} missing 'risk'"
            assert "risk_label" in info, f"{repo} missing 'risk_label'"
            assert info["risk"] in (0, 1, 2), f"{repo} risk must be 0, 1, or 2"
            assert info["risk_label"] in ("low", "medium", "high"), f"{repo} invalid risk_label"

    def test_no_duplicate_license_classes(self):
        lc = self.config["license_classifications"]
        high = set(lc["high_risk"])
        medium = set(lc["medium_risk"])
        low = set(lc["low_risk"])
        assert not high & medium, f"Overlap high/medium: {high & medium}"
        assert not high & low, f"Overlap high/low: {high & low}"
        assert not medium & low, f"Overlap medium/low: {medium & low}"

    def test_ecosystem_values_are_valid(self):
        valid = {None, "npm", "Maven", "Go", "PyPI"}
        for pid, cfg in self.config["projects"].items():
            eco = cfg.get("ecosystem")
            assert eco in valid, f"{pid} has invalid ecosystem '{eco}'"


# ---------------------------------------------------------------------------
# OSV package name resolution
# ---------------------------------------------------------------------------

# Import from the parent collector package
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from main import get_osv_package_name


class TestGetOsvPackageName:
    def test_npm_returns_project_id(self):
        cfg = {"ecosystem": "npm"}
        assert get_osv_package_name("vue", cfg) == "vue"

    def test_maven_returns_group_artifact(self):
        cfg = {"ecosystem": "Maven", "libraries_io": "maven/org.springframework.boot:spring-boot"}
        assert get_osv_package_name("spring-boot", cfg) == "org.springframework.boot:spring-boot"

    def test_go_returns_module_path(self):
        cfg = {"ecosystem": "Go", "libraries_io": "go/github.com%2Fminio%2Fminio-go"}
        assert get_osv_package_name("minio", cfg) == "github.com/minio/minio-go"

    def test_no_ecosystem_returns_none(self):
        cfg = {"ecosystem": None}
        assert get_osv_package_name("redis", cfg) is None

    def test_missing_ecosystem_returns_none(self):
        cfg = {}
        assert get_osv_package_name("redis", cfg) is None

    def test_unknown_ecosystem_returns_project_id(self):
        cfg = {"ecosystem": "PyPI"}
        assert get_osv_package_name("requests", cfg) == "requests"
