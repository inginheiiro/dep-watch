"""Integration tests for FastAPI endpoints in main.py."""

from pathlib import Path
import sys
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

import main


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "start_collection_loop", lambda: None)
    main._rate_limit_state.clear()
    with TestClient(main.app) as test_client:
        yield test_client
    main._rate_limit_state.clear()


def test_calculate_version_behind_minor_and_patch():
    assert main.calculate_version_behind("1.2.3", "1.5.0") == 3
    assert main.calculate_version_behind("1.2.3", "1.2.4") == 1


def test_calculate_version_behind_major_jump():
    assert main.calculate_version_behind("1.2.0", "3.1.0") == 2


def test_collect_endpoint_triggers_collection(client, monkeypatch):
    collect_mock = AsyncMock()
    monkeypatch.setattr(main, "collect_all", collect_mock)

    response = client.post("/collect")

    assert response.status_code == 200
    assert response.json()["status"] == "done"
    collect_mock.assert_awaited_once()


def test_reload_endpoint_refreshes_projects(client, monkeypatch):
    new_config = {
        "projects": {
            "demo": {"github": "org/demo", "category": "backend"},
        },
        "known_licenses": {},
        "license_classifications": {
            "high_risk": ["SSPL-1.0"],
            "medium_risk": ["GPL-3.0"],
            "low_risk": ["MIT"],
        },
    }
    monkeypatch.setattr(main, "load_config", lambda: new_config)

    response = client.post("/reload")

    assert response.status_code == 200
    assert response.json() == {"status": "reloaded", "projects": 1}
    assert main.PROJECTS == new_config["projects"]


def test_risks_endpoint_returns_sorted_results(client, monkeypatch):
    monkeypatch.setattr(
        main,
        "PROJECTS",
        {
            "safe": {"github": "org/safe", "category": "backend"},
            "unknown": {"github": "org/unknown", "category": "frontend"},
        },
    )
    monkeypatch.setattr(
        main,
        "load_history",
        lambda: {
            "safe": {"license": "MIT"},
            "unknown": {"license": "unknown"},
        },
    )
    monkeypatch.setattr(main, "KNOWN_LICENSES", {})
    monkeypatch.setattr(main, "HIGH_RISK", {"SSPL-1.0"})
    monkeypatch.setattr(main, "MEDIUM_RISK", {"GPL-3.0"})
    monkeypatch.setattr(main, "LOW_RISK", {"MIT"})

    response = client.get("/risks")

    assert response.status_code == 200
    payload = response.json()
    assert [item["project"] for item in payload["risks"]] == ["unknown", "safe"]
    assert payload["risks"][0]["risk"] == "unknown"
    assert payload["risks"][1]["risk"] == "low"


def test_metrics_endpoint_exposes_prometheus_output(client):
    response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "dep_version_behind" in response.text
    assert "collector_last_run_timestamp" in response.text
