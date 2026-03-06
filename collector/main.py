"""
Infrastructure Dependency Health Collector
100% Automatic monitoring - configuration in projects.yml

Entrypoint: FastAPI application with background collection loop.
"""

import os
import time
import json
import logging
import threading
import asyncio
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, Request, HTTPException
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

from scoring import classify_license, calc_health, calc_sustainability
from collector import Collector
from metrics import (
    license_risk as license_risk_gauge,
    license_changed,
    security_score,
    vulnerabilities,
    days_since_commit,
    days_since_release,
    is_archived,
    github_stars,
    github_forks,
    contributors,
    dependents,
    source_rank,
    current_version_info,
    latest_version_info,
    version_behind,
    has_funding,
    health_score,
    sustainability_score,
    collection_errors,
    last_collection,
)

# =============================================================================
# Structured Logging
# =============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv(
    "LOG_FORMAT",
    "%(asctime)s %(levelname)s %(name)s %(message)s",
)
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format=LOG_FORMAT)
logger = logging.getLogger("infra-monitor")

# Paths
CONFIG_FILE = Path(__file__).parent / "projects.yml"
DATA_DIR = Path("/data")
LICENSE_HISTORY_FILE = DATA_DIR / "license_history.json"

# =============================================================================
# Rate Limiting (simple in-memory, per-endpoint)
# =============================================================================

_rate_limit_state: dict[str, float] = {}
RATE_LIMIT_SECONDS = int(os.getenv("RATE_LIMIT_SECONDS", "30"))


def _check_rate_limit(key: str) -> None:
    """Raise HTTP 429 if the endpoint was called too recently."""
    now = time.monotonic()
    last = _rate_limit_state.get(key, 0.0)
    if now - last < RATE_LIMIT_SECONDS:
        remaining = int(RATE_LIMIT_SECONDS - (now - last))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limited. Retry in {remaining}s.",
        )
    _rate_limit_state[key] = now


# =============================================================================
# Configuration
# =============================================================================


def load_config() -> dict:
    """Load configuration from projects.yml."""
    try:
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error("Failed to load config: %s", e)
        return {"projects": {}, "known_licenses": {}, "license_classifications": {}}


def _unpack_config(config: dict) -> tuple:
    projects = config.get("projects", {})
    known = config.get("known_licenses", {})
    classes = config.get("license_classifications", {})
    high = set(classes.get("high_risk", []))
    medium = set(classes.get("medium_risk", []))
    low = set(classes.get("low_risk", []))
    return projects, known, high, medium, low


config = load_config()
PROJECTS, KNOWN_LICENSES, HIGH_RISK, MEDIUM_RISK, LOW_RISK = _unpack_config(config)
logger.info("Loaded %d projects from config", len(PROJECTS))

collector = Collector()
_collection_thread: Optional[threading.Thread] = None
_collection_thread_lock = threading.Lock()

# =============================================================================
# License History
# =============================================================================


def load_history() -> dict:
    try:
        if LICENSE_HISTORY_FILE.exists():
            return json.loads(LICENSE_HISTORY_FILE.read_text())
    except Exception:
        pass
    return {}


def save_history(history: dict) -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        LICENSE_HISTORY_FILE.write_text(json.dumps(history, indent=2))
    except Exception as e:
        logger.error("Could not save history: %s", e)


# =============================================================================
# OSV helpers
# =============================================================================


def get_osv_package_name(project_id: str, cfg: dict) -> Optional[str]:
    """Get package name for OSV query based on ecosystem."""
    ecosystem = cfg.get("ecosystem")
    if not ecosystem:
        return None

    if ecosystem == "npm":
        return project_id

    if ecosystem == "Maven":
        libs_io = cfg.get("libraries_io", "")
        if libs_io and libs_io.startswith("maven/"):
            return libs_io.replace("maven/", "")
        return None

    if ecosystem == "Go":
        libs_io = cfg.get("libraries_io", "")
        if libs_io and libs_io.startswith("go/"):
            return libs_io.replace("go/", "").replace("%2F", "/")
        return None

    return project_id


def calculate_version_behind(current_version: str, latest_version: str) -> int:
    """Estimate how many major/minor steps the current version is behind."""
    if not current_version or not latest_version:
        return 0

    def _parse(version: str) -> Optional[tuple[int, int, int]]:
        match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(version))
        if not match:
            return None
        major = int(match.group(1))
        minor = int(match.group(2) or 0)
        patch = int(match.group(3) or 0)
        return major, minor, patch

    current = _parse(current_version)
    latest = _parse(latest_version)
    if not current or not latest or latest <= current:
        return 0

    current_major, current_minor, current_patch = current
    latest_major, latest_minor, latest_patch = latest

    if latest_major > current_major:
        return (latest_major - current_major) + max(latest_minor - current_minor, 0)

    if latest_minor > current_minor:
        return latest_minor - current_minor

    return 1 if latest_patch > current_patch else 0


# =============================================================================
# Collection
# =============================================================================


async def collect_all() -> None:
    """Collect metrics for all projects."""
    logger.info("Starting collection for %d projects...", len(PROJECTS))
    history = load_history()

    for project_id, cfg in PROJECTS.items():
        try:
            cat = cfg["category"]
            repo = cfg["github"]
            ecosystem = cfg.get("ecosystem")
            current_version = cfg.get("current_version")
            osv_package = get_osv_package_name(project_id, cfg)

            async def empty_osv():
                return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

            github_raw, scorecard_raw, osv_raw, libs_raw = await asyncio.gather(
                collector.fetch_github(repo),
                collector.fetch_scorecard(repo),
                (
                    collector.fetch_osv(osv_package, ecosystem, current_version)
                    if osv_package
                    else empty_osv()
                ),
                collector.fetch_libraries_io(cfg.get("libraries_io")),
                return_exceptions=True,
            )

            github_data = github_raw if isinstance(github_raw, dict) else {}
            scorecard_val = float(scorecard_raw) if isinstance(scorecard_raw, (int, float)) else 0.0
            osv_vulns = osv_raw if isinstance(osv_raw, dict) else {}
            libs_data = libs_raw if isinstance(libs_raw, dict) else {}

            # License classification
            detected_license = github_data.get("license", "unknown")
            risk_val, risk_label, current_license = classify_license(
                detected_license, repo, KNOWN_LICENSES, HIGH_RISK, MEDIUM_RISK, LOW_RISK,
            )
            license_risk_gauge.labels(
                project=project_id, category=cat, license=current_license,
            ).set(risk_val)

            # License change detection
            prev_license = history.get(project_id, {}).get("license")
            changed = 1 if (
                prev_license and prev_license != current_license and current_license != "unknown"
            ) else 0
            license_changed.labels(project=project_id, category=cat).set(changed)
            if changed:
                logger.warning(
                    "LICENSE CHANGE: %s %s -> %s", project_id, prev_license, current_license,
                )

            history[project_id] = {
                "license": current_license,
                "first_seen": history.get(project_id, {}).get(
                    "first_seen", datetime.now(timezone.utc).isoformat(),
                ),
                "last_checked": datetime.now(timezone.utc).isoformat(),
            }

            # Security
            security_score.labels(project=project_id, category=cat).set(scorecard_val)
            for sev in ["critical", "high", "medium", "low"]:
                vulnerabilities.labels(
                    project=project_id, category=cat, severity=sev,
                ).set(osv_vulns.get(sev, 0))

            # Activity
            if github_data.get("last_commit"):
                try:
                    lc = datetime.fromisoformat(
                        github_data["last_commit"].replace("Z", "+00:00"),
                    )
                    days_since_commit.labels(project=project_id, category=cat).set(
                        (datetime.now(timezone.utc) - lc).days,
                    )
                except (ValueError, TypeError):
                    pass

            if github_data.get("release_date"):
                try:
                    rd = datetime.fromisoformat(
                        github_data["release_date"].replace("Z", "+00:00"),
                    )
                    days_since_release.labels(project=project_id, category=cat).set(
                        (datetime.now(timezone.utc) - rd).days,
                    )
                except (ValueError, TypeError):
                    pass

            is_archived.labels(project=project_id, category=cat).set(
                1 if github_data.get("archived") else 0,
            )

            # Community
            github_stars.labels(project=project_id, category=cat).set(
                github_data.get("stars", 0),
            )
            github_forks.labels(project=project_id, category=cat).set(
                github_data.get("forks", 0),
            )
            contributors.labels(project=project_id, category=cat).set(
                github_data.get("contributors", 0),
            )
            dependents.labels(project=project_id, category=cat).set(
                libs_data.get("dependents", 0),
            )
            source_rank.labels(project=project_id, category=cat).set(
                libs_data.get("source_rank", 0),
            )

            # Version tracking
            if current_version:
                current_version_info.labels(
                    project=project_id, category=cat, version=current_version,
                ).set(1)
                latest_ver = github_data.get("latest_tag", "unknown")
                if latest_ver and latest_ver != "unknown":
                    latest_version_info.labels(
                        project=project_id, category=cat, version=latest_ver,
                    ).set(1)
                    version_behind.labels(project=project_id, category=cat).set(
                        calculate_version_behind(current_version, latest_ver),
                    )
                else:
                    version_behind.labels(project=project_id, category=cat).set(0)

            # Funding
            has_funding.labels(project=project_id, category=cat).set(
                1 if github_data.get("has_funding") else 0,
            )

            # Scores
            health = calc_health(github_data, scorecard_val, osv_vulns)
            sustain = calc_sustainability(github_data, risk_val, libs_data)
            health_score.labels(project=project_id, category=cat).set(health)
            sustainability_score.labels(project=project_id, category=cat).set(sustain)

            vuln_count = osv_vulns.get("total", 0)
            ver_info = f" v{current_version}" if current_version else ""
            vuln_info = f" vulns={vuln_count}" if vuln_count > 0 else ""
            logger.info(
                "%s%s: health=%.0f sustain=%.0f license=%s(%s)%s",
                project_id, ver_info, health, sustain, current_license, risk_label, vuln_info,
            )

        except Exception as e:
            logger.error("Error collecting %s: %s", project_id, e)
            collection_errors.labels(project=project_id, source="collector").inc()

    save_history(history)
    last_collection.set(time.time())
    logger.info("Collection complete")


# =============================================================================
# Background Loop
# =============================================================================


def run_collection_loop() -> None:
    interval = int(os.getenv("COLLECT_INTERVAL", 86400))
    while True:
        try:
            asyncio.run(collect_all())
        except Exception as e:
            logger.error("Collection loop error: %s", e)
        time.sleep(interval)


def start_collection_loop() -> None:
    global _collection_thread

    with _collection_thread_lock:
        if _collection_thread and _collection_thread.is_alive():
            return
        _collection_thread = threading.Thread(target=run_collection_loop, daemon=True)
        _collection_thread.start()


@asynccontextmanager
async def lifespan(_: FastAPI):
    start_collection_loop()
    yield


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(title="Infra Dependency Monitor", lifespan=lifespan)

# =============================================================================
# API Endpoints
# =============================================================================


@app.get("/")
async def root():
    return {
        "service": "Infra Dependency Monitor",
        "version": "3.0",
        "projects": len(PROJECTS),
        "config_file": str(CONFIG_FILE),
        "endpoints": ["/metrics", "/health", "/risks", "/projects", "/collect", "/reload"],
    }


@app.get("/metrics")
async def get_metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def get_health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/projects")
async def get_projects():
    """List all monitored projects."""
    return {"projects": PROJECTS, "count": len(PROJECTS)}


@app.get("/risks")
async def get_risks():
    """Get all projects sorted by risk."""
    history = load_history()
    risks = []

    for pid, cfg in PROJECTS.items():
        detected_lic = history.get(pid, {}).get("license", "unknown")
        risk_val, risk_label, actual_lic = classify_license(
            detected_lic, cfg["github"], KNOWN_LICENSES, HIGH_RISK, MEDIUM_RISK, LOW_RISK,
        )
        risks.append({
            "project": pid,
            "category": cfg["category"],
            "detected_license": detected_lic,
            "actual_license": actual_lic,
            "risk": risk_label,
            "risk_value": risk_val,
        })

    risks.sort(key=lambda x: -x["risk_value"])
    return {
        "risks": risks,
        "known_overrides": {k: v["license"] for k, v in KNOWN_LICENSES.items()},
    }


@app.post("/collect")
async def trigger_collect():
    """Trigger an immediate collection (rate-limited)."""
    _check_rate_limit("collect")
    await collect_all()
    return {"status": "done", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/reload")
async def reload_config():
    """Reload configuration from YAML file (rate-limited)."""
    _check_rate_limit("reload")

    global PROJECTS, KNOWN_LICENSES, HIGH_RISK, MEDIUM_RISK, LOW_RISK

    new_config = load_config()
    PROJECTS, KNOWN_LICENSES, HIGH_RISK, MEDIUM_RISK, LOW_RISK = _unpack_config(new_config)

    logger.info("Reloaded config: %d projects", len(PROJECTS))
    return {"status": "reloaded", "projects": len(PROJECTS)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
