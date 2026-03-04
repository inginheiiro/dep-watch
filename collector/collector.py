"""
Data collection from external APIs with retry and backoff.
"""

import os
import asyncio
import logging
import random

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Retry with exponential backoff
# ---------------------------------------------------------------------------

MAX_RETRIES = 3
BASE_DELAY = 1.0  # seconds
MAX_DELAY = 10.0  # seconds


async def _retry(coro_fn, label: str):
    """Execute an async callable with exponential backoff.

    Args:
        coro_fn: Zero-arg async callable that returns a value.
        label: Human-readable label for logging.
    """
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return await coro_fn()
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as exc:
            last_exc = exc
            if attempt == MAX_RETRIES:
                break
            delay = min(BASE_DELAY * (2 ** (attempt - 1)), MAX_DELAY)
            delay += random.uniform(0, delay * 0.25)  # jitter
            logger.warning(
                "%s attempt %d/%d failed (%s), retrying in %.1fs",
                label, attempt, MAX_RETRIES, exc, delay,
            )
            await asyncio.sleep(delay)

    logger.error("%s failed after %d attempts: %s", label, MAX_RETRIES, last_exc)
    raise last_exc


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class Collector:
    def __init__(self):
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.libraries_io_key = os.getenv('LIBRARIES_IO_KEY', '')

    # -- GitHub ---------------------------------------------------------------

    async def fetch_github(self, repo: str) -> dict:
        """GitHub API - repo info, releases, contributors, funding."""
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        async def _do():
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(
                    f"https://api.github.com/repos/{repo}", headers=headers,
                )
                r.raise_for_status()
                data = r.json()

                rel = await client.get(
                    f"https://api.github.com/repos/{repo}/releases/latest",
                    headers=headers,
                )
                release_date = None
                latest_tag = None
                if rel.status_code == 200:
                    rel_data = rel.json()
                    release_date = rel_data.get("published_at")
                    latest_tag = rel_data.get("tag_name", "").lstrip("v")

                contrib = await client.get(
                    f"https://api.github.com/repos/{repo}/contributors?per_page=100",
                    headers=headers,
                )
                contrib_count = len(contrib.json()) if contrib.status_code == 200 else 0

                commits = await client.get(
                    f"https://api.github.com/repos/{repo}/commits?per_page=1",
                    headers=headers,
                )
                last_commit = None
                if commits.status_code == 200 and commits.json():
                    last_commit = (
                        commits.json()[0]
                        .get("commit", {})
                        .get("committer", {})
                        .get("date")
                    )

                has_sponsors = False
                try:
                    funding = await client.get(
                        f"https://api.github.com/repos/{repo}/community/profile",
                        headers=headers,
                    )
                    if funding.status_code == 200:
                        files = funding.json().get("files", {})
                        has_sponsors = files.get("funding") is not None
                except Exception:
                    pass

                return {
                    "stars": data.get("stargazers_count", 0),
                    "forks": data.get("forks_count", 0),
                    "open_issues": data.get("open_issues_count", 0),
                    "archived": data.get("archived", False),
                    "license": (
                        data.get("license", {}).get("spdx_id")
                        if data.get("license")
                        else "unknown"
                    ),
                    "release_date": release_date,
                    "latest_tag": latest_tag,
                    "last_commit": last_commit,
                    "contributors": contrib_count,
                    "has_funding": has_sponsors,
                }

        try:
            return await _retry(_do, f"GitHub({repo})")
        except Exception as exc:
            logger.error("GitHub error %s: %s", repo, exc)
            return {}

    # -- OpenSSF Scorecard ----------------------------------------------------

    async def fetch_scorecard(self, repo: str) -> float:
        """OpenSSF Scorecard score (0-10)."""

        async def _do():
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(
                    f"https://api.securityscorecards.dev/projects/github.com/{repo}",
                )
                r.raise_for_status()
                return r.json().get("score", 0)

        try:
            return await _retry(_do, f"Scorecard({repo})")
        except Exception:
            return 0

    # -- OSV.dev --------------------------------------------------------------

    async def fetch_osv(
        self, package_name: str, ecosystem: str, version: str = None,
    ) -> dict:
        """OSV.dev - vulnerability database.

        Args:
            package_name: e.g. 'vue', 'org.springframework.boot:spring-boot'
            ecosystem: e.g. 'npm', 'Maven', 'PyPI', 'Go'
            version: Specific version to check
        """
        vulns = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

        if not ecosystem:
            return vulns

        async def _do():
            async with httpx.AsyncClient(timeout=30) as client:
                query = {"package": {"name": package_name, "ecosystem": ecosystem}}
                if version:
                    query["version"] = version

                r = await client.post("https://api.osv.dev/v1/query", json=query)
                r.raise_for_status()
                return r.json()

        try:
            data = await _retry(_do, f"OSV({package_name})")
        except Exception as exc:
            logger.debug("OSV query failed for %s: %s", package_name, exc)
            return vulns

        osv_vulns = data.get("vulns", [])
        vulns["total"] = len(osv_vulns)

        for v in osv_vulns:
            severity = "unknown"
            if "severity" in v:
                for s in v.get("severity", []):
                    if s.get("type") == "CVSS_V3":
                        raw = str(s.get("score", "0"))
                        score_val = float(raw.split("/")[0]) if "/" in raw else 0
                        if score_val >= 9.0:
                            severity = "critical"
                        elif score_val >= 7.0:
                            severity = "high"
                        elif score_val >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                        break

            if severity == "unknown":
                v_str = str(v).lower()
                if "critical" in v_str:
                    severity = "critical"
                elif "high" in v_str:
                    severity = "high"
                elif "medium" in v_str or "moderate" in v_str:
                    severity = "medium"
                else:
                    severity = "low"

            vulns[severity] = vulns.get(severity, 0) + 1

        return vulns

    # -- Libraries.io ---------------------------------------------------------

    async def fetch_libraries_io(self, package: str) -> dict:
        """Libraries.io - SourceRank and dependents."""
        if not package:
            return {"source_rank": 0, "dependents": 0}

        async def _do():
            async with httpx.AsyncClient(timeout=30) as client:
                url = f"https://libraries.io/api/{package}"
                params = {"api_key": self.libraries_io_key} if self.libraries_io_key else {}
                r = await client.get(url, params=params)
                r.raise_for_status()
                data = r.json()
                return {
                    "source_rank": data.get("rank", 0),
                    "dependents": data.get("dependents_count", 0),
                }

        try:
            return await _retry(_do, f"LibrariesIO({package})")
        except Exception:
            return {"source_rank": 0, "dependents": 0}
