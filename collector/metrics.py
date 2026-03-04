"""
Prometheus metric definitions for the Infra Dependency Monitor.
"""

from prometheus_client import Gauge, Counter

# License & Risk
license_risk = Gauge(
    'dep_license_risk',
    'License risk (0=low, 1=medium, 2=high, 3=unknown)',
    ['project', 'category', 'license'],
)
license_changed = Gauge(
    'dep_license_changed',
    'License changed since monitoring started (1=yes)',
    ['project', 'category'],
)

# Security
security_score = Gauge(
    'dep_security_score',
    'OpenSSF Scorecard (0-10)',
    ['project', 'category'],
)
vulnerabilities = Gauge(
    'dep_vulnerabilities',
    'Known vulnerabilities from OSV.dev',
    ['project', 'category', 'severity'],
)

# Activity & Maintenance
days_since_commit = Gauge(
    'dep_days_since_commit',
    'Days since last commit',
    ['project', 'category'],
)
days_since_release = Gauge(
    'dep_days_since_release',
    'Days since last release',
    ['project', 'category'],
)
is_archived = Gauge(
    'dep_is_archived',
    'Repository archived (1=yes)',
    ['project', 'category'],
)

# Community & Popularity
github_stars = Gauge(
    'dep_github_stars',
    'GitHub stars',
    ['project', 'category'],
)
github_forks = Gauge(
    'dep_github_forks',
    'GitHub forks',
    ['project', 'category'],
)
contributors = Gauge(
    'dep_contributors',
    'Number of contributors',
    ['project', 'category'],
)
dependents = Gauge(
    'dep_dependents',
    'Projects depending on this (from Libraries.io)',
    ['project', 'category'],
)
source_rank = Gauge(
    'dep_source_rank',
    'Libraries.io SourceRank score',
    ['project', 'category'],
)

# Version tracking
current_version_info = Gauge(
    'dep_current_version',
    'Current version in use (1=has version)',
    ['project', 'category', 'version'],
)
latest_version_info = Gauge(
    'dep_latest_version',
    'Latest available version (1=has version)',
    ['project', 'category', 'version'],
)
version_behind = Gauge(
    'dep_version_behind',
    'Number of major/minor versions behind',
    ['project', 'category'],
)

# Funding & Sustainability
has_funding = Gauge(
    'dep_has_funding',
    'Has funding/sponsors (1=yes)',
    ['project', 'category'],
)

# Aggregated Scores
health_score = Gauge(
    'dep_health_score',
    'Overall health (0-100)',
    ['project', 'category'],
)
sustainability_score = Gauge(
    'dep_sustainability_score',
    'Sustainability risk (0-100)',
    ['project', 'category'],
)

# System
collection_errors = Counter(
    'collector_errors_total',
    'Collection errors',
    ['project', 'source'],
)
last_collection = Gauge(
    'collector_last_run_timestamp',
    'Last collection timestamp',
)
