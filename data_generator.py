"""Simulated Data Engineer's stream of mock OpenSearch security logs.

DATA PLANE / SOURCE
===================
This module represents the continuous log stream that a security platform
(here: IntelliBron Aman DNS telemetry) would emit into OpenSearch. The
orchestrator consumes this stream. The majority of events are benign
(blocked=False) so the pipeline can demonstrate silent filtering, and only a
minority are real blocked alerts worth pushing to a customer SIEM.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Iterator


# Deterministic demo table: (tenant_id, category, blocked, domain).
# ~65% benign/unblocked events so delivery only happens for real alerts.
DEMO_EVENTS: list[tuple[str, str, bool, str]] = [
    ("tenant-123", "benign", False, "trusted-news.example"),
    ("tenant-999", "benign", False, "internal.docs.example"),
    ("tenant-123", "advertising", False, "ads.network.example"),
    ("tenant-123", "benign", False, "cdn.analytics.example"),
    ("tenant-999", "advertising", False, "ad-tracker.example"),
    ("tenant-123", "benign", False, "payroll-portal.example"),
    ("tenant-999", "benign", False, "docs-storage.example"),
    ("tenant-123", "suspicious", True, "login-update-secure.example"),
    ("tenant-999", "malicious", True, "malware-command.example"),
    ("tenant-123", "malicious", True, "phishing-kit.example"),
    ("tenant-999", "suspicious", True, "credential-reuse.example"),
    ("tenant-123", "benign", False, "metrics.telemetry.example"),
]


def generate_opensearch_logs(count: int = 20) -> Iterator[dict[str, Any]]:
    """Yield ``count`` mock OpenSearch DNS/security log documents.

    Each document follows the OpenSearch ECS-style shape the Data Plane
    understands. The demo table is cycled so the output is deterministic and
    reproducible for a live demo.
    """
    base_time = datetime.now(UTC)

    for index in range(count):
        tenant_id, category, blocked, domain = DEMO_EVENTS[index % len(DEMO_EVENTS)]

        yield {
            "@timestamp": (base_time + timedelta(seconds=index)).isoformat(),
            "subscriber": {
                "id": tenant_id,
            },
            "destination": {
                "domain": domain,
                "blocked": blocked,
            },
            "rule": {
                "category": category,
            },
        }


if __name__ == "__main__":
    import json

    for log in generate_opensearch_logs():
        print(json.dumps(log, indent=2))
