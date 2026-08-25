"""Normalize raw security log documents into canonical OCSF alerts.

SOURCE-AGNOSTIC INGESTION LAYER
===============================
This module owns the transformation from *any* raw log document into the
canonical OCSF "DNS Activity" (class 4003) alert that the Data Plane delivers
to customer SIEMs. It knows nothing about where a document came from.

Every source exposes the same contract: a callable or generator that yields
raw documents as ``dict`` objects. Today that source is a static OpenSearch
CSV export (``iter_export_csv``) used for the sample and local demos.

FUTURE CONTINUOUS FEED (documented seam)
----------------------------------------
The production feed will be a continuous stream consumed via an API key. When
the endpoint contract is known, add a source adapter here with the SAME shape
as ``iter_export_csv`` -- e.g. ``iter_api_stream(endpoint, api_key)`` -- that
yields raw ECS documents. Nothing downstream changes:

    for raw_doc in iter_api_stream(endpoint, api_key):   # or iter_export_csv(...)
        alert = normalize_to_ocsf(raw_doc)               # pure, source-agnostic
        ...

``normalize_to_ocsf`` is deliberately pure: no I/O, no state, no source
dependency. It accepts both the flat ECS dotted shape used by the real
OpenSearch export and the nested shape used by the synthetic demo generator.
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


DEFAULT_EXPORT_CSV = Path.home() / "Downloads" / "opensearch_export_2026-08-21.csv"

# Enrichment: rule.category -> severity for the downstream SIEM.
# Single source of truth for the whole pipeline.
SEVERITY_BY_CATEGORY = {
    "malicious": "Critical",
    "suspicious": "High",
    "gambling": "Medium",
    "advertising": "Medium",
    "tracking_telemetry": "Low",
    "benign": "Low",
}

OCSF_PRODUCT = {
    "vendor_name": "PT ITSEC Asia",
    "name": "IntelliBron Aman",
}


def _get(raw_doc: dict[str, Any], dotted: str, nested: tuple[str, ...] | None = None) -> Any:
    """Read a field from a flat ECS doc (``a.b.c``) or a nested doc (``{"a":...}``)."""
    if dotted in raw_doc:
        return raw_doc[dotted]

    if nested:
        node: Any = raw_doc
        for key in nested:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        return node

    return None


def _parse_list(value: Any) -> list[Any]:
    """Parse JSON-stringified lists (``'["A","A"]'``) or single values into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return [value]
        return parsed if isinstance(parsed, list) else [parsed]
    return [value]


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse ISO-8601 or ``'Aug 21, 2026 @ 15:50:36.960'`` timestamps."""
    if value is None or isinstance(value, (dict, list)):
        return None

    if isinstance(value, (int, float)):
        seconds = value / 1000.0 if value > 10**12 else float(value)
        return datetime.fromtimestamp(seconds, tz=UTC)

    text = str(value).strip()
    if not text:
        return None

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass

    try:
        # The real export timestamps are UTC and have no timezone suffix.
        return datetime.strptime(text, "%b %d, %Y @ %H:%M:%S.%f").replace(tzinfo=UTC)
    except ValueError:
        return None


def _to_iso_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_to_ocsf(raw_doc: dict[str, Any]) -> dict[str, Any]:
    """Normalize one raw log document into the canonical OCSF DNS Activity alert.

    Maps the flat ECS dotted fields (real export) or the nested shape (synthetic
    generator) onto OCSF class 4003. Missing or sparse fields are handled
    gracefully -- empty IP lists, absent source IPs, and unclassified events
    all normalize without raising.
    """
    raw_timestamp = _get(raw_doc, "@timestamp")
    timestamp = _parse_timestamp(raw_timestamp)

    tenant_id = _get(raw_doc, "subscriber.id", ("subscriber", "id")) or "unknown"
    domain = _get(raw_doc, "destination.domain", ("destination", "domain"))
    category = _get(raw_doc, "rule.category", ("rule", "category")) or "benign"

    blocked_raw = _get(raw_doc, "destination.blocked", ("destination", "blocked"))
    if isinstance(blocked_raw, bool):
        blocked = blocked_raw
    elif blocked_raw is None:
        blocked = False
    else:
        blocked = str(blocked_raw).strip().lower() == "true"

    question_types = _parse_list(_get(raw_doc, "dns.question.type"))
    source_ips = _parse_list(_get(raw_doc, "source.ip"))
    destination_ips = _parse_list(_get(raw_doc, "destination.ip"))

    alert: dict[str, Any] = {
        "class_uid": 4003,
        "class_name": "DNS Activity",
        "activity_id": 1,
        "activity_name": "DNS Query",
        "time": _to_iso_utc(timestamp) if timestamp else str(raw_timestamp or ""),
        "severity": SEVERITY_BY_CATEGORY.get(category, "Low"),
        "category_name": category,
        "disposition": "Blocked" if blocked else "Allowed",
        "action": "Denied" if blocked else "Allowed",
        "tenant": {"uid": tenant_id},
        "query": {"hostname": domain or "", "type": question_types[0] if question_types else "ANY"},
        "metadata": {
            "product": dict(OCSF_PRODUCT),
        },
    }

    if source_ips:
        alert["src_endpoint"] = {"ip": str(source_ips[0])}
    if destination_ips:
        alert["dst_endpoint"] = {"ip": str(destination_ips[0])}

    host_name = _get(raw_doc, "host.name")
    if host_name:
        alert["metadata"]["device"] = {"hostname": host_name}

    event_code = _get(raw_doc, "event.dataset")
    if event_code:
        alert["metadata"]["event_code"] = event_code

    return alert


def iter_export_csv(path: Path = DEFAULT_EXPORT_CSV, *, limit: int | None = None) -> Iterator[dict[str, Any]]:
    """Yield raw log documents from an OpenSearch CSV export.

    The export stores each document as a JSON blob in a ``_source`` column.
    This is the sample/snapshot adapter; a future continuous API feed should
    expose the same generator contract.
    """
    with open(path, newline="", encoding="utf-8-sig") as file:
        for index, row in enumerate(csv.DictReader(file)):
            if limit is not None and index >= limit:
                break
            yield json.loads(row["_source"])


if __name__ == "__main__":
    import sys

    path = DEFAULT_EXPORT_CSV if len(sys.argv) < 2 else Path(sys.argv[1])
    print(f"normalizing sample from: {path}\n")
    for index, raw in enumerate(iter_export_csv(path, limit=5)):
        print(json.dumps(normalize_to_ocsf(raw), indent=2))
        print()
