"""Normalize raw security log documents into canonical OCSF alerts.

SOURCE-AGNOSTIC INGESTION LAYER
===============================
This module owns the transformation from *any* raw log document into the
canonical OCSF "DNS Activity" (class 4003) alert that the Data Plane delivers
to customer SIEMs. It knows nothing about where a document came from.

Every source exposes the same contract: a callable or generator that yields
raw documents as ``dict`` objects. Two sources exist today: a static
OpenSearch CSV export (``iter_export_csv``, used by the CLI/tests) and the
real internal ClickHouse data API (``iter_api_stream``, used by the live
dashboard). Nothing downstream changes between them:

    for raw_doc in iter_api_stream(base_url, api_key):   # or iter_export_csv(...)
        alert = normalize_to_ocsf(raw_doc)                # pure, source-agnostic
        ...

``iter_api_stream`` is a bounded, rate-limited pull of one day's slice of
real DNS log data -- proof that the pipeline can connect to and normalize
the real data source, not a production-grade continuous/checkpointed tail.
Freshness, query performance at scale, and pagination are all backend-side
concerns, out of scope here by explicit instruction (see its docstring).

``normalize_to_ocsf`` is deliberately pure: no I/O, no state, no source
dependency. It accepts both the flat ECS dotted shape used by the real
OpenSearch export and the nested shape used by the synthetic demo generator.
"""

from __future__ import annotations

import csv
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

import requests


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


DEFAULT_CLICKHOUSE_DATABASE = "intellibron_aman_silver"
DEFAULT_CLICKHOUSE_TABLE = "dns_request_parsed"


def _clickhouse_row_to_raw_doc(row: dict[str, Any]) -> dict[str, Any]:
    """Map one ``dns_request_parsed`` row onto the flat ECS-dotted shape
    ``normalize_to_ocsf`` already expects from the real OpenSearch export --
    no changes needed downstream for this new source.
    """
    return {
        "@timestamp": row.get("timestamp"),
        "subscriber.id": row.get("user_id"),
        "destination.domain": row.get("destination_domain"),
        "destination.blocked": row.get("destination_blocked"),
        "rule.category": row.get("rule_category") or "benign",
        "dns.question.type": row.get("dns_question_types"),
        "source.ip": row.get("source_ip"),
        "destination.ip": row.get("destination_ip"),
    }


def iter_api_stream(
    base_url: str,
    api_key: str,
    *,
    database: str = DEFAULT_CLICKHOUSE_DATABASE,
    table: str = DEFAULT_CLICKHOUSE_TABLE,
    dt: str | None = None,
    limit: int = 10,
    rate: float = 5.0,
) -> Iterator[dict[str, Any]]:
    """Yield raw DNS request documents from the ITSEC ClickHouse Data API.

    Proof-of-connectivity source, not a production continuous feed: real
    historical data (not synthetic), pulled as one bounded slice and
    replayed at a simple fixed rate. Three things are explicitly deferred,
    not solved here -- all backend/data-source concerns, not this pipeline's
    call to make:

    - **Freshness.** The freshest row currently available is real but
      already ~18 days old -- there is no live tail.
    - **Query performance at any real scale.** Direct testing found a hard
      cliff: `limit=5` on this endpoint returns in ~5s, `limit=20` reliably
      times out at 30s, both against the exact same dt-filtered day. That
      isn't this code being inefficient -- it's the API/ClickHouse side not
      short-circuiting on LIMIT the way you'd expect, on a table already
      known (per direct testing) to time out on an unfiltered
      `min/max(timestamp)` scan at 34M+ rows. The default here (10) sits
      comfortably inside the fast zone; raising it is a backend-side
      performance problem to hand off, not something to keep tuning around
      here.
    - **Throughput/pagination.** This pulls a single page. Continuous
      consumption of the full 34M+ row table (checkpointing, cursor-based
      pagination past one page) is a later problem for whoever owns that
      scale.

    Filtered by the ``dt`` partition column rather than scanning the whole
    table, and deliberately has no ``ORDER BY`` (sorting a single day's slice
    hit the same timeout class). Defaults to the most recent available day
    if ``dt`` isn't given.
    """
    headers = {"x-api-key": api_key}

    if dt is None:
        dt_rows = _clickhouse_query(
            base_url, headers, f"SELECT max(dt) AS max_dt FROM {database}.{table}", limit=1,
        )
        dt = dt_rows[0]["max_dt"]

    # No ORDER BY: a single day is still large enough (34M rows / ~6 weeks of
    # data) that sorting it timed out in direct testing, same shape as the
    # unfiltered min/max(timestamp) timeout this project already hit once.
    # Ordering isn't needed for proving connectivity -- chronological replay
    # is exactly the "later, backend's call" scope this function explicitly
    # defers (see docstring).
    #
    # destination_blocked = true is also load-bearing, not just an optimization:
    # without it, an unordered LIMIT against an immutable partition returns the
    # *same* fixed rows on every stream restart (verified directly), and
    # should_deliver_event drops every non-blocked one downstream anyway. On
    # the live day tested, the first 10 unfiltered rows happened to contain
    # zero blocked events, so the whole demo silently delivered nothing forever
    # -- looked like a dead stream, wasn't. Filtering here guarantees every
    # row pulled is one the rest of the pipeline will actually act on.
    sql = f"SELECT * FROM {database}.{table} WHERE dt = '{dt}' AND destination_blocked = true"
    rows = _clickhouse_query(base_url, headers, sql, limit=limit)

    interval = 1.0 / rate if rate > 0 else 0
    for row in rows:
        yield _clickhouse_row_to_raw_doc(row)
        if interval:
            time.sleep(interval)


def _clickhouse_query(
    base_url: str, headers: dict[str, str], sql: str, *, limit: int, retries: int = 2,
) -> list[dict[str, Any]]:
    """POST one query, retrying transient timeouts.

    This endpoint's response time is inconsistent in practice -- the exact
    same query and row count succeeded in ~5s on one call and timed out at
    30s on another. That's a backend/data-source reliability problem this
    pipeline doesn't own (see iter_api_stream's docstring); retrying here is
    just not letting a single slow response kill the whole ingest loop, the
    same retry-on-transient-failure posture orchestrator.py already applies
    to outbound deliveries.
    """
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            response = requests.post(
                f"{base_url}/api/v1/query",
                headers=headers,
                json={"sql": sql, "limit": limit},
                timeout=30,
            )
            response.raise_for_status()
            break
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(1)
    else:
        raise last_exc
    return response.json()["rows"]


if __name__ == "__main__":
    import sys

    path = DEFAULT_EXPORT_CSV if len(sys.argv) < 2 else Path(sys.argv[1])
    print(f"normalizing sample from: {path}\n")
    for index, raw in enumerate(iter_export_csv(path, limit=5)):
        print(json.dumps(normalize_to_ocsf(raw), indent=2))
        print()
