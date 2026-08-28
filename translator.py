"""Format canonical OCSF alerts for tenant-specific SIEM webhook targets."""

from __future__ import annotations

import base64
import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Iterable

# SIEM targets that support multi-alert batching in a single POST. Splunk,
# Sentinel, and Datadog accept a JSON array body; Elastic and Wazuh (its
# bundled indexer is an OpenSearch fork -- same wire protocol) batch via the
# Bulk API's newline-delimited JSON (NDJSON) body instead of a JSON array.
# Graylog (one GELF message per POST) and generic targets stay
# single-document per request.
BATCHABLE_SIEMS = frozenset({"splunk", "sentinel", "datadog", "elastic", "wazuh"})

# Of the batchable SIEMs, these specifically require the NDJSON bulk *body*
# even when there is only one alert -- unlike splunk/sentinel/datadog, whose
# single-alert envelope is valid on its own, a lone elastic/wazuh alert must
# still be wrapped as a one-record Bulk body or the target's `_bulk` endpoint
# will reject it (it's a different wire shape, not just a shorter list).
NDJSON_BULK_SIEMS = frozenset({"elastic", "wazuh"})

_SEVERITY_TO_SYSLOG_LEVEL = {
    "informational": 6,
    "low": 5,
    "medium": 4,
    "high": 3,
    "critical": 2,
}

_SYSLOG_FACILITY_SECURITY = 4  # security/authorization messages


def _compact_syslog_fields(alert: dict[str, Any]) -> dict[str, Any]:
    """Pick only the fields a SOC needs to triage this alert.

    UDP syslog has no delivery confirmation, and a real truncation risk: one
    dropped or fragmented datagram silently corrupts the whole message, and
    that gets more likely as the payload grows (lower-MTU network paths --
    VPNs, tunnels -- make it worse). So this is deliberately NOT the full
    OCSF alert -- the full-fidelity record already goes out over the
    non-UDP channels (elastic/wazuh's bulk API). Syslog only needs enough to
    act on, as compact as possible; timestamp is skipped here too since
    RFC 5424's own header already carries one.
    """
    query = alert.get("query", {}) or {}
    return {
        "domain": query.get("hostname"),
        "src_ip": alert.get("src_endpoint", {}).get("ip"),
        "severity": alert.get("severity"),
        "tenant": alert.get("tenant", {}).get("uid"),
        "rule": alert.get("firewall_rule", {}).get("name"),
    }


def _to_syslog_json(alert: dict[str, Any]) -> str:
    """Compact JSON body -- matches Wazuh's built-in JSON decoder, which
    supports JSON embedded after a syslog header via its `offset` attribute.
    No custom Wazuh-side decoder needed for this.
    """
    fields = {k: v for k, v in _compact_syslog_fields(alert).items() if v is not None}
    return json.dumps(fields, separators=(",", ":"))


def _to_syslog_kv(alert: dict[str, Any]) -> str:
    """Compact key=value body -- matches the generic key/value extractor
    most SIEMs (Graylog included) ship with out of the box. No custom
    decoder needed on that side either.
    """
    parts = []
    for key, value in _compact_syslog_fields(alert).items():
        if value is None:
            continue
        parts.append(f'{key}="{value}"' if isinstance(value, str) else f"{key}={value}")
    return " ".join(parts)


# Body format is chosen per downstream SIEM from what it natively/most
# easily parses -- not one convention forced across every target. Same
# principle as format_for_siem's per-SIEM envelopes, applied to a transport
# (UDP syslog) where several targets can share the wire protocol but not the
# payload convention.
_SYSLOG_BODY_BUILDERS = {
    "wazuh": _to_syslog_json,
    "graylog": _to_syslog_kv,
}


def format_for_syslog(ocsf_data: dict[str, Any], siem_type: str) -> str:
    """Build a full RFC 5424 syslog line for a target reached over UDP.

    Unlike format_for_siem, there's no auth_token parameter -- plain syslog
    has no authentication mechanism, the network path itself is the only
    access control.
    """
    if not isinstance(ocsf_data, dict):
        raise TypeError("ocsf_data must be a dictionary")

    normalized_siem_type = (siem_type or "generic").strip().lower()
    build_body = _SYSLOG_BODY_BUILDERS.get(normalized_siem_type, _to_syslog_kv)
    body = build_body(ocsf_data)

    severity = str(ocsf_data.get("severity", "")).lower()
    level = _SEVERITY_TO_SYSLOG_LEVEL.get(severity, 6)
    pri = _SYSLOG_FACILITY_SECURITY * 8 + level

    # HOSTNAME/APP-NAME identify the sender once, in the header -- no need
    # to repeat vendor/product info inside every message body.
    return f"<{pri}>1 {_normalize_timestamp(ocsf_data.get('time'))} aman-pipeline aman-dns - - - {body}"


def _normalize_timestamp(ocsf_time: Any) -> str:
    """Normalize ``alert["time"]`` to an ISO 8601 UTC string.

    Used for both the RFC 5424 syslog TIMESTAMP field and (see
    ``_to_bulk_ndjson``) an ECS-style ``@timestamp`` on documents sent to
    Elastic/Wazuh's `_bulk` endpoint -- without a properly *typed* date
    field, Elasticsearch has nothing to run a time-range query against, and
    Kibana's detection rules fail outright ("missing timestamp field").

    ``alert["time"]`` isn't one consistent type across OCSF producers in
    this project: our own ingest.normalize_to_ocsf emits an ISO 8601
    string, while hinata's separate OCSF mapper emits epoch milliseconds
    (an int). Accept either rather than assuming one -- that mismatch is a
    known, pre-existing divergence between the two normalizers, not
    something to silently paper over by picking one and breaking the other.
    """
    if isinstance(ocsf_time, (int, float)):
        moment = datetime.fromtimestamp(ocsf_time / 1000, tz=UTC)
    else:
        try:
            moment = datetime.fromisoformat(str(ocsf_time).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            moment = datetime.now(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _to_gelf(alert: dict[str, Any]) -> dict[str, Any]:
    """Build a GELF message body for Graylog's GELF HTTP input.

    Underscore-prefixed keys become searchable custom fields in Graylog;
    version/host/short_message/level are GELF's required envelope.
    """
    query = alert.get("query", {}) or {}
    severity = str(alert.get("severity", "")).lower()
    return {
        "version": "1.1",
        "host": alert.get("metadata", {}).get("product", {}).get("name") or "aman-pipeline",
        "short_message": f"{alert.get('disposition', 'Unknown')} DNS query: {query.get('hostname', 'unknown')}",
        "timestamp": (alert.get("time") or 0) / 1000,
        "level": _SEVERITY_TO_SYSLOG_LEVEL.get(severity, 6),
        "_domain": query.get("hostname"),
        "_severity": alert.get("severity"),
        "_disposition": alert.get("disposition"),
        "_tenant_uid": alert.get("tenant", {}).get("uid"),
        "_class_name": alert.get("class_name"),
    }


def format_for_siem(
    ocsf_data: dict[str, Any],
    siem_type: str,
    auth_token: str,
) -> tuple[dict[str, str], Any]:
    """
    Return HTTP headers and payload formatted for a specific SIEM.

    The input ``ocsf_data`` is treated as the canonical alert shape owned by the
    Data Plane. This function only adapts envelope/auth conventions for each
    downstream SIEM integration.
    """
    if not isinstance(ocsf_data, dict):
        raise TypeError("ocsf_data must be a dictionary")

    normalized_siem_type = (siem_type or "generic").strip().lower()

    if normalized_siem_type == "splunk":
        return (
            {"Authorization": f"Splunk {auth_token}"},
            {"event": deepcopy(ocsf_data)},
        )

    if normalized_siem_type == "sentinel":
        return (
            {"Authorization": f"Bearer {auth_token}"},
            [deepcopy(ocsf_data)],
        )

    if normalized_siem_type == "elastic":
        return (
            {"Authorization": f"ApiKey {auth_token}"},
            deepcopy(ocsf_data),
        )

    if normalized_siem_type == "wazuh":
        # Wazuh's bundled indexer is a stock OpenSearch security plugin --
        # HTTP Basic, not an API key. auth_token is stored as "user:pass".
        basic = base64.b64encode(auth_token.encode("utf-8")).decode("ascii")
        return (
            {"Authorization": f"Basic {basic}"},
            deepcopy(ocsf_data),
        )

    if normalized_siem_type == "graylog":
        # GELF HTTP input on this deployment has no auth configured.
        return ({}, _to_gelf(ocsf_data))

    if normalized_siem_type == "datadog":
        return (
            {"DD-API-KEY": auth_token},
            deepcopy(ocsf_data),
        )

    return (
        {"Authorization": f"Bearer {auth_token}"},
        deepcopy(ocsf_data),
    )


def format_batch_for_siem(
    ocsf_alerts: Iterable[dict[str, Any]],
    siem_type: str,
    auth_token: str,
) -> tuple[dict[str, str], Any]:
    """Return headers and a batched payload for a list of canonical alerts.

    Only array-envelope targets (``BATCHABLE_SIEMS``) support batching:
    Splunk HEC accepts a list of ``{"event": ...}`` objects, while Sentinel and
    Datadog accept a plain list of alert records. Calling this for a
    non-batchable target raises ``ValueError``.
    """
    alerts = list(ocsf_alerts)
    normalized_siem_type = (siem_type or "generic").strip().lower()

    if normalized_siem_type not in BATCHABLE_SIEMS:
        raise ValueError(f"{normalized_siem_type} does not support batched delivery")

    if normalized_siem_type == "splunk":
        return (
            {"Authorization": f"Splunk {auth_token}"},
            [{"event": deepcopy(alert)} for alert in alerts],
        )

    if normalized_siem_type == "sentinel":
        return (
            {"Authorization": f"Bearer {auth_token}"},
            [deepcopy(alert) for alert in alerts],
        )

    if normalized_siem_type in NDJSON_BULK_SIEMS:
        return (
            {"Content-Type": "application/x-ndjson"},
            _to_bulk_ndjson(alerts),
        )

    return (
        {"DD-API-KEY": auth_token},
        [deepcopy(alert) for alert in alerts],
    )


def _to_bulk_ndjson(alerts: Iterable[dict[str, Any]]) -> str:
    """Build an Elasticsearch/OpenSearch Bulk API body: alternating compact
    action + source lines, each its own single-line JSON object, with a
    required trailing newline. Must NOT be pretty-printed -- literal ``\\n``
    is the record delimiter the Bulk API parses on.

    Normalizes ``time`` to a consistent ISO 8601 string and adds a matching
    ECS-style ``@timestamp`` when present, so Elasticsearch's dynamic
    mapping types it as an actual `date` field -- our own ``time`` field is
    a plain number (epoch millis) or a string depending on which OCSF
    producer built the alert, and once an index has dynamically mapped
    ``time`` as one type, a document with the other type gets hard-rejected
    with a document_parsing_exception (a real failure mode this project hit
    in practice: hinata's numeric timestamps mapped the field as `long`
    first, so ingest.normalize_to_ocsf's string timestamps started failing
    against that same index). Normalizing both fields to the same
    consistent string here removes that whole conflict class for anything
    delivered through this path. Alerts without a ``time`` field (e.g. ad
    hoc test fixtures) are left untouched.
    """
    lines: list[str] = []
    for alert in alerts:
        doc = alert
        if "time" in alert:
            normalized = _normalize_timestamp(alert["time"])
            doc = {**alert, "time": normalized, "@timestamp": normalized}
        lines.append(json.dumps({"index": {}}, separators=(",", ":")))
        lines.append(json.dumps(doc, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def to_splunk_hec(ocsf_event: dict[str, Any]) -> dict[str, Any]:
    """
    Backward-compatible helper for the earlier POC modules.

    New pipeline code should call ``format_for_siem`` instead.
    """
    _, payload = format_for_siem(ocsf_event, "splunk", auth_token="")
    return payload


if __name__ == "__main__":
    sample_ocsf_event = {
        "class_uid": 4003,
        "class_name": "DNS Activity",
        "time": 1787326310055,
        "severity": "High",
        "disposition": "Blocked",
        "category_name": "suspicious",
        "query": {"hostname": "login-update-secure.example", "type": "A"},
        "src_endpoint": {"ip": "192.168.1.50", "uid": "device-9921"},
        "metadata": {
            "product": {
                "vendor_name": "PT ITSEC Asia",
                "name": "IntelliBron Aman",
            }
        },
    }

    for target_siem in ("splunk", "sentinel", "elastic", "generic"):
        headers, payload = format_for_siem(
            sample_ocsf_event,
            target_siem,
            auth_token="demo-token-123",
        )

        print(f"\n=== {target_siem.upper()} FORMAT ===")
        print("Headers:")
        print(json.dumps(headers, indent=2))
        print("Payload:")
        print(json.dumps(payload, indent=2))
