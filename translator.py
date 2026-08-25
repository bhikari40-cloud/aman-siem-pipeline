"""Format canonical OCSF alerts for tenant-specific SIEM webhook targets."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Iterable

# SIEM targets whose webhook endpoints accept a JSON array body, so multiple
# alerts can be delivered in a single POST (batching). Elastic and generic
# targets stay single-document per request.
BATCHABLE_SIEMS = frozenset({"splunk", "sentinel", "datadog"})


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

    return (
        {"DD-API-KEY": auth_token},
        [deepcopy(alert) for alert in alerts],
    )


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
