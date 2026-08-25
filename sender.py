"""Send translated Splunk HEC payloads to a SIEM endpoint over HTTP."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any

from translator import to_splunk_hec


def send_to_siem(
    payload: dict[str, Any],
    endpoint_url: str,
    token: str = "mock-token",
) -> bool:
    """
    Send a JSON payload to a SIEM endpoint using HTTP POST.

    Args:
        payload: Splunk HEC-compatible payload.
        endpoint_url: Target HTTP endpoint.
        token: Splunk HEC token value.

    Returns:
        True when the endpoint responds with HTTP 200 or 201, otherwise False.
    """
    try:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            endpoint_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Splunk {token}",
            },
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status in (200, 201)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, socket.timeout):
        return False


if __name__ == "__main__":
    sample_ocsf_event = {
        "class_uid": 4003,
        "class_name": "DNS Activity",
        "time": 1787326310055,
        "disposition": "Blocked",
        "action": "Denied",
        "severity": "High",
        "query": {"hostname": "malicious-phishing.com", "type": "A"},
        "src_endpoint": {"ip": "192.168.1.50", "uid": "dev-9921"},
        "dst_endpoint": {"ip": "203.0.113.42"},
        "metadata": {
            "product": {
                "vendor_name": "PT ITSEC Asia",
                "name": "IntelliBron Aman",
            }
        },
    }

    hec_payload = to_splunk_hec(sample_ocsf_event)
    delivered = send_to_siem(
        hec_payload,
        "http://httpbin.org/post",
        token="mock-token-12345",
    )

    print(json.dumps(hec_payload, indent=2))
    print(f"Delivery successful: {delivered}")
