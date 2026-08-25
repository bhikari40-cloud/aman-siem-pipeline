"""Failsafe in-memory event queue for SIEM delivery retries."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable

from sender import send_to_siem
from translator import to_splunk_hec


SenderFunc = Callable[[dict[str, Any], str], bool]


class EventQueue:
    """Buffer raw OCSF events and retry failed SIEM deliveries later."""

    def __init__(self) -> None:
        """Initialize an empty event buffer."""
        self._buffer: list[dict[str, Any]] = []

    def add_event(self, raw_ocsf_event: dict[str, Any]) -> None:
        """Add a raw OCSF event to the queue."""
        if not isinstance(raw_ocsf_event, dict):
            raise TypeError("raw_ocsf_event must be a dictionary")

        self._buffer.append(deepcopy(raw_ocsf_event))

    def flush_and_send(
        self,
        sender_func: SenderFunc,
        endpoint_url: str,
        batch_size: int = 5,
    ) -> dict[str, int | bool]:
        """
        Send queued events to the SIEM endpoint.

        Events are sent in queue order. Successfully delivered events are removed
        from the queue. When delivery fails, the failed event and all later events
        remain in the queue for a future retry.

        Args:
            sender_func: Function that sends one Splunk HEC payload.
            endpoint_url: Target SIEM endpoint.
            batch_size: Maximum number of queued events to attempt.

        Returns:
            Delivery summary with attempted, sent, failed, and remaining counts.
        """
        if batch_size < 1:
            raise ValueError("batch_size must be at least 1")

        batch = self._buffer[:batch_size]
        sent_count = 0
        failed_count = 0

        for raw_event in batch:
            payload = to_splunk_hec(raw_event)
            if not sender_func(payload, endpoint_url):
                failed_count = 1
                break

            sent_count += 1

        if sent_count:
            del self._buffer[:sent_count]

        return {
            "attempted": sent_count + failed_count,
            "sent": sent_count,
            "failed": failed_count,
            "remaining": len(self._buffer),
            "success": failed_count == 0,
        }

    def __len__(self) -> int:
        """Return the current number of buffered events."""
        return len(self._buffer)


def _sample_event(device_id: str, hostname: str) -> dict[str, Any]:
    """Build a small sample OCSF DNS Activity event for local testing."""
    return {
        "class_uid": 4003,
        "class_name": "DNS Activity",
        "time": 1787326310055,
        "disposition": "Blocked",
        "action": "Denied",
        "severity": "High",
        "query": {"hostname": hostname, "type": "A"},
        "src_endpoint": {"ip": "192.168.1.50", "uid": device_id},
        "dst_endpoint": {"ip": "203.0.113.42"},
        "metadata": {
            "product": {
                "vendor_name": "PT ITSEC Asia",
                "name": "IntelliBron Aman",
            }
        },
    }


if __name__ == "__main__":
    queue = EventQueue()
    for index in range(1, 4):
        queue.add_event(_sample_event(f"dev-992{index}", f"test-{index}.example"))

    success_result = queue.flush_and_send(
        send_to_siem,
        "http://httpbin.org/post",
        batch_size=5,
    )
    print(f"Successful flush result: {success_result}")
    print(f"Queue size after successful flush: {len(queue)}")

    for index in range(1, 4):
        queue.add_event(_sample_event(f"dev-retry-{index}", f"retry-{index}.example"))

    failed_result = queue.flush_and_send(
        send_to_siem,
        "http://localhost:9999/fail",
        batch_size=5,
    )
    print(f"Failed flush result: {failed_result}")
    print(f"Queue size after failed flush: {len(queue)}")
