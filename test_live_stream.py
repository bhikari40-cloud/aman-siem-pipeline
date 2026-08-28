"""One-off test driver: replay hinata's live OCSF stream capture through the
Data Plane and deliver to Annie's real SIEM backends.

Hinata's forwarder (ocsf_mapper.py) already normalizes raw logs to OCSF before
writing them to the stream -- unlike orchestrator.run_pipeline's usual input,
these lines must NOT be passed through ingest.normalize_to_ocsf again (it
expects raw ECS-shaped docs, not already-OCSF ones, and would silently
mis-extract most fields). This script starts one stage later: it takes the
already-normalized alert, injects the tenant field hinata's mapper omits
(subscriber id lives at unmapped.subscriber_id, not tenant.uid), and runs it
through the same isolation -> filter -> format -> deliver stages orchestrator
uses internally.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from config_store import load_tenant_configs
from orchestrator import (
    deliver_concurrently,
    group_into_batches,
    log_line,
    prepare_delivery_attempt,
    should_deliver_event,
)

DEFAULT_CAPTURE = Path(
    "/private/tmp/claude-501/-Users-brianhikarijanna/"
    "98963248-8536-44fd-b2bb-2376b12d4696/scratchpad/hinata_live_capture.ndjson"
)


def load_capture(path: Path) -> list[dict[str, Any]]:
    events = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def with_tenant(alert: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    """Copy an already-OCSF hinata alert with tenant.uid injected."""
    adapted = dict(alert)
    adapted["tenant"] = {"uid": tenant_id}
    return adapted


def run_for_tenant(
    tenant_id: str,
    alerts: list[dict[str, Any]],
    tenant_configs: dict[str, dict[str, str]],
) -> None:
    generated = len(alerts)
    dropped_unblocked = 0
    dropped_unknown_tenant = 0
    attempts = []

    for alert in alerts:
        adapted = with_tenant(alert, tenant_id)
        should_deliver, reason = should_deliver_event(adapted, tenant_configs)
        if not should_deliver:
            if reason == "unblocked":
                dropped_unblocked += 1
            else:
                dropped_unknown_tenant += 1
            continue
        attempts.append(prepare_delivery_attempt(adapted, tenant_configs[tenant_id]))

    batches = group_into_batches(attempts, batch_size=50) if attempts else []
    deliver_concurrently(batches)

    delivered = sum(len(b.attempts) for b in batches if not b.error)
    failed = sum(len(b.attempts) for b in batches if b.error)

    log_line(
        "INFO",
        "live-stream replay complete",
        tenant=tenant_id,
        generated=generated,
        blocked_alerts=len(attempts),
        dropped_unblocked=dropped_unblocked,
        delivered=delivered,
        failed=failed,
        batches=len(batches),
    )
    for batch in batches:
        if batch.error:
            log_line(
                "ERROR",
                "batch delivery failed",
                tenant=tenant_id,
                webhook_url=batch.webhook_url,
                error=batch.error,
                retries=batch.retries,
            )
        else:
            log_line(
                "INFO",
                "batch delivered",
                tenant=tenant_id,
                webhook_url=batch.webhook_url,
                alerts=len(batch.attempts),
                status=batch.status_code,
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE)
    parser.add_argument(
        "--tenants",
        nargs="+",
        default=["test-annie-elk", "test-annie-opensearch"],
        help="tenant_configs.json keys to replay the same capture against",
    )
    args = parser.parse_args()

    alerts = load_capture(args.capture)
    tenant_configs = load_tenant_configs()

    print(f"\n=== Replaying {len(alerts)} hinata live-stream events ===\n")
    for tenant_id in args.tenants:
        if tenant_id not in tenant_configs:
            log_line("ERROR", "tenant not found in tenant_configs.json", tenant=tenant_id)
            continue
        run_for_tenant(tenant_id, alerts, tenant_configs)
        print()


if __name__ == "__main__":
    main()
