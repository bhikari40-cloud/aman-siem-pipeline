"""IntelliBron Aman SIEM webhook backend engine.

DATA PLANE / BACKGROUND PIPELINE
================================
This is the core backend that turns the incoming security log stream into
per-tenant SIEM webhook deliveries. It loads the tenant configuration that the
Control Plane (mock_dashboard.py) wrote, then filters, enriches, formats, and
delivers alerts. Per-SIEM envelope formatting is delegated to translator.py.

Separation of concerns:
  * Control Plane (mock_dashboard.py) -- WRITES tenant_configs.json.
  * Data Plane  (this module)         -- READS config at runtime, processes
    the log stream. It never prompts the user and never mutates config.

Pipeline stages per log:
  1. Normalization   -- raw ECS doc -> canonical OCSF DNS Activity alert.
  2. Tenant Isolation -- drop alerts whose tenant.uid has no integration.
  3. Alert Filter     -- drop alerts that were NOT blocked (benign noise).
  4. Formatting       -- adapt the canonical alert to the tenant's SIEM.
  5. Delivery         -- batch + POST concurrently to the tenant's webhook URL,
                        with per-tenant worker isolation, retry/backoff, and a
                        dead-letter queue for permanent failures.

The event source is pluggable: a synthetic demo stream (data_generator.py) or a
real OpenSearch export (ingest.iter_export_csv). A future continuous API feed
just needs to satisfy the same "yields raw dicts" contract -- see ingest.py.
"""

from __future__ import annotations

import argparse
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

import requests

from config_store import load_tenant_configs
from data_generator import generate_opensearch_logs
from ingest import DEFAULT_EXPORT_CSV, iter_export_csv, normalize_to_ocsf
from translator import (
    BATCHABLE_SIEMS,
    NDJSON_BULK_SIEMS,
    format_batch_for_siem,
    format_for_siem,
    format_for_syslog,
)


CONFIG_FILE = Path("tenant_configs.json")
DEAD_LETTER_FILE = Path("dead_letter_queue.jsonl")
LOG_COUNT = 20
REQUEST_TIMEOUT_SECONDS = 10
DEFAULT_BATCH_SIZE = 10
DEFAULT_MAX_WORKERS = 8
DEFAULT_RETRIES = 2
BACKOFF_BASE_SECONDS = 0.5
SYSLOG_DEFAULT_PORT = 514

PostFunc = Callable[..., Any]
SyslogSendFunc = Callable[[str, str], None]


def send_syslog_udp(webhook_url: str, message: str) -> None:
    """Fire-and-forget one syslog line at a `syslog://host:port` target.

    UDP has no delivery confirmation at the protocol level -- a successful
    call here means the local kernel accepted the datagram for
    transmission, nothing more. Whether the destination received or parsed
    it is unknowable from the sender's side; that's a deliberate tradeoff
    (simplicity/universal compatibility over guaranteed delivery), not an
    oversight. See deliver_batch's status_code handling for the syslog case.
    """
    parsed = urlparse(webhook_url)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(REQUEST_TIMEOUT_SECONDS)
        sock.sendto(message.encode("utf-8"), (parsed.hostname, parsed.port or SYSLOG_DEFAULT_PORT))


@dataclass
class DeliveryAttempt:
    """One formatted outbound SIEM delivery attempt.

    ``payload`` is the single-alert envelope (used for dry-run display and
    single-event delivery); ``alert`` is the canonical OCSF alert itself, which
    the batching layer re-wraps into an array envelope when needed.
    """

    tenant_id: str
    siem_type: str
    webhook_url: str
    severity: str
    domain: str
    headers: dict[str, str]
    payload: Any
    alert: dict[str, Any]
    verify: bool = True
    status_code: int | None = None
    error: str | None = None

    @property
    def redacted_headers(self) -> dict[str, str]:
        """Expose headers for logs without leaking the auth token."""
        redacted = dict(self.headers)
        if "Authorization" in redacted:
            scheme = redacted["Authorization"].split(" ", 1)[0]
            redacted["Authorization"] = f"{scheme} ***"
        return redacted


@dataclass
class DeliveryBatch:
    """One outbound HTTP POST carrying one or more delivery attempts."""

    tenant_id: str
    siem_type: str
    webhook_url: str
    headers: dict[str, str]
    payload: Any
    attempts: list[DeliveryAttempt]
    verify: bool = True
    status_code: int | None = None
    error: str | None = None
    retries: int = 0


@dataclass
class PipelineResult:
    """Summary counters for one pipeline run."""

    generated: int = 0
    delivered: int = 0
    dropped_unknown_tenant: int = 0
    dropped_unblocked: int = 0
    failed: int = 0
    attempts: list[DeliveryAttempt] = field(default_factory=list)
    delivery_batches: list[DeliveryBatch] = field(default_factory=list)
    retries: int = 0
    dlq_written: int = 0
    elapsed_seconds: float = 0.0

    @property
    def batch_count(self) -> int:
        """Number of HTTP POSTs issued for delivery."""
        return len(self.delivery_batches)


def now_log_time() -> str:
    """Compact UTC timestamp for terminal server logs."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_line(level: str, message: str, **fields: Any) -> None:
    """Print one professional structured server log line."""
    field_text = " ".join(f"{key}={value}" for key, value in fields.items())
    suffix = f" {field_text}" if field_text else ""
    print(f"{now_log_time()} | {level:<5} | aman-webhook-orchestrator | {message}{suffix}")


def should_deliver_event(
    alert: dict[str, Any],
    tenant_configs: dict[str, dict[str, str]],
) -> tuple[bool, str]:
    """Apply tenant isolation, then the blocked-alert filter.

    Operates on the canonical OCSF alert produced by the normalizer.
    """
    tenant_id = alert.get("tenant", {}).get("uid")
    if tenant_id not in tenant_configs:
        return False, "unknown_tenant"

    if alert.get("disposition") != "Blocked":
        return False, "unblocked"

    return True, "deliver"


def prepare_delivery_attempt(
    alert: dict[str, Any],
    tenant_config: dict[str, str],
) -> DeliveryAttempt:
    """Envelope the canonical alert for the tenant's SIEM target."""
    siem_type = tenant_config.get("siem_type", "generic")
    webhook_url = tenant_config["webhook_url"]

    if urlparse(webhook_url).scheme == "syslog":
        # Plain syslog has no HTTP envelope and no auth mechanism -- the
        # network path is the only access control, so there's nothing to
        # put in headers.
        headers: dict[str, str] = {}
        payload = format_for_syslog(alert, siem_type)
    else:
        headers, payload = format_for_siem(alert, siem_type, tenant_config.get("auth_token", ""))
        headers = {
            **headers,
            "Content-Type": "application/json",
            "X-Aman-Tenant-ID": tenant_config["tenant_id"],
        }

    return DeliveryAttempt(
        tenant_id=tenant_config["tenant_id"],
        siem_type=siem_type,
        webhook_url=tenant_config["webhook_url"],
        severity=alert["severity"],
        domain=alert["query"]["hostname"],
        headers=headers,
        payload=payload,
        alert=alert,
        verify=tenant_config.get("verify_ssl", True),
    )


def build_batch(attempts: list[DeliveryAttempt]) -> DeliveryBatch:
    """Wrap one or more attempts into a single outbound POST.

    A single attempt keeps its already-formatted envelope (identical to the
    pre-batching behavior). Multiple attempts are re-wrapped into the array
    envelope for the tenant's SIEM via the translator.
    """
    first = attempts[0]
    headers = first.headers
    is_syslog = urlparse(first.webhook_url).scheme == "syslog"

    # elastic/wazuh need the NDJSON bulk *body* even for a single alert --
    # unlike splunk/sentinel/datadog, a lone alert isn't valid on its own at
    # a `_bulk` endpoint, it's a different wire shape, not just a shorter
    # list. Everything else keeps its already-formatted single envelope.
    # Syslog is never batched regardless of siem_type -- one alert is one
    # datagram, by convention (RFC 5426), and prepare_delivery_attempt
    # already built the right compact body for it.
    if is_syslog or (len(attempts) == 1 and first.siem_type not in NDJSON_BULK_SIEMS):
        payload = first.payload
    else:
        _, payload = format_batch_for_siem([a.alert for a in attempts], first.siem_type, "")
        if isinstance(payload, str):
            # Elastic/wazuh's batched payload is a raw NDJSON body, not a
            # JSON object -- override the single-alert Content-Type
            # accordingly. Auth stays from first.headers (format_batch_for_siem
            # gets an empty auth_token here since the real token is already
            # baked into first.headers from the single-alert format_for_siem
            # call).
            headers = {**first.headers, "Content-Type": "application/x-ndjson"}

    return DeliveryBatch(
        tenant_id=first.tenant_id,
        siem_type=first.siem_type,
        webhook_url=first.webhook_url,
        headers=headers,
        payload=payload,
        attempts=list(attempts),
        verify=first.verify,
    )


def group_into_batches(
    attempts: list[DeliveryAttempt],
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> list[DeliveryBatch]:
    """Group attempts by (tenant, SIEM, webhook) and chunk them into batches.

    Array-envelope SIEMs (``BATCHABLE_SIEMS``) fill up to ``batch_size`` alerts
    per POST; single-document SIEMs (elastic, generic) stay one alert per POST.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")

    grouped: dict[tuple[str, str, str], list[DeliveryAttempt]] = {}
    for attempt in attempts:
        key = (attempt.tenant_id, attempt.siem_type, attempt.webhook_url)
        grouped.setdefault(key, []).append(attempt)

    batches: list[DeliveryBatch] = []
    for (tenant_id, siem_type, url), group_attempts in grouped.items():
        # Same siem_type can be reached over two different transports (e.g.
        # wazuh's bulk API vs. wazuh over syslog) with different batching
        # rules -- syslog is never batched, regardless of what the HTTP
        # transport for that same siem_type would allow.
        if urlparse(url).scheme == "syslog":
            chunk_size = 1
        else:
            chunk_size = batch_size if siem_type in BATCHABLE_SIEMS else 1
        for start in range(0, len(group_attempts), chunk_size):
            batches.append(build_batch(group_attempts[start : start + chunk_size]))

    return batches


def _first_bulk_item_error(response: Any) -> str | None:
    """Return the first per-item error from a Bulk API response, if any.

    A 2xx status only means the HTTP request itself was well-formed; each
    item in the bulk body succeeds or fails independently, and a failure
    (a mapping conflict, a malformed document) only shows up in the
    response body's ``errors``/``items`` fields, never in the status code.
    """
    try:
        body = response.json()
    except ValueError:
        return None
    if not body.get("errors"):
        return None
    for item in body.get("items", []):
        action_result = next(iter(item.values()), {})
        if action_result.get("error"):
            return str(action_result["error"])
    return "unspecified bulk item error"


def deliver_batch(
    batch: DeliveryBatch,
    *,
    post_func: PostFunc = requests.post,
    send_syslog: SyslogSendFunc = send_syslog_udp,
    retries: int = DEFAULT_RETRIES,
    backoff_base: float = BACKOFF_BASE_SECONDS,
) -> DeliveryBatch:
    """Deliver one batch with retry + exponential backoff; returns it with status.

    Scheme decides the transport, not payload type -- elastic/wazuh's bulk
    NDJSON and wazuh/graylog's syslog body are both plain strings, but one
    goes out as an HTTP POST and the other as a raw UDP datagram.
    """
    is_syslog = urlparse(batch.webhook_url).scheme == "syslog"

    for attempt_number in range(retries + 1):
        try:
            if is_syslog:
                send_syslog(batch.webhook_url, batch.payload)
            elif isinstance(batch.payload, str):
                # Elastic/wazuh bulk NDJSON: a preformatted raw body. Must
                # use data=, not json= -- json= would re-serialize the
                # string as a single JSON value and destroy the
                # newline-delimited record structure the Bulk API parses on.
                response = post_func(
                    batch.webhook_url,
                    headers=batch.headers,
                    data=batch.payload.encode("utf-8"),
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    verify=batch.verify,
                )
            else:
                response = post_func(
                    batch.webhook_url,
                    headers=batch.headers,
                    json=batch.payload,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    verify=batch.verify,
                )
        except Exception as exc:  # network layer: any failure is retryable
            error = exc.__class__.__name__
        else:
            if is_syslog:
                # UDP: the send succeeding only means the local kernel
                # accepted the datagram -- there is no delivery confirmation
                # to report. 0 is a sentinel, not a real status code.
                batch.status_code = 0
                return batch
            if 200 <= response.status_code < 300:
                # Elastic/wazuh's Bulk API can return HTTP 200 while
                # individual documents were rejected (e.g. a field-type
                # mapping conflict) -- that per-item result only shows up in
                # the response body, never in the status code. Hit this for
                # real: a "time" field mapping conflict silently dropped
                # documents that this exact check would have caught.
                bulk_error = (
                    _first_bulk_item_error(response) if isinstance(batch.payload, str) else None
                )
                if bulk_error is None:
                    batch.status_code = response.status_code
                    return batch
                error = f"Bulk item error: {bulk_error}"
            else:
                error = f"HTTP {response.status_code}"

        batch.retries += 1
        if attempt_number < retries:
            time.sleep(backoff_base * (2**attempt_number))

    batch.error = error
    return batch


def write_dead_letter(batch: DeliveryBatch, path: Path = DEAD_LETTER_FILE) -> None:
    """Append one permanently-failed batch to the dead-letter queue (JSONL)."""
    record = {
        "timestamp": now_log_time(),
        "tenant_id": batch.tenant_id,
        "siem_type": batch.siem_type,
        "webhook_url": batch.webhook_url,
        "error": batch.error,
        "retries": batch.retries,
        "alerts": [{"domain": a.domain, "severity": a.severity} for a in batch.attempts],
    }
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def deliver_concurrently(
    batches: list[DeliveryBatch],
    *,
    post_func: PostFunc = requests.post,
    send_syslog: SyslogSendFunc = send_syslog_udp,
    max_workers: int = DEFAULT_MAX_WORKERS,
    retries: int = DEFAULT_RETRIES,
) -> None:
    """Deliver batches in parallel with per-tenant isolation.

    One worker slot is submitted per (tenant, SIEM) group. Each group's batches
    run sequentially on its own worker, so a slow or failing tenant can never
    block another tenant, and per-tenant event ordering is preserved.
    """
    groups: dict[tuple[str, str], list[DeliveryBatch]] = {}
    for batch in batches:
        groups.setdefault((batch.tenant_id, batch.siem_type), []).append(batch)

    def deliver_group(group_batches: list[DeliveryBatch]) -> None:
        for batch in group_batches:
            deliver_batch(batch, post_func=post_func, send_syslog=send_syslog, retries=retries)

    worker_count = min(len(groups), max_workers) if groups else 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(deliver_group, group) for group in groups.values()]
        for future in futures:
            future.result()


def run_pipeline(
    tenant_configs: dict[str, dict[str, str]],
    events: Iterable[dict[str, Any]],
    *,
    send: bool = True,
    post_func: PostFunc = requests.post,
    send_syslog: SyslogSendFunc = send_syslog_udp,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_workers: int = DEFAULT_MAX_WORKERS,
    retries: int = DEFAULT_RETRIES,
    dead_letter_file: Path | None = DEAD_LETTER_FILE,
) -> PipelineResult:
    """Run the Data Plane over a stream of raw log documents.

    Each raw document is normalized into the canonical OCSF alert, then
    filtered and formatted. When ``send`` is true the formatted attempts are
    grouped into batches, delivered concurrently with retries, and permanent
    failures are written to the dead-letter queue.
    """
    result = PipelineResult()
    started = time.perf_counter()

    for raw_doc in events:
        result.generated += 1
        alert = normalize_to_ocsf(raw_doc)
        should_deliver, reason = should_deliver_event(alert, tenant_configs)

        if not should_deliver:
            if reason == "unknown_tenant":
                result.dropped_unknown_tenant += 1
            elif reason == "unblocked":
                result.dropped_unblocked += 1
            continue

        tenant_id = alert["tenant"]["uid"]
        attempt = prepare_delivery_attempt(alert, tenant_configs[tenant_id])

        if not send:
            result.delivered += 1
        result.attempts.append(attempt)

    if send and result.attempts:
        batches = group_into_batches(result.attempts, batch_size=batch_size)
        result.delivery_batches = batches
        deliver_concurrently(
            batches,
            post_func=post_func,
            send_syslog=send_syslog,
            max_workers=max_workers,
            retries=retries,
        )

        for batch in batches:
            result.retries += batch.retries
            if batch.error:
                result.failed += len(batch.attempts)
                for attempt in batch.attempts:
                    attempt.error = batch.error
                    attempt.status_code = None
                if dead_letter_file is not None:
                    write_dead_letter(batch, dead_letter_file)
                    result.dlq_written += 1
            else:
                result.delivered += len(batch.attempts)
                for attempt in batch.attempts:
                    attempt.status_code = batch.status_code
                    attempt.error = None

    result.elapsed_seconds = time.perf_counter() - started
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IntelliBron Aman SIEM webhook data plane",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source",
        choices=("synthetic", "real"),
        default="synthetic",
        help="Event source: synthetic demo stream or the real OpenSearch export sample",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of events to process (default: all available)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Maximum alerts per POST for array-envelope SIEMs",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="Parallel delivery workers (one slot per tenant/SIEM group)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help="Delivery retries per batch before dead-lettering",
    )
    args = parser.parse_args()

    print("\n=== IntelliBron Aman SIEM Webhook Data Plane ===\n")

    # Control Plane boundary:
    # The dashboard wrote tenant_configs.json. We only READ it at runtime --
    # no user input, no writes. Config changes flow one way: dashboard -> store.
    tenant_configs = load_tenant_configs()
    if not tenant_configs:
        log_line("ERROR", "no tenant config found; run mock_dashboard.py to enable an integration")
        return

    log_line(
        "INFO",
        "loaded tenant webhook configuration",
        tenants=",".join(sorted(tenant_configs)),
    )

    # Data Plane boundary:
    # This background workflow is the hot path. It consumes a raw event stream,
    # normalizes it to OCSF, silently drops noise, batches, and delivers alerts.
    if args.source == "real":
        log_line("INFO", "using real OpenSearch export", path=str(DEFAULT_EXPORT_CSV))
        events = iter_export_csv(DEFAULT_EXPORT_CSV, limit=args.limit)
    else:
        count = args.limit or LOG_COUNT
        log_line("INFO", "using synthetic event stream", count=count)
        events = generate_opensearch_logs(count)

    log_line(
        "INFO",
        "delivery settings",
        batch_size=args.batch_size,
        max_workers=args.max_workers,
        retries=args.retries,
    )

    result = run_pipeline(
        tenant_configs=tenant_configs,
        events=events,
        send=True,
        batch_size=args.batch_size,
        max_workers=args.max_workers,
        retries=args.retries,
    )

    for attempt in result.attempts:
        log_line(
            "INFO",
            "alert formatted for delivery",
            tenant=attempt.tenant_id,
            siem=attempt.siem_type,
            severity=attempt.severity,
            domain=attempt.domain,
        )

    for batch in result.delivery_batches:
        log_line(
            "INFO",
            "POSTing batch to tenant webhook",
            tenant=batch.tenant_id,
            siem=batch.siem_type,
            alerts=len(batch.attempts),
            url=batch.webhook_url,
        )
        if batch.error:
            log_line(
                "ERROR",
                "batch delivery failed after retries",
                tenant=batch.tenant_id,
                error=batch.error,
                retries=batch.retries,
            )
        else:
            status = f"{batch.status_code} OK" if batch.status_code == 200 else batch.status_code
            log_line(
                "INFO",
                "batch delivery completed",
                tenant=batch.tenant_id,
                alerts=len(batch.attempts),
                status=status,
            )

    throughput = result.delivered / result.elapsed_seconds if result.elapsed_seconds else 0.0
    print()
    log_line(
        "INFO",
        "pipeline run complete",
        generated=result.generated,
        delivered=result.delivered,
        failed=result.failed,
        dropped_unknown_tenant=result.dropped_unknown_tenant,
        dropped_unblocked=result.dropped_unblocked,
        batches=result.batch_count,
        retries=result.retries,
        dlq_written=result.dlq_written,
        elapsed_seconds=round(result.elapsed_seconds, 3),
        delivered_per_sec=round(throughput, 1),
    )


if __name__ == "__main__":
    main()
