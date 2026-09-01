"""Minimal ECS-over-syslog delivery pipeline -- pushes data, not native alerts.

SCOPE, DELIBERATELY NARROW
===========================
orchestrator.py/translator.py already build each SIEM's own *native alert*:
Kibana detection rules, Wazuh's custom decoder/rules, per-platform schema
mapping (Splunk CIM / Sentinel ASIM / Datadog Standard Attributes), GELF for
Graylog. That's real, working, and stays untouched here -- a future customer
may still need it.

This module answers a separate, narrower ask: push each blocked alert to a
customer's own SIEM webhook, in ECS field names, framed as a single RFC 5424
syslog line, over a plain HTTP POST -- no per-SIEM branching, no native-alert
provisioning, no batching, no retry/DLQ.

ONE EXCEPTION: THE LOGIN HEADER
================================
Real Splunk's HTTP Event Collector hard-requires "Authorization: Splunk
<token>" -- this module's generic "Bearer <token>" default gets a flat 401
from it, confirmed 2026-09-01 against a live instance (see PROGRESS.md).
That's not a format/style choice we can defer the way native-alert
formatting is; it's the one thing that decides whether a Splunk customer's
data arrives at all. _AUTH_SCHEME_BY_SIEM is a single-entry exception for
that one hard requirement -- every other siem_type, including any future
one, still gets the same generic Bearer header. This does not reopen the
no-per-SIEM-branching decision for message format, batching, or retries.

A "webhook" is an HTTP(S) POST to a URL (TCP, gets a real status code back).
That is NOT the same thing as orchestrator.send_syslog_udp, which opens a
raw UDP socket with no delivery confirmation -- this module never touches
that transport. The syslog-line *formatting* (RFC 5424 header) is reused
here purely as a text convention for the POST body, not as a reason to use
UDP.

MULTIPLE CUSTOMERS, EACH WITH THEIR OWN WEBHOOK
================================================
The onboarding app (onboarding-app/) lets each customer submit their own
webhook_url/auth_token through a one-time link and saves it into
tenant_configs.json under the tenant_id that link was issued for -- the
same config file/format orchestrator.py already reads. This module reuses
that unchanged: config_store.load_tenant_configs() for the config, and
orchestrator.should_deliver_event() for the exact same tenant-isolation +
blocked-only check the full engine already uses, tested. Nothing new is
invented here -- this is the minimum glue needed to make what onboarding
already collects actually go somewhere, in the plain ECS/syslog shape.

This is a different "tenant" question than the *raw ClickHouse feed's*
missing customer field (see ARCHITECTURE.md's known limitation): there,
the ambiguity is which real-world customer a raw DNS log row belongs to.
Here, the tenant_id is assigned deliberately by whoever issues the
onboarding link (onboarding_cli.py generate --tenant-id ...) -- a real,
intentional mapping, not a guess.

Reuses (does not duplicate) the already-correct pieces of the existing
pipeline: ingest.normalize_to_ocsf (severity enrichment + canonical OCSF
shape), orchestrator.should_deliver_event (tenant isolation + blocked-only
filter), and translator's syslog PRI/timestamp helpers + ECS field mapper.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

import requests

import translator
from config_store import load_tenant_configs
from data_generator import generate_opensearch_logs
from ingest import DEFAULT_EXPORT_CSV, iter_export_csv, normalize_to_ocsf
from orchestrator import log_line, should_deliver_event

REQUEST_TIMEOUT_SECONDS = 10
LOG_COUNT = 20

# See "ONE EXCEPTION: THE LOGIN HEADER" in the module docstring -- Splunk is
# the only siem_type whose auth scheme this module knows about; every other
# key falls back to the generic Bearer header in deliver_to_webhook.
_AUTH_SCHEME_BY_SIEM = {"splunk": "Splunk"}

PostFunc = Callable[..., Any]


@dataclass
class SimpleDeliveryResult:
    """Summary counters for one run. No attempts/batches list -- unlike
    orchestrator.PipelineResult, there is nothing here worth replaying or
    re-batching; a caller that wants that should use orchestrator.py.
    """

    generated: int = 0
    delivered: int = 0
    dropped_unknown_tenant: int = 0
    dropped_unblocked: int = 0
    dropped_unsupported_transport: int = 0
    failed: int = 0


def build_ecs_syslog_line(alert: dict[str, Any]) -> str:
    """Build one RFC 5424 syslog line whose MSG body is the alert in ECS
    field names.

    Severity is carried in two places on purpose: the syslog PRI value
    (syslog's own severity-level convention -- translator._SEVERITY_TO_SYSLOG_LEVEL,
    same mapping the existing UDP path already uses) and a plain top-level
    ``severity`` field in the body. ECS itself deliberately leaves
    ``event.severity`` unset (see translator._ecs_fields) since it is an
    open numeric field with no fixed scale -- a plain string field is the
    only place our severity can live without inventing an ECS convention
    that does not exist.

    Unlike translator._compact_syslog_fields (built for the raw-UDP path,
    where a dropped/fragmented datagram risks corrupting the whole
    message), this line travels over HTTP/TCP -- there is no truncation
    risk to design around, so the full ECS-mapped alert goes in the body.
    """
    severity = str(alert.get("severity", "")).lower()
    level = translator._SEVERITY_TO_SYSLOG_LEVEL.get(severity, 6)
    pri = translator._SYSLOG_FACILITY_SECURITY * 8 + level
    timestamp = translator._normalize_timestamp(alert.get("time"))

    body = {
        "@timestamp": timestamp,
        **translator._ecs_fields(alert),
        "severity": alert.get("severity"),
    }

    return (
        f"<{pri}>1 {timestamp} aman-pipeline aman-dns - - - "
        f"{json.dumps(body, separators=(',', ':'))}"
    )


def deliver_to_webhook(
    tenant_config: dict[str, str],
    line: str,
    *,
    post_func: PostFunc = requests.post,
) -> Any:
    """POST one syslog line to this tenant's own webhook (the URL/token
    they submitted through the onboarding page).

    No retry/backoff/DLQ -- see module docstring. The body is a syslog
    text line (the JSON only starts partway through, after the RFC 5424
    header), so Content-Type is text/plain, not application/json.
    """
    headers = {"Content-Type": "text/plain"}
    auth_token = tenant_config.get("auth_token", "")
    if auth_token:
        scheme = _AUTH_SCHEME_BY_SIEM.get(tenant_config.get("siem_type", ""), "Bearer")
        headers["Authorization"] = f"{scheme} {auth_token}"

    return post_func(
        tenant_config["webhook_url"],
        headers=headers,
        data=line.encode("utf-8"),
        timeout=REQUEST_TIMEOUT_SECONDS,
        verify=tenant_config.get("verify_ssl", True),
    )


def run_simple_pipeline(
    tenant_configs: dict[str, dict[str, str]],
    events: Iterable[dict[str, Any]],
    *,
    post_func: PostFunc = requests.post,
) -> SimpleDeliveryResult:
    """Normalize -> tenant match + blocked-only filter -> ECS/syslog line -> POST.

    Sequential, one alert per request -- no batching or concurrency. Each
    event is delivered to the webhook *that specific tenant* submitted
    through onboarding -- not one fixed global URL -- so multiple customers
    each get only their own data, at their own address.

    A tenant onboarded with a syslog:// webhook (Wazuh/Graylog's raw-UDP
    transport option) is skipped here, not sent, and counted separately --
    this pipeline is HTTP-webhook-only by definition; a customer who picked
    that transport needs orchestrator.py's engine instead, not this one.
    One bad/unsupported tenant is skipped, not fatal to the rest.
    """
    result = SimpleDeliveryResult()

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
        tenant_config = tenant_configs[tenant_id]

        if urlparse(tenant_config["webhook_url"]).scheme not in {"http", "https"}:
            result.dropped_unsupported_transport += 1
            log_line(
                "WARNING",
                "tenant webhook_url is not http(s); skipping (raw-UDP syslog "
                "targets belong to orchestrator.py, not this pipeline)",
                tenant=tenant_id,
                webhook_url=tenant_config["webhook_url"],
            )
            continue

        line = build_ecs_syslog_line(alert)

        try:
            response = deliver_to_webhook(tenant_config, line, post_func=post_func)
        except Exception as exc:  # network layer: log and move on, no retry
            result.failed += 1
            log_line("ERROR", "webhook delivery failed", tenant=tenant_id, error=exc.__class__.__name__)
            continue

        if 200 <= response.status_code < 300:
            result.delivered += 1
        else:
            result.failed += 1
            log_line("ERROR", "webhook rejected delivery", tenant=tenant_id, status=response.status_code)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IntelliBron Aman -- ECS/syslog-over-webhook pipeline (simple, no native alerting)",
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
    args = parser.parse_args()

    print("\n=== IntelliBron Aman -- ECS/syslog-over-webhook pipeline ===\n")

    tenant_configs = load_tenant_configs()
    if not tenant_configs:
        log_line("ERROR", "no tenant config found -- send a customer their onboarding link "
                  "(onboarding_cli.py generate) so they can submit a webhook first")
        return

    if args.source == "real":
        log_line("INFO", "using real OpenSearch export", path=str(DEFAULT_EXPORT_CSV))
        events = iter_export_csv(DEFAULT_EXPORT_CSV, limit=args.limit)
    else:
        count = args.limit or LOG_COUNT
        log_line("INFO", "using synthetic event stream", count=count)
        events = generate_opensearch_logs(count)

    result = run_simple_pipeline(tenant_configs, events)

    print()
    log_line(
        "INFO",
        "pipeline run complete",
        generated=result.generated,
        delivered=result.delivered,
        failed=result.failed,
        dropped_unknown_tenant=result.dropped_unknown_tenant,
        dropped_unblocked=result.dropped_unblocked,
        dropped_unsupported_transport=result.dropped_unsupported_transport,
    )


if __name__ == "__main__":
    main()
