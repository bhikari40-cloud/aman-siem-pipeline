from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Any
import unittest
from unittest import mock

from orchestrator import (
    group_into_batches,
    prepare_delivery_attempt,
    run_pipeline,
    should_deliver_event,
)
from ingest import normalize_to_ocsf
from translator import format_for_siem


@dataclass
class MockResponse:
    status_code: int
    body: dict[str, Any] | None = None

    def json(self) -> dict[str, Any]:
        # Real Elasticsearch/OpenSearch bulk responses always carry an
        # "errors" key -- default to the no-errors shape so existing tests
        # that don't care about bulk-item errors don't need to know this
        # method exists.
        return self.body if self.body is not None else {"errors": False}


def sample_log(
    tenant_id: str = "tenant-123",
    blocked: bool = True,
    category: str = "malicious",
) -> dict[str, Any]:
    return {
        "@timestamp": "2026-08-25T00:00:00Z",
        "subscriber": {"id": tenant_id},
        "destination": {
            "domain": "phishing-kit.example",
            "blocked": blocked,
        },
        "rule": {"category": category},
    }


def sample_alert(
    tenant_id: str = "tenant-123",
    blocked: bool = True,
    category: str = "malicious",
) -> dict[str, Any]:
    return normalize_to_ocsf(sample_log(tenant_id, blocked, category))


def sample_configs() -> dict[str, dict[str, str]]:
    return {
        "tenant-123": {
            "tenant_id": "tenant-123",
            "siem_type": "splunk",
            "webhook_url": "https://example.com/webhook",
            "auth_token": "secret",
        }
    }


class OrchestratorTests(unittest.TestCase):
    def test_should_deliver_event_enforces_tenant_isolation(self) -> None:
        should_deliver, reason = should_deliver_event(
            sample_alert("tenant-999"),
            sample_configs(),
        )

        self.assertFalse(should_deliver)
        self.assertEqual(reason, "unknown_tenant")

    def test_should_deliver_event_drops_unblocked_events(self) -> None:
        should_deliver, reason = should_deliver_event(
            sample_alert("tenant-123", blocked=False),
            sample_configs(),
        )

        self.assertFalse(should_deliver)
        self.assertEqual(reason, "unblocked")

    def test_should_deliver_event_reads_normalized_alert(self) -> None:
        alert = normalize_to_ocsf(sample_log(category="malicious"))
        should_deliver, reason = should_deliver_event(alert, sample_configs())

        self.assertTrue(should_deliver)
        self.assertEqual(reason, "deliver")
        self.assertEqual(alert["severity"], "Critical")
        self.assertEqual(alert["tenant"]["uid"], "tenant-123")
        self.assertEqual(alert["query"]["hostname"], "phishing-kit.example")

    def test_format_for_siem_uses_splunk_envelope(self) -> None:
        headers, payload = format_for_siem({"message": "blocked"}, "splunk", "token")

        self.assertEqual(headers, {"Authorization": "Splunk token"})
        self.assertEqual(payload, {"event": {"message": "blocked"}})

    def test_format_for_siem_uses_sentinel_batch(self) -> None:
        headers, payload = format_for_siem({"message": "blocked"}, "sentinel", "token")

        self.assertEqual(headers, {"Authorization": "Bearer token"})
        self.assertEqual(payload, [{"message": "blocked"}])

    def test_format_for_siem_uses_elastic_api_key(self) -> None:
        headers, payload = format_for_siem({"message": "blocked"}, "elastic", "token")

        self.assertEqual(headers, {"Authorization": "ApiKey token"})
        self.assertEqual(payload, {"message": "blocked"})

    def test_prepare_delivery_attempt_uses_siem_formatter(self) -> None:
        alert = normalize_to_ocsf(sample_log())
        attempt = prepare_delivery_attempt(alert, sample_configs()["tenant-123"])

        self.assertEqual(attempt.siem_type, "splunk")
        self.assertEqual(attempt.headers["Authorization"], "Splunk secret")
        self.assertEqual(attempt.payload["event"], alert)
        self.assertEqual(attempt.redacted_headers["Authorization"], "Splunk ***")

    def test_run_pipeline_can_dry_run_without_network(self) -> None:
        result = run_pipeline(
            tenant_configs=sample_configs(),
            events=[
                sample_log("tenant-123", blocked=True),
                sample_log("tenant-999", blocked=True),
                sample_log("tenant-123", blocked=False),
            ],
            send=False,
        )

        self.assertEqual(result.generated, 3)
        self.assertEqual(result.delivered, 1)
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.dropped_unknown_tenant, 1)
        self.assertEqual(result.dropped_unblocked, 1)
        self.assertEqual(len(result.attempts), 1)

    def test_run_pipeline_accepts_injected_http_client(self) -> None:
        calls = []

        def fake_post(*args: Any, **kwargs: Any) -> MockResponse:
            calls.append((args, kwargs))
            return MockResponse(status_code=202)

        result = run_pipeline(
            tenant_configs=sample_configs(),
            events=[sample_log("tenant-123", blocked=True)],
            send=True,
            post_func=fake_post,
        )

        self.assertEqual(result.delivered, 1)
        self.assertEqual(result.batch_count, 1)
        self.assertEqual(result.attempts[0].status_code, 202)
        self.assertEqual(calls[0][0], ("https://example.com/webhook",))
        self.assertEqual(calls[0][1]["json"], result.attempts[0].payload)


class BatchingTests(unittest.TestCase):
    def test_group_into_batches_chunks_batchable_siem_and_singles_others(self) -> None:
        events = [sample_log("tenant-123", blocked=True) for _ in range(5)]
        attempts = run_pipeline(sample_configs(), events, send=False).attempts

        splunk_batches = group_into_batches(attempts, batch_size=2)
        self.assertEqual([len(b.attempts) for b in splunk_batches], [2, 2, 1])
        self.assertTrue(all(b.siem_type == "splunk" for b in splunk_batches))

        # elastic batches via Bulk NDJSON, same chunking as the JSON-array SIEMs
        for attempt in attempts:
            attempt.siem_type = "elastic"
        elastic_batches = group_into_batches(attempts, batch_size=2)
        self.assertEqual([len(b.attempts) for b in elastic_batches], [2, 2, 1])

        # generic is not batchable: every alert ships as its own POST
        for attempt in attempts:
            attempt.siem_type = "generic"
        generic_batches = group_into_batches(attempts, batch_size=2)
        self.assertEqual([len(b.attempts) for b in generic_batches], [1, 1, 1, 1, 1])

    def test_lone_elastic_or_wazuh_attempt_still_batches_as_ndjson(self) -> None:
        # Regression: build_batch used to keep format_for_siem's plain-JSON
        # single-alert envelope whenever there was exactly one attempt, even
        # for elastic/wazuh -- but their webhook_url is a `_bulk` endpoint,
        # which rejects a bare JSON object. A lone alert must still be
        # wrapped as a one-record Bulk NDJSON body.
        for siem_type in ("elastic", "wazuh"):
            attempts = run_pipeline(
                sample_configs() | {
                    "tenant-123": {**sample_configs()["tenant-123"], "siem_type": siem_type},
                },
                [sample_log("tenant-123", blocked=True)],
                send=False,
            ).attempts
            batches = group_into_batches(attempts, batch_size=10)

            self.assertEqual(len(batches), 1)
            self.assertIsInstance(batches[0].payload, str)
            self.assertEqual(batches[0].headers["Content-Type"], "application/x-ndjson")
            lines = batches[0].payload.rstrip("\n").split("\n")
            self.assertEqual(lines[0], '{"index":{}}')

    def test_syslog_target_dispatches_to_send_syslog_not_post_func(self) -> None:
        syslog_calls = []
        post_calls = []

        def fake_send_syslog(webhook_url: str, message: str) -> None:
            syslog_calls.append((webhook_url, message))

        def fake_post(*args: Any, **kwargs: Any) -> MockResponse:
            post_calls.append((args, kwargs))
            return MockResponse(status_code=200)

        syslog_configs = {
            "tenant-123": {
                "tenant_id": "tenant-123",
                "siem_type": "wazuh",
                "webhook_url": "syslog://10.2.10.200:514",
                "auth_token": "unused",
            }
        }

        result = run_pipeline(
            tenant_configs=syslog_configs,
            events=[sample_log("tenant-123", blocked=True) for _ in range(5)],
            send=True,
            post_func=fake_post,
            send_syslog=fake_send_syslog,
            batch_size=10,
        )

        # one datagram per alert, never batched, even though "wazuh" is
        # normally a BATCHABLE_SIEMS member over its HTTP/bulk transport
        self.assertEqual(len(syslog_calls), 5)
        self.assertEqual(post_calls, [])
        self.assertEqual(result.delivered, 5)
        self.assertEqual(result.batch_count, 5)
        for webhook_url, message in syslog_calls:
            self.assertEqual(webhook_url, "syslog://10.2.10.200:514")
            self.assertTrue(message.startswith("<"))  # RFC 5424 PRI header

    def test_run_pipeline_batches_alerts_into_single_post(self) -> None:
        calls = []

        def fake_post(*args: Any, **kwargs: Any) -> MockResponse:
            calls.append((args, kwargs))
            return MockResponse(status_code=200)

        result = run_pipeline(
            tenant_configs=sample_configs(),
            events=[sample_log("tenant-123", blocked=True) for _ in range(5)],
            send=True,
            post_func=fake_post,
            batch_size=10,
        )

        self.assertEqual(result.batch_count, 1)
        self.assertEqual(len(calls), 1)
        payload = calls[0][1]["json"]
        self.assertEqual(len(payload), 5)
        self.assertTrue(all("event" in item for item in payload))
        self.assertEqual(result.delivered, 5)

    def test_run_pipeline_batches_elastic_as_bulk_ndjson(self) -> None:
        calls = []

        def fake_post(*args: Any, **kwargs: Any) -> MockResponse:
            calls.append((args, kwargs))
            return MockResponse(status_code=200)

        elastic_configs = {
            "tenant-123": {
                "tenant_id": "tenant-123",
                "siem_type": "elastic",
                "webhook_url": "https://example.com/_bulk",
                "auth_token": "secret",
            }
        }

        result = run_pipeline(
            tenant_configs=elastic_configs,
            events=[sample_log("tenant-123", blocked=True) for _ in range(3)],
            send=True,
            post_func=fake_post,
            batch_size=10,
        )

        self.assertEqual(result.batch_count, 1)
        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]

        # data=, not json= -- json= would corrupt the NDJSON body.
        self.assertNotIn("json", kwargs)
        self.assertIn("data", kwargs)
        self.assertIsInstance(kwargs["data"], bytes)
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/x-ndjson")

        body = kwargs["data"].decode("utf-8")
        self.assertTrue(body.endswith("\n"))
        lines = body.rstrip("\n").split("\n")
        self.assertEqual(len(lines), 6)  # 3 alerts x (action line + source line)
        self.assertEqual(lines[0], '{"index":{}}')
        self.assertEqual(result.delivered, 3)

    def test_run_pipeline_catches_bulk_item_errors_despite_http_200(self) -> None:
        # Real failure mode this project hit: Elasticsearch's Bulk API
        # returns HTTP 200 even when an individual document was rejected
        # (e.g. a field-type mapping conflict) -- the rejection only shows
        # up in the response body. Code that only checks the status code
        # treats this as a full success and silently loses the document.
        bulk_response_with_error = {
            "errors": True,
            "items": [
                {
                    "index": {
                        "status": 400,
                        "error": {
                            "type": "document_parsing_exception",
                            "reason": "failed to parse field [time] of type [long]",
                        },
                    }
                }
            ],
        }

        def fake_post(*args: Any, **kwargs: Any) -> MockResponse:
            return MockResponse(status_code=200, body=bulk_response_with_error)

        elastic_configs = {
            "tenant-123": {
                "tenant_id": "tenant-123",
                "siem_type": "elastic",
                "webhook_url": "https://example.com/_bulk",
                "auth_token": "secret",
            }
        }

        with mock.patch("orchestrator.time.sleep"):
            result = run_pipeline(
                tenant_configs=elastic_configs,
                events=[sample_log("tenant-123", blocked=True)],
                send=True,
                post_func=fake_post,
                retries=0,
                dead_letter_file=None,
            )

        self.assertEqual(result.delivered, 0)
        self.assertEqual(result.failed, 1)
        self.assertIn("document_parsing_exception", result.attempts[0].error)

    def test_run_pipeline_retries_then_succeeds(self) -> None:
        calls = []

        def flaky_post(*args: Any, **kwargs: Any) -> MockResponse:
            calls.append((args, kwargs))
            if len(calls) < 3:
                raise ConnectionError("boom")
            return MockResponse(status_code=200)

        with mock.patch("orchestrator.time.sleep"):
            result = run_pipeline(
                tenant_configs=sample_configs(),
                events=[sample_log("tenant-123", blocked=True)],
                send=True,
                post_func=flaky_post,
                retries=2,
            )

        self.assertEqual(len(calls), 3)
        self.assertEqual(result.retries, 2)
        self.assertEqual(result.delivered, 1)
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.attempts[0].status_code, 200)
        self.assertEqual(result.attempts[0].error, None)

    def test_run_pipeline_dead_letters_permanent_failure(self) -> None:
        dlq_path = Path(tempfile.mktemp(suffix=".jsonl"))
        self.addCleanup(dlq_path.unlink, missing_ok=True)

        def always_fail(*args: Any, **kwargs: Any) -> MockResponse:
            raise ConnectionError("down")

        with mock.patch("orchestrator.time.sleep"):
            result = run_pipeline(
                tenant_configs=sample_configs(),
                events=[sample_log("tenant-123", blocked=True)],
                send=True,
                post_func=always_fail,
                retries=1,
                dead_letter_file=dlq_path,
            )

        self.assertEqual(result.failed, 1)
        self.assertEqual(result.delivered, 0)
        self.assertEqual(result.dlq_written, 1)
        self.assertEqual(result.attempts[0].error, "ConnectionError")
        self.assertEqual(result.attempts[0].status_code, None)

        records = [json.loads(line) for line in dlq_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["tenant_id"], "tenant-123")
        self.assertEqual(records[0]["error"], "ConnectionError")
        self.assertEqual(records[0]["retries"], 2)


if __name__ == "__main__":
    unittest.main()
