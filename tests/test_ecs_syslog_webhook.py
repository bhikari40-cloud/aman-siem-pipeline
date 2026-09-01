from __future__ import annotations

import json
import unittest
from dataclasses import dataclass
from typing import Any

from ecs_syslog_webhook import (
    build_ecs_syslog_line,
    deliver_to_webhook,
    run_simple_pipeline,
)
from ingest import normalize_to_ocsf


@dataclass
class MockResponse:
    status_code: int


def sample_log(
    tenant_id: str = "tenant-123",
    blocked: bool = True,
    category: str = "malicious",
) -> dict[str, Any]:
    return {
        "@timestamp": "2026-08-25T00:00:00Z",
        "subscriber.id": tenant_id,
        "destination.domain": "phishing-kit.example",
        "destination.blocked": blocked,
        "rule.category": category,
        # normalize_to_ocsf reads source.ip as a flat dotted key (no nested
        # fallback tuple passed for this field) -- see ingest.py.
        "source.ip": "203.153.118.242",
    }


def sample_alert(**kwargs: Any) -> dict[str, Any]:
    return normalize_to_ocsf(sample_log(**kwargs))


def sample_configs(webhook_url: str = "https://example.com/webhook") -> dict[str, dict[str, str]]:
    # Same shape onboarding_store.build_tenant_config saves into
    # tenant_configs.json -- this is what a real customer submission looks
    # like once config_store.normalize_config has validated it.
    return {
        "tenant-123": {
            "tenant_id": "tenant-123",
            "siem_type": "generic",
            "webhook_url": webhook_url,
            "auth_token": "secret",
        }
    }


def _parse_body(line: str) -> dict[str, Any]:
    # Header is everything up to the 7th space-separated field; MSG starts
    # right after ("- - - " is PROCID/MSGID/STRUCTURED-DATA, all unused here).
    _, body_text = line.split("- - - ", 1)
    return json.loads(body_text)


class BuildEcsSyslogLineTests(unittest.TestCase):
    def test_critical_severity_sets_pri_and_header_fields(self) -> None:
        alert = sample_alert(category="malicious")  # -> Critical
        line = build_ecs_syslog_line(alert)

        # facility 4 (security) * 8 + level 2 (critical) = 34
        self.assertTrue(line.startswith("<34>1 "))
        self.assertIn("aman-pipeline aman-dns - - - ", line)

    def test_body_carries_ecs_fields_and_severity(self) -> None:
        alert = sample_alert(category="malicious")
        body = _parse_body(build_ecs_syslog_line(alert))

        self.assertEqual(body["severity"], "Critical")
        self.assertEqual(body["dns"]["question"]["name"], "phishing-kit.example")
        self.assertEqual(body["event"]["action"], "blocked")
        self.assertEqual(body["source"]["ip"], "203.153.118.242")
        self.assertIn("@timestamp", body)


class DeliverToWebhookTests(unittest.TestCase):
    def test_sends_bearer_auth_and_text_plain_content_type(self) -> None:
        captured: dict[str, Any] = {}

        def fake_post(url: str, **kwargs: Any) -> MockResponse:
            captured["url"] = url
            captured.update(kwargs)
            return MockResponse(status_code=200)

        tenant_config = sample_configs()["tenant-123"]
        response = deliver_to_webhook(tenant_config, "<34>1 line", post_func=fake_post)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(captured["url"], "https://example.com/webhook")
        self.assertEqual(captured["headers"]["Content-Type"], "text/plain")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer secret")
        self.assertEqual(captured["data"], b"<34>1 line")
        self.assertTrue(captured["verify"])

    def test_splunk_gets_splunk_auth_scheme_not_bearer(self) -> None:
        # Real Splunk HEC 401s on "Bearer <token>" -- confirmed 2026-09-01
        # against a live instance, see PROGRESS.md. Locks in the one
        # per-SIEM exception documented in the module docstring.
        captured: dict[str, Any] = {}

        def fake_post(url: str, **kwargs: Any) -> MockResponse:
            captured.update(kwargs)
            return MockResponse(status_code=200)

        tenant_config = {
            "tenant_id": "tenant-splunk",
            "siem_type": "splunk",
            "webhook_url": "https://splunk.example/services/collector",
            "auth_token": "secret",
        }
        deliver_to_webhook(tenant_config, "<34>1 line", post_func=fake_post)

        self.assertEqual(captured["headers"]["Authorization"], "Splunk secret")


class RunSimplePipelineTests(unittest.TestCase):
    def test_delivers_blocked_events_to_that_tenants_own_webhook(self) -> None:
        captured: dict[str, Any] = {}

        def fake_post(url: str, **kwargs: Any) -> MockResponse:
            captured["url"] = url
            return MockResponse(status_code=200)

        result = run_simple_pipeline(sample_configs(), [sample_log()], post_func=fake_post)

        self.assertEqual(result.generated, 1)
        self.assertEqual(result.delivered, 1)
        self.assertEqual(result.failed, 0)
        self.assertEqual(captured["url"], "https://example.com/webhook")

    def test_two_customers_each_get_only_their_own_webhook(self) -> None:
        configs = {
            "tenant-a": {"tenant_id": "tenant-a", "siem_type": "generic",
                         "webhook_url": "https://a.example/webhook", "auth_token": "a-secret"},
            "tenant-b": {"tenant_id": "tenant-b", "siem_type": "generic",
                         "webhook_url": "https://b.example/webhook", "auth_token": "b-secret"},
        }
        hits: list[str] = []

        def fake_post(url: str, **kwargs: Any) -> MockResponse:
            hits.append(url)
            return MockResponse(status_code=200)

        events = [sample_log(tenant_id="tenant-a"), sample_log(tenant_id="tenant-b")]
        result = run_simple_pipeline(configs, events, post_func=fake_post)

        self.assertEqual(result.delivered, 2)
        self.assertEqual(sorted(hits), ["https://a.example/webhook", "https://b.example/webhook"])

    def test_drops_unblocked_events_without_posting(self) -> None:
        def fail_if_called(*args: Any, **kwargs: Any) -> MockResponse:
            raise AssertionError("should not POST an unblocked event")

        result = run_simple_pipeline(
            sample_configs(),
            [sample_log(blocked=False)],
            post_func=fail_if_called,
        )

        self.assertEqual(result.dropped_unblocked, 1)
        self.assertEqual(result.delivered, 0)

    def test_drops_unknown_tenant_without_posting(self) -> None:
        # A tenant_id with no matching onboarding submission yet (or one
        # from a completely different customer's data) never gets a POST.
        def fail_if_called(*args: Any, **kwargs: Any) -> MockResponse:
            raise AssertionError("should not POST for an unconfigured tenant")

        result = run_simple_pipeline(
            sample_configs(),
            [sample_log(tenant_id="tenant-not-onboarded-yet")],
            post_func=fail_if_called,
        )

        self.assertEqual(result.dropped_unknown_tenant, 1)
        self.assertEqual(result.delivered, 0)

    def test_skips_syslog_scheme_webhook_without_posting(self) -> None:
        # A customer who picked Wazuh/Graylog's syslog transport during
        # onboarding gets a syslog:// webhook_url -- this pipeline has no
        # UDP transport, so that tenant is skipped, not sent to the wrong
        # place, and everyone else still gets delivered.
        def fail_if_called(*args: Any, **kwargs: Any) -> MockResponse:
            raise AssertionError("syslog:// targets belong to orchestrator.py, not this module")

        result = run_simple_pipeline(
            sample_configs(webhook_url="syslog://10.2.10.200:514"),
            [sample_log()],
            post_func=fail_if_called,
        )

        self.assertEqual(result.dropped_unsupported_transport, 1)
        self.assertEqual(result.delivered, 0)

    def test_one_bad_tenant_does_not_block_delivery_to_others(self) -> None:
        configs = {
            "tenant-bad": {"tenant_id": "tenant-bad", "siem_type": "generic",
                           "webhook_url": "syslog://10.2.10.200:514", "auth_token": ""},
            "tenant-good": {"tenant_id": "tenant-good", "siem_type": "generic",
                            "webhook_url": "https://good.example/webhook", "auth_token": "secret"},
        }
        hits: list[str] = []

        def fake_post(url: str, **kwargs: Any) -> MockResponse:
            hits.append(url)
            return MockResponse(status_code=200)

        events = [sample_log(tenant_id="tenant-bad"), sample_log(tenant_id="tenant-good")]
        result = run_simple_pipeline(configs, events, post_func=fake_post)

        self.assertEqual(result.dropped_unsupported_transport, 1)
        self.assertEqual(result.delivered, 1)
        self.assertEqual(hits, ["https://good.example/webhook"])

    def test_counts_failed_on_non_2xx_response(self) -> None:
        result = run_simple_pipeline(
            sample_configs(),
            [sample_log()],
            post_func=lambda *a, **k: MockResponse(status_code=500),
        )

        self.assertEqual(result.failed, 1)
        self.assertEqual(result.delivered, 0)

    def test_counts_failed_on_post_exception(self) -> None:
        def raising_post(*args: Any, **kwargs: Any) -> MockResponse:
            raise ConnectionError("boom")

        result = run_simple_pipeline(sample_configs(), [sample_log()], post_func=raising_post)

        self.assertEqual(result.failed, 1)
        self.assertEqual(result.delivered, 0)


if __name__ == "__main__":
    unittest.main()
