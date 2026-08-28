import base64
import json
import unittest

from translator import BATCHABLE_SIEMS, format_batch_for_siem, format_for_siem, format_for_syslog


class TranslatorTests(unittest.TestCase):
    def test_format_for_splunk_wraps_event_and_auth_scheme(self) -> None:
        headers, payload = format_for_siem({"message": "blocked"}, "splunk", "token")

        self.assertEqual(headers, {"Authorization": "Splunk token"})
        self.assertEqual(payload, {"event": {"message": "blocked"}})

    def test_format_for_sentinel_returns_batch_list(self) -> None:
        headers, payload = format_for_siem({"message": "blocked"}, "sentinel", "token")

        self.assertEqual(headers, {"Authorization": "Bearer token"})
        self.assertEqual(payload, [{"message": "blocked"}])

    def test_format_for_elastic_uses_api_key(self) -> None:
        headers, payload = format_for_siem({"message": "blocked"}, "elastic", "token")

        self.assertEqual(headers, {"Authorization": "ApiKey token"})
        self.assertEqual(payload, {"message": "blocked"})

    def test_format_for_wazuh_uses_basic_auth(self) -> None:
        headers, payload = format_for_siem({"message": "blocked"}, "wazuh", "admin:SecretPassword")

        expected = base64.b64encode(b"admin:SecretPassword").decode("ascii")
        self.assertEqual(headers, {"Authorization": f"Basic {expected}"})
        self.assertEqual(payload, {"message": "blocked"})

    def test_format_for_graylog_builds_gelf_message(self) -> None:
        alert = {
            "disposition": "Blocked",
            "severity": "High",
            "query": {"hostname": "evil.example"},
            "tenant": {"uid": "tenant-123"},
            "time": 1787658141034,
        }
        headers, payload = format_for_siem(alert, "graylog", "unused")

        self.assertEqual(headers, {})
        self.assertEqual(payload["version"], "1.1")
        self.assertEqual(payload["short_message"], "Blocked DNS query: evil.example")
        self.assertEqual(payload["level"], 3)  # High -> syslog "error"
        self.assertEqual(payload["_domain"], "evil.example")
        self.assertEqual(payload["_tenant_uid"], "tenant-123")

    def test_format_for_fallback_uses_bearer_raw_json(self) -> None:
        headers, payload = format_for_siem({"message": "blocked"}, "unknown", "token")

        self.assertEqual(headers, {"Authorization": "Bearer token"})
        self.assertEqual(payload, {"message": "blocked"})

    def test_format_for_siem_rejects_non_dict_payload(self) -> None:
        with self.assertRaisesRegex(TypeError, "ocsf_data"):
            format_for_siem(["not", "a", "dict"], "generic", "token")  # type: ignore[arg-type]


class TranslatorBatchTests(unittest.TestCase):
    def test_batchable_siems(self) -> None:
        self.assertEqual(
            BATCHABLE_SIEMS,
            frozenset({"splunk", "sentinel", "datadog", "elastic", "wazuh"}),
        )

    def test_splunk_batch_wraps_each_alert_in_event(self) -> None:
        headers, payload = format_batch_for_siem(
            [{"a": 1}, {"a": 2}],
            "splunk",
            "token",
        )

        self.assertEqual(headers, {"Authorization": "Splunk token"})
        self.assertEqual(payload, [{"event": {"a": 1}}, {"event": {"a": 2}}])

    def test_sentinel_batch_is_plain_list(self) -> None:
        headers, payload = format_batch_for_siem(
            [{"a": 1}, {"a": 2}],
            "sentinel",
            "token",
        )

        self.assertEqual(headers, {"Authorization": "Bearer token"})
        self.assertEqual(payload, [{"a": 1}, {"a": 2}])

    def test_datadog_batch_uses_api_key_header_and_list(self) -> None:
        headers, payload = format_batch_for_siem(
            [{"a": 1}, {"a": 2}],
            "datadog",
            "token",
        )

        self.assertEqual(headers, {"DD-API-KEY": "token"})
        self.assertEqual(payload, [{"a": 1}, {"a": 2}])

    def test_batch_rejects_non_batchable_siem(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not support batched delivery"):
            format_batch_for_siem([{"a": 1}], "generic", "token")

    def test_elastic_batch_returns_bulk_ndjson_body(self) -> None:
        headers, payload = format_batch_for_siem(
            [{"a": 1}, {"a": 2}],
            "elastic",
            "token",
        )

        self.assertEqual(headers, {"Content-Type": "application/x-ndjson"})
        self.assertIsInstance(payload, str)
        self.assertTrue(payload.endswith("\n"))

        lines = payload.rstrip("\n").split("\n")
        self.assertEqual(lines, [
            '{"index":{}}',
            '{"a":1}',
            '{"index":{}}',
            '{"a":2}',
        ])

    def test_wazuh_batch_reuses_elastic_bulk_ndjson_shape(self) -> None:
        headers, payload = format_batch_for_siem([{"a": 1}, {"a": 2}], "wazuh", "token")

        self.assertEqual(headers, {"Content-Type": "application/x-ndjson"})
        lines = payload.rstrip("\n").split("\n")
        self.assertEqual(lines, [
            '{"index":{}}',
            '{"a":1}',
            '{"index":{}}',
            '{"a":2}',
        ])

    def test_elastic_batch_normalizes_time_and_adds_ecs_timestamp(self) -> None:
        # Elasticsearch's dynamic mapping locks "time" to whichever type it
        # sees first (long here, from an epoch-millis producer) -- a later
        # alert with a string time would hard-fail with a
        # document_parsing_exception against that same index. Normalizing
        # both time and @timestamp to the same ISO string removes the
        # conflict, and also gives Kibana's detection rules/Discover an
        # actual date-typed field to query against.
        _, payload = format_batch_for_siem(
            [{"a": 1, "time": 1787743900000}], "elastic", "token",
        )
        lines = payload.rstrip("\n").split("\n")
        doc = json.loads(lines[1])
        self.assertEqual(doc["a"], 1)
        self.assertEqual(doc["time"], "2026-08-26T11:31:40.000Z")
        self.assertEqual(doc["@timestamp"], "2026-08-26T11:31:40.000Z")

    def test_elastic_batch_leaves_alerts_without_time_untouched(self) -> None:
        _, payload = format_batch_for_siem([{"a": 1}], "elastic", "token")
        doc = json.loads(payload.rstrip("\n").split("\n")[1])
        self.assertNotIn("@timestamp", doc)

    def test_elastic_batch_ndjson_lines_are_not_pretty_printed(self) -> None:
        _, payload = format_batch_for_siem([{"a": 1, "b": 2}], "elastic", "token")

        for line in payload.rstrip("\n").split("\n"):
            self.assertNotIn(" ", line)

    def test_batch_does_not_mutate_input_alerts(self) -> None:
        alerts = [{"a": 1}, {"a": 2}]
        _, payload = format_batch_for_siem(alerts, "splunk", "token")

        self.assertEqual(alerts, [{"a": 1}, {"a": 2}])
        payload[0]["event"]["a"] = 99
        self.assertEqual(alerts[0]["a"], 1)


def sample_full_alert() -> dict:
    """A realistically full OCSF alert -- includes fields that syslog
    formatting should drop (metadata, unmapped, answers) alongside the ones
    it should keep, so the compactness tests actually prove something.
    """
    return {
        "severity": "High",
        "disposition": "Blocked",
        "time": 1787658141034,
        "query": {"hostname": "evil.example", "type": "A"},
        "src_endpoint": {"ip": "203.153.118.242"},
        "tenant": {"uid": "tenant-123"},
        "firewall_rule": {"name": "malicious"},
        "metadata": {"product": {"name": "IntelliBron Aman", "vendor_name": "ITSEC Asia"}, "uid": "req-1"},
        "unmapped": {"subscriber_id": "sub-1", "source_geo_org": "Example ISP"},
        "answers": [{"rdata": "1.2.3.4", "type": "A"}],
    }


class SyslogFormatTests(unittest.TestCase):
    def test_wazuh_syslog_body_is_compact_json(self) -> None:
        line = format_for_syslog(sample_full_alert(), "wazuh")

        self.assertRegex(line, r"^<\d+>1 \S+ aman-pipeline aman-dns - - - \{.*\}$")
        body = line.split(" - - - ", 1)[1]
        parsed = json.loads(body)
        self.assertEqual(parsed, {
            "domain": "evil.example",
            "src_ip": "203.153.118.242",
            "severity": "High",
            "tenant": "tenant-123",
            "rule": "malicious",
        })
        # dropped fields must not leak into the compact body
        self.assertNotIn("metadata", body)
        self.assertNotIn("unmapped", body)
        self.assertNotIn("subscriber_id", body)

    def test_graylog_syslog_body_is_compact_key_value(self) -> None:
        line = format_for_syslog(sample_full_alert(), "graylog")
        body = line.split(" - - - ", 1)[1]

        self.assertEqual(
            body,
            'domain="evil.example" src_ip="203.153.118.242" severity="High" '
            'tenant="tenant-123" rule="malicious"',
        )
        self.assertNotIn("metadata", body)
        self.assertNotIn("subscriber_id", body)

    def test_syslog_severity_maps_to_pri(self) -> None:
        critical_line = format_for_syslog({**sample_full_alert(), "severity": "Critical"}, "wazuh")
        pri = int(critical_line.split(">", 1)[0].lstrip("<"))
        # facility 4 (security/authorization) * 8 + syslog level 2 (critical)
        self.assertEqual(pri, 4 * 8 + 2)

    def test_syslog_omits_none_fields(self) -> None:
        minimal_alert = {"severity": "Low", "query": {}, "tenant": {}}
        line = format_for_syslog(minimal_alert, "wazuh")
        body = line.split(" - - - ", 1)[1]

        self.assertEqual(json.loads(body), {"severity": "Low"})


if __name__ == "__main__":
    unittest.main()
