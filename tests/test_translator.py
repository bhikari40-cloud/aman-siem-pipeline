import unittest

from translator import BATCHABLE_SIEMS, format_batch_for_siem, format_for_siem


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

    def test_format_for_fallback_uses_bearer_raw_json(self) -> None:
        headers, payload = format_for_siem({"message": "blocked"}, "unknown", "token")

        self.assertEqual(headers, {"Authorization": "Bearer token"})
        self.assertEqual(payload, {"message": "blocked"})

    def test_format_for_siem_rejects_non_dict_payload(self) -> None:
        with self.assertRaisesRegex(TypeError, "ocsf_data"):
            format_for_siem(["not", "a", "dict"], "generic", "token")  # type: ignore[arg-type]


class TranslatorBatchTests(unittest.TestCase):
    def test_batchable_siems(self) -> None:
        self.assertEqual(BATCHABLE_SIEMS, frozenset({"splunk", "sentinel", "datadog"}))

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
            format_batch_for_siem([{"a": 1}], "elastic", "token")

    def test_batch_does_not_mutate_input_alerts(self) -> None:
        alerts = [{"a": 1}, {"a": 2}]
        _, payload = format_batch_for_siem(alerts, "splunk", "token")

        self.assertEqual(alerts, [{"a": 1}, {"a": 2}])
        payload[0]["event"]["a"] = 99
        self.assertEqual(alerts[0]["a"], 1)


if __name__ == "__main__":
    unittest.main()
