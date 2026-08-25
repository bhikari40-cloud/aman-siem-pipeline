from pathlib import Path
import tempfile
import unittest

from ingest import (
    SEVERITY_BY_CATEGORY,
    iter_export_csv,
    normalize_to_ocsf,
)


REAL_BLOCKED_DOC = {
    "@timestamp": "Aug 21, 2026 @ 15:50:36.960",
    "subscriber.id": "qZGVg501KZZFF6364HVGWN5CACKZDFB4",
    "destination.blocked": "true",
    "destination.domain": "malware-command.example",
    "destination.root.domain": "example.com",
    "destination.ip": '["34.101.183.27","203.0.113.9"]',
    "dns.question.type": '["A","A"]',
    "rule.category": "malicious",
    "source.ip": "203.153.118.242",
    "event.dataset": "dns.request",
    "host.name": "IB-DNS",
}

REAL_ALLOWED_DOC = {
    "@timestamp": "Aug 21, 2026 @ 15:50:36.960",
    "subscriber.id": "qZGVg501KZZFF6364HVGWN5CACKZDFB4",
    "destination.blocked": "false",
    "destination.domain": "trusted.example",
    "destination.ip": "[]",
    "dns.question.type": '["A","A","A"]',
    "source.ip": "203.153.118.242",
}


class NormalizerTests(unittest.TestCase):
    def test_normalizes_real_blocked_doc_to_ocsf_dns_activity(self) -> None:
        alert = normalize_to_ocsf(REAL_BLOCKED_DOC)

        self.assertEqual(alert["class_uid"], 4003)
        self.assertEqual(alert["class_name"], "DNS Activity")
        self.assertEqual(alert["activity_name"], "DNS Query")
        self.assertEqual(alert["time"], "2026-08-21T15:50:36.960Z")
        self.assertEqual(alert["disposition"], "Blocked")
        self.assertEqual(alert["action"], "Denied")
        self.assertEqual(alert["severity"], "Critical")
        self.assertEqual(alert["category_name"], "malicious")
        self.assertEqual(alert["tenant"]["uid"], "qZGVg501KZZFF6364HVGWN5CACKZDFB4")
        self.assertEqual(alert["query"]["hostname"], "malware-command.example")
        self.assertEqual(alert["query"]["type"], "A")
        self.assertEqual(alert["src_endpoint"]["ip"], "203.153.118.242")
        self.assertEqual(alert["dst_endpoint"]["ip"], "34.101.183.27")
        self.assertEqual(alert["metadata"]["product"]["name"], "IntelliBron Aman")
        self.assertEqual(alert["metadata"]["event_code"], "dns.request")
        self.assertEqual(alert["metadata"]["device"]["hostname"], "IB-DNS")

    def test_allowed_event_maps_to_allowed_disposition(self) -> None:
        alert = normalize_to_ocsf(REAL_ALLOWED_DOC)

        self.assertEqual(alert["disposition"], "Allowed")
        self.assertEqual(alert["action"], "Allowed")
        self.assertEqual(alert["severity"], "Low")
        self.assertEqual(alert["category_name"], "benign")

    def test_empty_ip_lists_are_omitted(self) -> None:
        alert = normalize_to_ocsf(REAL_ALLOWED_DOC)

        self.assertNotIn("dst_endpoint", alert)
        self.assertIn("src_endpoint", alert)

    def test_missing_source_ip_omits_src_endpoint(self) -> None:
        doc = dict(REAL_BLOCKED_DOC)
        doc.pop("source.ip")
        alert = normalize_to_ocsf(doc)

        self.assertNotIn("src_endpoint", alert)
        self.assertIn("dst_endpoint", alert)

    def test_severity_mapping_for_all_real_categories(self) -> None:
        for category, expected in (
            ("malicious", "Critical"),
            ("suspicious", "High"),
            ("gambling", "Medium"),
            ("advertising", "Medium"),
            ("tracking_telemetry", "Low"),
            ("benign", "Low"),
        ):
            with self.subTest(category=category):
                self.assertEqual(SEVERITY_BY_CATEGORY[category], expected)

    def test_unclassified_event_defaults_to_low(self) -> None:
        doc = dict(REAL_ALLOWED_DOC)
        doc.pop("rule.category", None)
        alert = normalize_to_ocsf(doc)

        self.assertEqual(alert["severity"], "Low")
        self.assertEqual(alert["category_name"], "benign")

    def test_normalizes_nested_synthetic_shape(self) -> None:
        raw = {
            "@timestamp": "2026-08-25T11:49:24.829800+00:00",
            "subscriber": {"id": "tenant-123"},
            "destination": {"domain": "phishing-kit.example", "blocked": True},
            "rule": {"category": "suspicious"},
        }
        alert = normalize_to_ocsf(raw)

        self.assertEqual(alert["tenant"]["uid"], "tenant-123")
        self.assertEqual(alert["disposition"], "Blocked")
        self.assertEqual(alert["severity"], "High")
        self.assertEqual(alert["query"]["hostname"], "phishing-kit.example")
        self.assertEqual(alert["time"], "2026-08-25T11:49:24.829Z")

    def test_missing_blocked_defaults_to_allowed(self) -> None:
        doc = dict(REAL_BLOCKED_DOC)
        doc.pop("destination.blocked")
        alert = normalize_to_ocsf(doc)

        self.assertEqual(alert["disposition"], "Allowed")

    def test_iso_timestamp_with_z_suffix(self) -> None:
        raw = dict(REAL_BLOCKED_DOC)
        raw["@timestamp"] = "2026-08-25T00:00:00Z"
        alert = normalize_to_ocsf(raw)

        self.assertEqual(alert["time"], "2026-08-25T00:00:00.000Z")


class ExportCsvTests(unittest.TestCase):
    def _write_temp_export(self, rows: list[dict]) -> Path:
        import csv as csv_module
        import json

        path = Path(tempfile.mktemp(suffix=".csv"))
        self.addCleanup(path.unlink, missing_ok=True)
        with path.open("w", encoding="utf-8", newline="") as file:
            writer = csv_module.writer(file)
            writer.writerow(["event.ingested", "_source"])
            for row in rows:
                writer.writerow(["", json.dumps(row)])
        return path

    def test_iter_export_csv_yields_raw_docs(self) -> None:
        path = self._write_temp_export([REAL_BLOCKED_DOC, REAL_ALLOWED_DOC])

        docs = list(iter_export_csv(path))

        self.assertEqual(len(docs), 2)
        self.assertEqual(docs[0]["subscriber.id"], "qZGVg501KZZFF6364HVGWN5CACKZDFB4")
        self.assertEqual(docs[1]["destination.blocked"], "false")

    def test_iter_export_csv_respects_limit(self) -> None:
        path = self._write_temp_export([REAL_BLOCKED_DOC, REAL_ALLOWED_DOC])

        docs = list(iter_export_csv(path, limit=1))

        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["destination.blocked"], "true")


if __name__ == "__main__":
    unittest.main()
