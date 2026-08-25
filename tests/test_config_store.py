from pathlib import Path
import unittest


from config_store import ConfigError, load_tenant_configs, save_tenant_config


class ConfigStoreTests(unittest.TestCase):
    def test_save_tenant_config_upserts_by_tenant(self) -> None:
        with self.subTest("new config file"):
            config_path = Path(self.id().replace(".", "_") + ".json")
            self.addCleanup(config_path.unlink, missing_ok=True)

            saved = save_tenant_config(
                {
                    "tenant_id": "tenant-123",
                    "siem_type": "Splunk",
                    "webhook_url": "https://example.com/webhook",
                    "auth_token": "secret",
                },
                path=config_path,
            )

            self.assertEqual(saved["siem_type"], "splunk")
            self.assertEqual(load_tenant_configs(config_path), {"tenant-123": saved})

    def test_load_tenant_configs_accepts_legacy_single_object(self) -> None:
        config_path = Path(self.id().replace(".", "_") + ".json")
        self.addCleanup(config_path.unlink, missing_ok=True)
        config_path.write_text(
            """
            {
              "tenant_id": "tenant-123",
              "siem_type": "generic",
              "webhook_url": "http://httpbin.org/post",
              "auth_token": "secret"
            }
            """,
            encoding="utf-8",
        )

        configs = load_tenant_configs(config_path)

        self.assertEqual(list(configs), ["tenant-123"])
        self.assertEqual(configs["tenant-123"]["webhook_url"], "http://httpbin.org/post")

    def test_save_tenant_config_rejects_bad_url(self) -> None:
        config_path = Path(self.id().replace(".", "_") + ".json")
        self.addCleanup(config_path.unlink, missing_ok=True)

        with self.assertRaisesRegex(ConfigError, "Webhook URL"):
            save_tenant_config(
                {
                    "tenant_id": "tenant-123",
                    "siem_type": "generic",
                    "webhook_url": "not-a-url",
                    "auth_token": "secret",
                },
                path=config_path,
            )

    def test_load_tenant_configs_is_cached_until_file_changes(self) -> None:
        config_path = Path(self.id().replace(".", "_") + ".json")
        self.addCleanup(config_path.unlink, missing_ok=True)
        config_path.write_text(
            '{"tenant-123": {"tenant_id": "tenant-123", "siem_type": "splunk", "webhook_url": "https://a.example", "auth_token": "one"}}',
            encoding="utf-8",
        )

        first = load_tenant_configs(config_path)
        second = load_tenant_configs(config_path)

        # Cache hit: same values, and independent copies (no shared mutation)
        self.assertEqual(first, second)
        self.assertIsNot(first["tenant-123"], second["tenant-123"])

        # A save invalidates the cache via the changed file signature
        saved = save_tenant_config(
            {
                "tenant_id": "tenant-123",
                "siem_type": "sentinel",
                "webhook_url": "https://b.example",
                "auth_token": "two",
            },
            path=config_path,
        )

        after_save = load_tenant_configs(config_path)
        self.assertEqual(after_save["tenant-123"]["siem_type"], "sentinel")
        self.assertEqual(after_save["tenant-123"]["auth_token"], "two")
        self.assertNotEqual(after_save, first)


if __name__ == "__main__":
    unittest.main()
