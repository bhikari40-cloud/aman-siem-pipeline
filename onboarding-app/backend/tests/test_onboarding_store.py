import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import onboarding_store as store


class OnboardingStoreTests(unittest.TestCase):
    def _tmp_path(self) -> Path:
        path = Path(self.id().replace(".", "_") + ".json")
        self.addCleanup(path.unlink, missing_ok=True)
        self.addCleanup(lambda: path.with_suffix(".json.lock").unlink(missing_ok=True))
        return path

    def test_generate_then_resolve_round_trips(self) -> None:
        path = self._tmp_path()
        token = store.generate_token("tenant-456", label="Acme Corp", path=path)

        record = store.resolve_token(token, path=path)

        self.assertIsNotNone(record)
        self.assertEqual(record["tenant_id"], "tenant-456")
        self.assertEqual(record["status"], "pending")

    def test_resolve_returns_none_for_unknown_token(self) -> None:
        path = self._tmp_path()
        path.write_text("{}", encoding="utf-8")

        self.assertIsNone(store.resolve_token("does-not-exist", path=path))

    def test_token_is_single_use(self) -> None:
        path = self._tmp_path()
        token = store.generate_token("tenant-456", path=path)

        store.mark_token_used(token, path=path)

        self.assertIsNone(store.resolve_token(token, path=path))

    def test_revoked_token_cannot_be_resolved(self) -> None:
        path = self._tmp_path()
        token = store.generate_token("tenant-456", path=path)

        store.revoke_token(token, path=path)

        self.assertIsNone(store.resolve_token(token, path=path))

    def test_revoking_unknown_token_raises(self) -> None:
        path = self._tmp_path()
        path.write_text("{}", encoding="utf-8")

        with self.assertRaises(store.TokenError):
            store.revoke_token("does-not-exist", path=path)

    def test_expired_token_cannot_be_resolved(self) -> None:
        path = self._tmp_path()
        token = store.generate_token("tenant-456", expires_days=30, path=path)

        # Force expiry directly rather than sleeping in a test.
        records = store._load(path)
        records[token]["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        store._atomic_write_json(path, records)

        self.assertIsNone(store.resolve_token(token, path=path))

    def test_list_tokens_returns_all_records(self) -> None:
        path = self._tmp_path()
        store.generate_token("tenant-1", path=path)
        store.generate_token("tenant-2", path=path)

        records = store.list_tokens(path=path)

        self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
