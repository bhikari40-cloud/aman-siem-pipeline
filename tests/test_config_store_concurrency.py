"""Regression test for the save_tenant_config race fix (flock + atomic write).

Before the fix, save_tenant_config was a plain read-modify-write with no lock:
two processes racing to save DIFFERENT tenants could each read the file before
either had written, then each write back a full-file copy missing the other's
change -- a silent lost update, distinct from a torn/corrupt file. This is
exercised with real `python3` subprocesses (see _concurrency_worker.py), not
threads: the risk only exists across separate OS processes (the onboarding
API and the Streamlit dashboard both writing tenant_configs.json), which
threading within one interpreter wouldn't reproduce.
"""

import json
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from config_store import load_tenant_configs

WORKER = Path(__file__).with_name("_concurrency_worker.py")
WORKER_COUNT = 20


class ConfigStoreConcurrencyTests(unittest.TestCase):
    def test_concurrent_writers_never_produce_a_torn_file_and_never_lose_an_update(self) -> None:
        config_path = Path(self.id().replace(".", "_") + ".json")
        self.addCleanup(config_path.unlink, missing_ok=True)
        self.addCleanup(lambda: config_path.with_suffix(".json.lock").unlink(missing_ok=True))
        config_path.write_text("{}", encoding="utf-8")

        torn_reads: list[str] = []
        stop_reading = threading.Event()

        def reader() -> None:
            while not stop_reading.is_set():
                try:
                    text = config_path.read_text(encoding="utf-8")
                    if text:
                        json.loads(text)
                except (json.JSONDecodeError, OSError) as exc:
                    torn_reads.append(str(exc))
                time.sleep(0.001)

        reader_thread = threading.Thread(target=reader, daemon=True)
        reader_thread.start()

        tenant_ids = [f"concurrent-tenant-{i}" for i in range(WORKER_COUNT)]
        processes = [
            subprocess.Popen([sys.executable, str(WORKER), str(config_path), tenant_id])
            for tenant_id in tenant_ids
        ]
        for process in processes:
            self.assertEqual(process.wait(timeout=30), 0)

        stop_reading.set()
        reader_thread.join(timeout=5)

        self.assertEqual(torn_reads, [], "a reader observed an invalid/torn JSON file mid-write")

        final = load_tenant_configs(config_path)
        missing = set(tenant_ids) - set(final)
        self.assertEqual(missing, set(), "a concurrent writer's save was silently lost")
        for tenant_id in tenant_ids:
            self.assertEqual(final[tenant_id]["auth_token"], f"token-for-{tenant_id}")


if __name__ == "__main__":
    unittest.main()
