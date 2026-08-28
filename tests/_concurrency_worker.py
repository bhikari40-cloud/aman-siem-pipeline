"""Standalone worker invoked as a real subprocess by test_config_store_concurrency.

Must run as its own `python3` process (not a thread, not multiprocessing) --
the race this proves out (fcntl.flock across separate `python3` invocations)
is exactly what happens when the onboarding FastAPI backend and the Streamlit
dashboard both call save_tenant_config at roughly the same moment.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config_store import save_tenant_config

if __name__ == "__main__":
    config_path = Path(sys.argv[1])
    tenant_id = sys.argv[2]
    save_tenant_config(
        {
            "tenant_id": tenant_id,
            "siem_type": "generic",
            "webhook_url": "http://httpbin.org/post",
            "auth_token": f"token-for-{tenant_id}",
        },
        path=config_path,
    )
