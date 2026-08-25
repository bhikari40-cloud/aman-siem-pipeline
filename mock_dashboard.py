"""Interactive mock of the IntelliBron Aman customer-facing dashboard.

CONTROL PLANE / USERFLOW
=======================
This script simulates the dashboard a customer uses to enable a SIEM webhook
integration. It only captures and persists *configuration* (tenant, SIEM type,
webhook URL, auth token). It never reads, parses, or routes security logs --
that is the job of the Data Plane (orchestrator.py).

The dashboard writes a single JSON file (tenant_configs.json) that acts as our
mock "config database". The orchestrator reads it at runtime, read-only.
"""

from __future__ import annotations

import json
from pathlib import Path


CONFIG_FILE = Path("tenant_configs.json")
DEFAULT_TENANT_ID = "tenant-123"
DEFAULT_WEBHOOK_URL = "http://httpbin.org/post"

# Menu key -> (display label, canonical siem_type key).
SIEM_TYPES = {
    "1": ("Splunk", "splunk"),
    "2": ("Elastic", "elastic"),
    "3": ("Sentinel", "sentinel"),
}


def prompt_with_default(label: str, default: str) -> str:
    """Prompt for a value, falling back to ``default`` on an empty Enter."""
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def load_existing_configs() -> dict[str, dict[str, str]]:
    """Load saved tenant SIEM settings from the mock config database."""
    if not CONFIG_FILE.exists():
        return {}

    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def select_siem_type() -> str:
    """Ask the user which SIEM they want to receive Aman alerts."""
    print("\nSelect SIEM type:")
    for key, (label, _siem_key) in SIEM_TYPES.items():
        print(f"  {key}. {label}")

    while True:
        choice = input("Choice [1]: ").strip() or "1"
        if choice in SIEM_TYPES:
            return SIEM_TYPES[choice][1]

        print("Invalid choice. Please select 1, 2, or 3.")


def main() -> None:
    print("=== IntelliBron Aman Dashboard ===")
    print("Customer SIEM Integration Setup\n")

    # Control Plane: collect config only. No security data passes through here.
    tenant_id = prompt_with_default("Tenant ID", DEFAULT_TENANT_ID)
    siem_type = select_siem_type()
    webhook_url = prompt_with_default("Webhook URL", DEFAULT_WEBHOOK_URL)
    auth_token = input("Auth Token: ").strip()

    configs = load_existing_configs()
    configs[tenant_id] = {
        "tenant_id": tenant_id,
        "siem_type": siem_type,
        "webhook_url": webhook_url,
        "auth_token": auth_token,
    }

    with CONFIG_FILE.open("w", encoding="utf-8") as file:
        json.dump(configs, file, indent=2)
        file.write("\n")

    print("\nSIEM Integration Enabled (Fire & Forget Active).")


if __name__ == "__main__":
    main()
