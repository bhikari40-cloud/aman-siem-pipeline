"""Data-only catalog describing what the onboarding form should ask for and
show, per SIEM type and (where a type has more than one) per transport.

No guidance prose lives here on purpose -- customer-facing copy goes through
Brian's normal copywriting review (the `hikari` skill / an HTML-preview pass),
not authored ad hoc inside this data structure. `guidance_key` is a slot a
separate copy dict fills in later; until that pass happens, the frontend
falls back to rendering `native_alerting`/`status` as plain labels.

Status is assigned per TRANSPORT, not per siem_type: Wazuh's two transports
(and Graylog's) land on opposite native-alerting outcomes even though they
share a siem_type, so a single per-SIEM status would misrepresent one of them.
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path
from typing import TypedDict

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from config_store import SUPPORTED_SIEMS  # noqa: E402


class SiemStatus(str, Enum):
    VERIFIED = "verified"  # confirmed end-to-end against a real instance of this SIEM
    UNTESTED = "untested"  # translator.py has a real wire format for it, never verified live
    VENDOR_BLOCKED = "vendor_blocked"  # our side works; a defect on the vendor's side blocks the outcome
    NOT_IMPLEMENTED = "not_implemented"  # in SUPPORTED_SIEMS, but translator.py has no dedicated branch


class FieldSpec(TypedDict):
    name: str  # key in the onboarding POST body: "auth_token" | "username" | "password"
    label: str  # placeholder copy -- TBD via the copywriting pass
    kind: str  # "text" | "password" | "url"
    required: bool


class TransportSpec(TypedDict):
    key: str  # "http" | "bulk_http" | "syslog" | "gelf_http"
    url_scheme: str  # must match what config_store.validate_webhook_url accepts (http/https/syslog)
    url_example: str  # UI placeholder only -- config_store still owns real validation
    fields: list[FieldSpec]
    status: SiemStatus | None  # None only for "generic" -- see its entry below for why
    native_alerting: str | None  # "yes" | "no" | "vendor_blocked" | None (no concept of a native alert here)
    guidance_key: str


class SiemSpec(TypedDict):
    key: str
    label: str
    transports: dict[str, TransportSpec]
    default_transport: str


_TOKEN_FIELD: FieldSpec = {
    "name": "auth_token",
    "label": "Auth token",
    "kind": "password",
    "required": True,
}

_WAZUH_USER_FIELDS: list[FieldSpec] = [
    {"name": "username", "label": "Username", "kind": "text", "required": True},
    {"name": "password", "label": "Password", "kind": "password", "required": True},
]

SIEM_CATALOG: dict[str, SiemSpec] = {
    "elastic": {
        "key": "elastic",
        "label": "Elastic",
        "default_transport": "http",
        "transports": {
            "http": {
                "key": "http",
                "url_scheme": "https",
                "url_example": "https://your-elastic-host:9200/<index>/_bulk",
                "fields": [_TOKEN_FIELD],
                "status": SiemStatus.VERIFIED,
                "native_alerting": "yes",
                "guidance_key": "elastic.http",
            },
        },
    },
    "wazuh": {
        "key": "wazuh",
        "label": "Wazuh",
        "default_transport": "syslog",
        "transports": {
            "syslog": {
                "key": "syslog",
                "url_scheme": "syslog",
                "url_example": "syslog://your-wazuh-manager-host:514",
                "fields": [],  # network path is the only access control -- no auth fields at all
                "status": SiemStatus.VERIFIED,
                "native_alerting": "yes",
                "guidance_key": "wazuh.syslog",
            },
            "bulk_http": {
                "key": "bulk_http",
                "url_scheme": "https",
                "url_example": "https://your-wazuh-indexer-host:9200/<index>/_bulk",
                "fields": _WAZUH_USER_FIELDS,
                "status": SiemStatus.VERIFIED,
                "native_alerting": "no",
                "guidance_key": "wazuh.bulk_http",
            },
        },
    },
    "graylog": {
        "key": "graylog",
        "label": "Graylog",
        "default_transport": "gelf_http",
        "transports": {
            "gelf_http": {
                "key": "gelf_http",
                "url_scheme": "https",
                "url_example": "https://your-graylog-host:12202/gelf",
                "fields": [],  # no auth configured on the GELF HTTP input
                "status": SiemStatus.VERIFIED,
                "native_alerting": None,  # data delivery verified; native-alerting untested on this path
                "guidance_key": "graylog.gelf_http",
            },
            "syslog": {
                "key": "syslog",
                "url_scheme": "syslog",
                "url_example": "syslog://your-graylog-host:1514",
                "fields": [],
                "status": SiemStatus.VENDOR_BLOCKED,
                "native_alerting": "vendor_blocked",
                "guidance_key": "graylog.syslog",
            },
        },
    },
    "splunk": {
        "key": "splunk",
        "label": "Splunk",
        "default_transport": "http",
        "transports": {
            "http": {
                "key": "http",
                "url_scheme": "https",
                # /services/collector/raw, not the bare /services/collector --
                # the currently-shipping pipeline (ecs_syslog_webhook.py) posts
                # a plain-text syslog line, and /services/collector is the
                # JSON *event* endpoint: it 400s ("Invalid data format") on
                # anything that isn't valid JSON. /raw is Splunk HEC's own
                # unstructured-text endpoint. Confirmed live 2026-09-01.
                "url_example": "https://your-splunk-host:8088/services/collector/raw",
                "fields": [_TOKEN_FIELD],
                "status": SiemStatus.VERIFIED,
                "native_alerting": None,
                "guidance_key": "splunk.http",
            },
        },
    },
    "sentinel": {
        "key": "sentinel",
        "label": "Microsoft Sentinel",
        "default_transport": "http",
        "transports": {
            "http": {
                "key": "http",
                "url_scheme": "https",
                "url_example": "https://your-sentinel-endpoint",
                "fields": [_TOKEN_FIELD],
                "status": SiemStatus.UNTESTED,
                "native_alerting": None,
                "guidance_key": "sentinel.http",
            },
        },
    },
    "datadog": {
        "key": "datadog",
        "label": "Datadog",
        "default_transport": "http",
        "transports": {
            "http": {
                "key": "http",
                "url_scheme": "https",
                "url_example": "https://http-intake.logs.datadoghq.com/api/v2/logs",
                "fields": [_TOKEN_FIELD],
                "status": SiemStatus.UNTESTED,
                "native_alerting": None,
                "guidance_key": "datadog.http",
            },
        },
    },
    "sumologic": {
        "key": "sumologic",
        "label": "Sumo Logic",
        "default_transport": "http",
        "transports": {
            "http": {
                "key": "http",
                "url_scheme": "https",
                "url_example": "https://your-sumologic-collector-url",
                "fields": [_TOKEN_FIELD],
                "status": SiemStatus.NOT_IMPLEMENTED,
                "native_alerting": None,
                "guidance_key": "sumologic.http",
            },
        },
    },
    "crowdstrike": {
        "key": "crowdstrike",
        "label": "CrowdStrike Falcon LogScale",
        "default_transport": "http",
        "transports": {
            "http": {
                "key": "http",
                "url_scheme": "https",
                "url_example": "https://your-logscale-host/api/v1/ingest",
                "fields": [_TOKEN_FIELD],
                "status": SiemStatus.NOT_IMPLEMENTED,
                "native_alerting": None,
                "guidance_key": "crowdstrike.http",
            },
        },
    },
    "generic": {
        "key": "generic",
        "label": "Generic / Custom Webhook",
        "default_transport": "http",
        "transports": {
            "http": {
                "key": "http",
                "url_scheme": "https",
                "url_example": "https://your-webhook-url",
                "fields": [_TOKEN_FIELD],
                # Not a real vendor to verify against -- intentionally not
                # scored verified/untested/blocked/not_implemented like the
                # others, since none of those claims make sense for a
                # deliberate fallback target. Status is omitted; the
                # frontend shows this as a plain "raw delivery only" option.
                "status": None,
                "native_alerting": "no",
                "guidance_key": "generic.http",
            },
        },
    },
}


def get_catalog() -> dict[str, SiemSpec]:
    assert set(SIEM_CATALOG) == SUPPORTED_SIEMS, (
        "SIEM_CATALOG has drifted from config_store.SUPPORTED_SIEMS -- "
        f"catalog={set(SIEM_CATALOG)!r} supported={SUPPORTED_SIEMS!r}"
    )
    return SIEM_CATALOG
