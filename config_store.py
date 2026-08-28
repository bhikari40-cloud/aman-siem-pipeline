"""Shared tenant integration configuration storage for the SIEM POC."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CONFIG_FILE = Path("tenant_configs.json")
SUPPORTED_SIEMS = {
    "splunk",
    "sentinel",
    "elastic",
    "datadog",
    "sumologic",
    "crowdstrike",
    "graylog",
    "wazuh",
    "generic",
}


class ConfigError(ValueError):
    """Raised when tenant integration configuration is invalid."""


def normalize_siem_type(siem_type: str | None) -> str:
    """Return a supported lowercase SIEM key."""
    normalized = (siem_type or "generic").strip().lower()
    return normalized if normalized in SUPPORTED_SIEMS else "generic"


def validate_webhook_url(webhook_url: str) -> str:
    """Validate and return a clean webhook/target URL.

    ``syslog://host:port`` is accepted alongside http(s) -- it addresses a
    UDP socket, not an HTTP endpoint, but it's still "where this tenant's
    alerts go" and lives in the same field for that reason.
    """
    cleaned_url = (webhook_url or "").strip()
    parsed = urlparse(cleaned_url)

    if parsed.scheme not in {"http", "https", "syslog"} or not parsed.netloc:
        raise ConfigError("Webhook URL must be a valid http://, https://, or syslog:// URL")

    return cleaned_url


def normalize_config(raw_config: dict[str, Any]) -> dict[str, str]:
    """Normalize one tenant config record into the canonical schema."""
    if not isinstance(raw_config, dict):
        raise ConfigError("Tenant config must be a dictionary")

    tenant_id = str(raw_config.get("tenant_id", "")).strip()
    auth_token = str(raw_config.get("auth_token", "")).strip()

    if not tenant_id:
        raise ConfigError("Tenant ID is required")
    if not auth_token:
        raise ConfigError("Auth token is required")

    return {
        "tenant_id": tenant_id,
        "siem_type": normalize_siem_type(str(raw_config.get("siem_type", "generic"))),
        "webhook_url": validate_webhook_url(str(raw_config.get("webhook_url", ""))),
        "auth_token": auth_token,
        # Self-hosted SIEMs (e.g. Wazuh's bundled indexer) commonly run on a
        # self-signed cert -- default true (verify) and let a tenant opt out.
        "verify_ssl": bool(raw_config.get("verify_ssl", True)),
    }


def normalize_config_file_shape(raw_data: Any) -> dict[str, dict[str, str]]:
    """
    Normalize config files into ``{tenant_id: config}``.

    Earlier demo versions saved either a single config object or a tenant-keyed
    mapping. Supporting both keeps the POC forgiving while the UI evolves.
    """
    if not raw_data:
        return {}

    if isinstance(raw_data, dict) and "tenant_id" in raw_data:
        config = normalize_config(raw_data)
        return {config["tenant_id"]: config}

    if not isinstance(raw_data, dict):
        raise ConfigError("Config file must contain a JSON object")

    configs: dict[str, dict[str, str]] = {}
    for tenant_id, tenant_config in raw_data.items():
        if not isinstance(tenant_config, dict):
            raise ConfigError(f"Config for {tenant_id} must be a dictionary")

        merged_config = {"tenant_id": tenant_id, **tenant_config}
        normalized = normalize_config(merged_config)
        configs[normalized["tenant_id"]] = normalized

    return configs


def _file_signature(path: Path) -> tuple[int, int] | None:
    """Return ``(mtime_ns, size)`` for the config file, or ``None`` if absent."""
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


def _parse_configs(path: Path) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8") as file:
        return normalize_config_file_shape(json.load(file))


# Stat-based cache: keyed by resolved path, invalidated when mtime or size
# changes (i.e. automatically on every save). No manual invalidation required.
_CONFIG_CACHE: dict[Path, tuple[tuple[int, int], dict[str, dict[str, str]]]] = {}


def load_tenant_configs(path: Path = CONFIG_FILE) -> dict[str, dict[str, str]]:
    """Load all tenant integration configs from disk.

    Results are cached per file signature (mtime + size) and invalidate
    automatically whenever the file is saved. A copy is returned so callers
    can never mutate the cached entry.
    """
    signature = _file_signature(path)
    if signature is not None:
        cached = _CONFIG_CACHE.get(path)
        if cached is not None and cached[0] == signature:
            return {key: dict(value) for key, value in cached[1].items()}

    if not path.exists():
        return {}

    configs = _parse_configs(path)
    if signature is not None:
        _CONFIG_CACHE[path] = (signature, configs)
    return {key: dict(value) for key, value in configs.items()}


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write ``data`` as JSON without ever leaving a torn/partial file on disk.

    A plain ``open(path, "w")`` truncates immediately, so a crash mid-``json.dump``
    (or a reader opening the file at that instant) sees invalid JSON. Writing to a
    sibling temp file first and ``os.replace``-ing it in is atomic on POSIX --
    readers always see either the old file or the fully-written new one.
    """
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            json.dump(data, tmp_file, indent=2)
            tmp_file.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        os.unlink(tmp_name)
        raise


def save_tenant_config(
    tenant_config: dict[str, Any],
    path: Path = CONFIG_FILE,
) -> dict[str, str]:
    """Validate and upsert one tenant config into the mock config database.

    Holds an exclusive ``flock`` across the whole read-modify-write. This
    matters once more than one process can write concurrently (e.g. the
    onboarding API alongside the Streamlit dashboard): without it, two writers
    that both read before either writes will each write back a full-file copy
    missing the other's change -- a silent lost update, not just a torn file.
    The load must happen *inside* the lock; locking only around the write (with
    an unlocked read beforehand, as this function used to do) does not prevent
    that race.
    """
    normalized = normalize_config(tenant_config)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with open(lock_path, "w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            configs = load_tenant_configs(path)
            configs[normalized["tenant_id"]] = normalized
            _atomic_write_json(path, configs)
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)

    return normalized


def public_config(config: dict[str, str]) -> dict[str, str]:
    """Return a UI/log-safe config preview."""
    preview = dict(config)
    if preview.get("auth_token"):
        preview["auth_token"] = "********"
    return preview
