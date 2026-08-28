"""Storage for single-use customer onboarding links.

A record maps an opaque token to a tenant_id, so a customer never sees or
edits their own tenant_id directly (mirrors dashboard_app.py's existing
comment that tenant_id "comes from the authenticated user session" -- here
it comes from the token instead, since there's no real auth system in this
POC). Tokens are single-use: resolve_token refuses anything already
"used"/"revoked"/expired, and the onboarding API marks a token "used" the
moment its submission is saved -- a leaked link can't be replayed later to
redirect that customer's alerts somewhere else.
"""

from __future__ import annotations

import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from config_store import _atomic_write_json  # noqa: E402 -- reuse the same torn-write fix, not a copy of it

TOKENS_FILE = REPO_ROOT / "onboarding_tokens.json"


class TokenError(ValueError):
    """Raised for an invalid token operation (e.g. revoking one that doesn't exist)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    return _load_locked(path)


def _load_locked(path: Path) -> dict[str, dict[str, Any]]:
    import json

    with path.open("r", encoding="utf-8") as file:
        text = file.read()
    return json.loads(text) if text.strip() else {}


def _with_lock_and_save(path: Path, mutate) -> dict[str, Any]:
    """Run ``mutate(records) -> (result, records)`` under an exclusive flock,
    then atomically persist ``records``. Same read-inside-the-lock shape as
    config_store.save_tenant_config, for the same reason: this file can be
    written by the FastAPI backend and the ops CLI at different moments, and
    a lock only around the write (not the read) wouldn't prevent a lost update.
    """
    import fcntl

    lock_path = path.with_suffix(path.suffix + ".lock")
    with open(lock_path, "w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            records = _load(path)
            result, records = mutate(records)
            _atomic_write_json(path, records)
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
    return result


def generate_token(
    tenant_id: str,
    label: str = "",
    expires_days: int = 30,
    path: Path = TOKENS_FILE,
) -> str:
    """Create a new single-use onboarding link token for ``tenant_id``."""
    tenant_id = tenant_id.strip()
    if not tenant_id:
        raise TokenError("tenant_id is required")

    token = secrets.token_urlsafe(24)
    now = _now()
    record = {
        "tenant_id": tenant_id,
        "label": label.strip(),
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=expires_days)).isoformat(),
        "status": "pending",
    }

    def mutate(records: dict[str, dict[str, Any]]):
        records[token] = record
        return token, records

    return _with_lock_and_save(path, mutate)


def resolve_token(token: str, path: Path = TOKENS_FILE) -> dict[str, Any] | None:
    """Return the token's record if it's usable, else None.

    None covers every reason a caller must treat identically for security
    (don't leak *why* a token failed): unknown, revoked, expired, or already
    used. The API layer turns None into one generic 404/410, never a message
    that distinguishes these cases to the client.
    """
    records = _load(path)
    record = records.get(token)
    if record is None:
        return None
    if record["status"] != "pending":
        return None
    if datetime.fromisoformat(record["expires_at"]) < _now():
        return None
    return dict(record)


def mark_token_used(token: str, path: Path = TOKENS_FILE) -> None:
    def mutate(records: dict[str, dict[str, Any]]):
        if token in records:
            records[token]["status"] = "used"
            records[token]["used_at"] = _now().isoformat()
        return None, records

    _with_lock_and_save(path, mutate)


def revoke_token(token: str, path: Path = TOKENS_FILE) -> None:
    def mutate(records: dict[str, dict[str, Any]]):
        if token not in records:
            raise TokenError(f"No such token: {token}")
        records[token]["status"] = "revoked"
        return None, records

    _with_lock_and_save(path, mutate)


def list_tokens(path: Path = TOKENS_FILE) -> dict[str, dict[str, Any]]:
    """Return all token records, for the ops CLI's `list` command."""
    return _load(path)
