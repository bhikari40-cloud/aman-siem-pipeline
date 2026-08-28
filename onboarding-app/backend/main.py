"""Customer-facing onboarding API.

Lets an end customer submit their own SIEM webhook + auth token, resolved
through a single-use onboarding link rather than a free-text tenant_id field
(see onboarding_store.py for why). Delegates all tenant-config validation to
config_store.py -- this module only knows how to turn one onboarding
submission into the shape config_store already expects, plus the one
Wazuh-specific wrinkle (auth_token as "user:pass") translator.py requires.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# NOTE: config_store.CONFIG_FILE is CWD-relative, not relative to the module's
# own location -- every call below passes path=TENANT_CONFIG_PATH explicitly.
# Omitting it would silently read/write a different tenant_configs.json
# depending on wherever this process's cwd happens to be when uvicorn starts
# it, with no error anywhere ("saved fine, pipeline never delivers").
TENANT_CONFIG_PATH = REPO_ROOT / "tenant_configs.json"

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from config_store import ConfigError, load_tenant_configs, public_config, save_tenant_config  # noqa: E402
from onboarding_store import TOKENS_FILE, mark_token_used, resolve_token  # noqa: E402
from schemas import OnboardingStateResponse, OnboardingSubmission, SubmissionResult  # noqa: E402
from siem_catalog import get_catalog  # noqa: E402

app = FastAPI(title="Aman SIEM Pipeline — Customer Onboarding")

# Dev-only: Vite's default port. A real deployment would restrict this to the
# actual onboarding frontend's origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _require_token(token: str) -> dict:
    record = resolve_token(token, path=TOKENS_FILE)
    if record is None:
        # One generic 404 for every failure reason (unknown / expired /
        # already used / revoked) -- distinguishing them to the client would
        # leak whether a guessed token ever existed.
        raise HTTPException(status_code=404, detail="This onboarding link is invalid or has expired.")
    return record


@app.get("/api/siem-catalog")
def siem_catalog() -> dict:
    return get_catalog()


@app.get("/api/onboarding/{token}")
def get_onboarding_state(token: str) -> OnboardingStateResponse:
    record = _require_token(token)
    existing = load_tenant_configs(path=TENANT_CONFIG_PATH).get(record["tenant_id"])
    return OnboardingStateResponse(
        tenant_label=record.get("label") or record["tenant_id"],
        existing_config=public_config(existing) if existing else None,
    )


def build_tenant_config(tenant_id: str, submission: OnboardingSubmission) -> dict:
    """Map one onboarding submission onto config_store's expected shape.

    Handles only the Wazuh bulk_http username+password -> "user:pass" join
    translator.py requires, and the syslog-transport placeholder token that
    matches the "unused-syslog-has-no-auth" convention already used in
    tenant_configs.json for no-auth transports. Everything else (required
    fields, URL scheme) still flows through config_store.normalize_config --
    this function does not duplicate that validation.
    """
    if submission.siem_type == "wazuh" and submission.transport == "bulk_http":
        if not submission.username or not submission.password:
            raise HTTPException(400, "Wazuh indexer auth requires a username and password")
        auth_token = f"{submission.username}:{submission.password}"
    elif submission.siem_type == "graylog" or (
        submission.siem_type == "wazuh" and submission.transport == "syslog"
    ):
        auth_token = "unused-syslog-has-no-auth"
    else:
        auth_token = submission.auth_token or ""

    return {
        "tenant_id": tenant_id,
        "siem_type": submission.siem_type,
        "webhook_url": submission.webhook_url,
        "auth_token": auth_token,
        "verify_ssl": submission.verify_ssl,
    }


@app.post("/api/onboarding/{token}")
def submit_onboarding(token: str, submission: OnboardingSubmission) -> SubmissionResult:
    record = _require_token(token)

    try:
        saved = save_tenant_config(
            build_tenant_config(record["tenant_id"], submission),
            path=TENANT_CONFIG_PATH,
        )
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    mark_token_used(token, path=TOKENS_FILE)
    return SubmissionResult(saved=public_config(saved))
