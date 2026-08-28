"""Pydantic request/response models for the onboarding API.

Flat rather than nested per-SIEM shapes: Wazuh's bulk_http transport needs a
username+password pair instead of one opaque token, and that's the only real
divergence, so it's simpler to carry both possible shapes as optional fields
than to model a discriminated union the frontend would have to mirror.
"""

from __future__ import annotations

from pydantic import BaseModel


class OnboardingSubmission(BaseModel):
    siem_type: str
    transport: str | None = None  # required when the chosen siem has >1 transport (wazuh, graylog)
    webhook_url: str
    auth_token: str | None = None  # splunk / sentinel / elastic / datadog / sumologic / crowdstrike / generic
    username: str | None = None  # wazuh bulk_http only
    password: str | None = None  # wazuh bulk_http only
    verify_ssl: bool = True


class OnboardingStateResponse(BaseModel):
    tenant_label: str
    existing_config: dict | None  # config_store.public_config()-shaped, i.e. auth_token already redacted


class SubmissionResult(BaseModel):
    saved: dict  # config_store.public_config()-shaped
