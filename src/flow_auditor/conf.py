"""Configuration settings with sensible defaults for flow_auditor."""

from __future__ import annotations

from typing import Any

from django.conf import settings

DEFAULTS: dict[str, Any] = {
    "FLOW_AUDITOR_ASYNC_THRESHOLD_BYTES": 500_000,
    "FLOW_AUDITOR_DEFAULT_TIMEOUT_MS": 60_000,
    "FLOW_AUDITOR_MAX_ATTEMPTS": 3,
    "FLOW_AUDITOR_WEBHOOK_MAX_RETRIES": 3,
    "FLOW_AUDITOR_LEASE_TTL_SECONDS": 60,
    "FLOW_AUDITOR_RETENTION_DAYS": 30,
    "FLOW_AUDITOR_CELERY_QUEUE": "default",
}


def get_setting(name: str) -> Any:
    """Retrieve app setting from Django settings or fallback to default."""
    return getattr(settings, name, DEFAULTS.get(name))
