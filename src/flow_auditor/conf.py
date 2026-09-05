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
    "FLOW_AUDITOR_PERMISSION_CLASSES": None,
    "FLOW_AUDITOR_ADMIN_PERMISSION_CLASSES": None,
}


def get_setting(name: str) -> Any:
    """Retrieve app setting from Django settings or fallback to default."""
    return getattr(settings, name, DEFAULTS.get(name))


def get_permission_classes(admin: bool = False) -> list[type]:
    """Retrieve resolved DRF permission classes using Django standard auth/RBAC."""
    setting_key = (
        "FLOW_AUDITOR_ADMIN_PERMISSION_CLASSES" if admin else "FLOW_AUDITOR_PERMISSION_CLASSES"
    )
    classes = get_setting(setting_key)
    if classes is not None:
        from django.utils.module_loading import import_string

        resolved = []
        for cls in classes:
            if isinstance(cls, str):
                resolved.append(import_string(cls))
            else:
                resolved.append(cls)
        return resolved

    if admin:
        from rest_framework.permissions import IsAdminUser

        return [IsAdminUser]

    # By default, defer to REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'] in settings
    return []
