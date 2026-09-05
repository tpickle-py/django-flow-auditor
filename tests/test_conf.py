"""Tests for app configuration and permission classes resolution."""

from rest_framework.permissions import AllowAny, IsAdminUser

from flow_auditor.conf import get_permission_classes, get_setting


def test_get_setting_default():
    assert get_setting("FLOW_AUDITOR_LEASE_TTL_SECONDS") == 60
    assert get_setting("NON_EXISTENT_SETTING") is None


def test_get_permission_classes_defaults():
    public_perms = get_permission_classes(admin=False)
    assert public_perms == []

    admin_perms = get_permission_classes(admin=True)
    assert admin_perms == [IsAdminUser]


def test_get_permission_classes_custom(settings):
    settings.FLOW_AUDITOR_PERMISSION_CLASSES = [
        "rest_framework.permissions.AllowAny",
        AllowAny,
    ]
    perms = get_permission_classes(admin=False)
    assert len(perms) == 2
    assert perms[0] is AllowAny
    assert perms[1] is AllowAny
