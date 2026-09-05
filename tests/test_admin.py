"""Tests for Django admin registration and configurations."""

import pytest
from django.contrib.admin.sites import AdminSite

from flow_auditor.admin import (
    AdminAuditLogAdmin,
    ArchiveOperationAdmin,
    JobAdmin,
    JobEventAdmin,
    JobEventInline,
    JobResultArchiveAdmin,
)
from flow_auditor.models import (
    AdminAuditLog,
    ArchiveOperation,
    Job,
    JobEvent,
    JobResultArchive,
)


class DummySite(AdminSite):
    pass


@pytest.fixture
def admin_site():
    return DummySite()


@pytest.mark.django_db
def test_job_admin(admin_site):
    ma = JobAdmin(Job, admin_site)
    assert "status" in ma.list_filter
    assert "id" in ma.readonly_fields
    assert "module_slug" in ma.list_display
    assert JobEventInline in ma.inlines


@pytest.mark.django_db
def test_job_event_admin(admin_site):
    ma = JobEventAdmin(JobEvent, admin_site)
    assert "event_type" in ma.list_filter
    assert "actor_id" in ma.search_fields


@pytest.mark.django_db
def test_job_result_archive_admin(admin_site):
    ma = JobResultArchiveAdmin(JobResultArchive, admin_site)
    assert "status" in ma.list_filter
    assert "job_id" in ma.list_display


@pytest.mark.django_db
def test_archive_operation_admin(admin_site):
    ma = ArchiveOperationAdmin(ArchiveOperation, admin_site)
    assert "status" in ma.list_filter
    assert "rows_processed" in ma.list_display


@pytest.mark.django_db
def test_admin_audit_log_admin(admin_site):
    ma = AdminAuditLogAdmin(AdminAuditLog, admin_site)
    assert "action" in ma.list_filter
    assert "actor_id" in ma.list_display
