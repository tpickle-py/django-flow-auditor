"""Tests for flow_auditor ORM models."""

import pytest
from django.db.utils import IntegrityError

from flow_auditor.models import (
    ActorType,
    AdminAuditLog,
    ArchiveOperation,
    Job,
    JobEvent,
    JobResultArchive,
    JobStatus,
)


@pytest.mark.django_db
def test_job_creation_and_defaults():
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        request_json={"config": "test"},
        normalized_hash="hash123",
    )
    assert job.status == JobStatus.QUEUED
    assert job.priority == 5
    assert job.attempts == 0
    assert job.progress_percent == 0
    assert str(job).startswith("Job ")


@pytest.mark.django_db
def test_job_idempotency_constraint():
    Job.objects.create(
        tenant_id="tenant-1",
        idempotency_key="idemp-key-1",
        module_slug="cisco-asa-parser",
        normalized_hash="h1",
    )
    with pytest.raises(IntegrityError):
        Job.objects.create(
            tenant_id="tenant-1",
            idempotency_key="idemp-key-1",
            module_slug="cisco-asa-parser",
            normalized_hash="h2",
        )


@pytest.mark.django_db
def test_job_event_relationship():
    job = Job.objects.create(
        module_slug="juniper-srx-parser",
        normalized_hash="hash456",
    )
    event = JobEvent.objects.create(
        job=job,
        event_type="job.created",
        actor_type=ActorType.USER,
        actor_id="admin",
    )
    assert job.events.count() == 1
    assert job.events.first() == event


@pytest.mark.django_db
def test_job_result_archive():
    archive = JobResultArchive.objects.create(
        job_id="00000000-0000-0000-0000-000000000001",
        tenant_id="default",
        module_slug="flowdiff",
        status="completed",
        archive_reason="retention_30_days",
    )
    assert str(archive).startswith("JobResultArchive")


@pytest.mark.django_db
def test_archive_operation_and_audit_log():
    op = ArchiveOperation.objects.create(
        operation_type="sweep",
        status="completed",
        rows_processed=10,
    )
    assert str(op).startswith("ArchiveOperation")

    audit = AdminAuditLog.objects.create(
        actor_id="admin_user",
        actor_role="admin",
        action="retention.sweep",
        target_type="archive_operation",
        target_id=str(op.id),
    )
    assert str(audit).startswith("AdminAuditLog")
