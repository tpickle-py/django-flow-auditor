"""Tests for Celery tasks executing eagerly in test environment."""

import pytest
from django.utils import timezone

from flow_auditor.models import Job, JobStatus
from flow_auditor.tasks import (
    archive_retention_task,
    cleanup_expired_leases_task,
    execute_job_task,
)


@pytest.mark.django_db
def test_execute_job_task_success():
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        request_json={"config": "access-list T extended permit ip any any"},
        normalized_hash="hash1",
        status=JobStatus.QUEUED,
    )
    execute_job_task(str(job.id))
    job.refresh_from_db()
    assert job.status == JobStatus.COMPLETED
    assert job.progress_percent == 100
    assert isinstance(job.result_json, list)
    assert len(job.result_json) == 1
    assert job.events.filter(event_type="job.completed").exists()


@pytest.mark.django_db
def test_execute_job_task_failure():
    job = Job.objects.create(
        module_slug="flowdiff",
        request_json={"config": "invalid-non-json-config"},
        normalized_hash="hash-err",
        status=JobStatus.QUEUED,
        max_attempts=1,
    )
    execute_job_task(str(job.id))
    job.refresh_from_db()
    assert job.status == JobStatus.DEAD_LETTER
    assert job.error_json is not None


@pytest.mark.django_db
def test_archive_retention_task():
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.COMPLETED,
        result_json=[{"foo": "bar"}],
        finished_at=timezone.now() - timezone.timedelta(days=40),
        normalized_hash="h1",
    )
    res = archive_retention_task(retention_days=30)
    assert res["rows_processed"] >= 1
    job.refresh_from_db()
    assert job.result_json is None
    assert job.archived_at is not None


@pytest.mark.django_db
def test_cleanup_expired_leases_task():
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.RUNNING,
        lease_owner="dead-worker",
        lease_expires_at=timezone.now() - timezone.timedelta(minutes=5),
        attempts=3,
        max_attempts=3,
        normalized_hash="h2",
    )
    cleaned = cleanup_expired_leases_task()
    assert cleaned >= 1
    job.refresh_from_db()
    assert job.status == JobStatus.TIMED_OUT


@pytest.mark.django_db
def test_cleanup_expired_leases_retryable():
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        request_json={"config": "access-list T extended permit ip any any"},
        status=JobStatus.RUNNING,
        lease_owner="dead-worker",
        lease_expires_at=timezone.now() - timezone.timedelta(minutes=5),
        attempts=1,
        max_attempts=3,
        normalized_hash="h3",
    )
    cleaned = cleanup_expired_leases_task()
    assert cleaned >= 1
    job.refresh_from_db()
    # In eager mode, execute_job_task.delay() runs immediately, transitioning to COMPLETED
    assert job.status == JobStatus.COMPLETED


@pytest.mark.django_db
def test_execute_job_task_cancellation():
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.CANCEL_REQUESTED,
        normalized_hash="h4",
    )
    execute_job_task(str(job.id))
    job.refresh_from_db()
    assert job.status == JobStatus.CANCELLED


@pytest.mark.django_db
def test_deliver_webhook_task(monkeypatch):
    from flow_auditor.tasks import deliver_webhook_task

    called = []

    def mock_deliver(url, payload, secret=None):
        called.append((url, payload))
        return True

    monkeypatch.setattr("flow_auditor.tasks.deliver_webhook", mock_deliver)

    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.COMPLETED,
        webhook_url="https://example.com/hook",
        normalized_hash="h5",
    )
    deliver_webhook_task(str(job.id))
    job.refresh_from_db()
    assert len(called) == 1
    assert job.webhook_attempts == 1
    assert job.first_webhook_retrieved_at is not None
