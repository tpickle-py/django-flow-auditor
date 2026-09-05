"""Celery background tasks for flow_auditor.

These tasks assume the host project configures Celery and automatically
discovers tasks via celery.autodiscover_tasks().
"""

from __future__ import annotations

import datetime
import logging
from typing import Any

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from flow_auditor.conf import get_setting
from flow_auditor.models import (
    ActorType,
    ArchiveOperation,
    Job,
    JobEvent,
    JobResultArchive,
    JobStatus,
)
from flow_auditor.services.registry import execute_module
from flow_auditor.services.webhooks import deliver_webhook

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=5)
def execute_job_task(self: Any, job_id: str) -> None:
    """Execute a background firewall audit job."""
    lease_ttl = get_setting("FLOW_AUDITOR_LEASE_TTL_SECONDS")
    now = timezone.now()
    lease_expires = now + datetime.timedelta(seconds=lease_ttl)
    worker_id = getattr(self.request, "hostname", "celery-worker")

    with transaction.atomic():
        try:
            job = Job.objects.select_for_update().get(id=job_id)
        except Job.DoesNotExist:
            logger.error("Job %s not found for execution", job_id)
            return

        if job.status in (JobStatus.CANCELLED, JobStatus.COMPLETED):
            return

        if job.status == JobStatus.CANCEL_REQUESTED:
            job.status = JobStatus.CANCELLED
            job.cancelled_at = now
            job.save(update_fields=["status", "cancelled_at"])
            JobEvent.objects.create(
                job=job,
                event_type="job.cancelled",
                actor_type=ActorType.WORKER,
                actor_id=worker_id,
            )
            return

        job.status = JobStatus.RUNNING
        job.started_at = job.started_at or now
        job.lease_owner = worker_id
        job.lease_expires_at = lease_expires
        job.heartbeat_at = now
        job.attempts += 1
        job.progress_percent = 10
        job.progress_stage = "initializing"
        job.save(
            update_fields=[
                "status",
                "started_at",
                "lease_owner",
                "lease_expires_at",
                "heartbeat_at",
                "attempts",
                "progress_percent",
                "progress_stage",
            ]
        )

        JobEvent.objects.create(
            job=job,
            event_type="job.started",
            actor_type=ActorType.WORKER,
            actor_id=worker_id,
        )

    # Check cancellation checkpoint
    job.refresh_from_db()
    if job.status == JobStatus.CANCEL_REQUESTED:
        job.status = JobStatus.CANCELLED
        job.cancelled_at = timezone.now()
        job.save(update_fields=["status", "cancelled_at"])
        return

    try:
        req = job.request_json
        config = req.get("config", "")
        options = req.get("options", {})
        filter_params = req.get("filter", {})
        query = req.get("query", {})

        job.progress_percent = 50
        job.progress_stage = "executing"
        job.save(update_fields=["progress_percent", "progress_stage"])

        result = execute_module(
            slug=job.module_slug,
            config=config,
            options=options,
            filter_params=filter_params,
            query=query,
        )

        # Check cancellation before saving result
        job.refresh_from_db()
        if job.status == JobStatus.CANCEL_REQUESTED:
            job.status = JobStatus.CANCELLED
            job.cancelled_at = timezone.now()
            job.save(update_fields=["status", "cancelled_at"])
            return

        finish_time = timezone.now()
        job.status = JobStatus.COMPLETED
        job.result_json = result.get("data")
        job.progress_percent = 100
        job.progress_stage = "completed"
        job.finished_at = finish_time
        job.save(
            update_fields=[
                "status",
                "result_json",
                "progress_percent",
                "progress_stage",
                "finished_at",
            ]
        )

        JobEvent.objects.create(
            job=job,
            event_type="job.completed",
            actor_type=ActorType.WORKER,
            actor_id=worker_id,
            payload={"exportUsed": result.get("exportUsed")},
        )

        if job.webhook_url:
            deliver_webhook_task.delay(str(job.id))

    except Exception as exc:
        logger.exception("Error executing job %s: %s", job_id, exc)
        finish_time = timezone.now()
        job.refresh_from_db()
        is_dead_letter = job.attempts >= job.max_attempts
        job.status = JobStatus.DEAD_LETTER if is_dead_letter else JobStatus.FAILED
        job.error_json = {"error": str(exc), "type": exc.__class__.__name__}
        job.finished_at = finish_time
        job.save(update_fields=["status", "error_json", "finished_at"])

        JobEvent.objects.create(
            job=job,
            event_type="job.failed",
            actor_type=ActorType.WORKER,
            actor_id=worker_id,
            payload={"error": str(exc)},
        )


@shared_task(bind=True, max_retries=3, default_retry_delay=10)
def deliver_webhook_task(self: Any, job_id: str) -> None:
    """Deliver webhook notification for completed or failed job."""
    try:
        job = Job.objects.get(id=job_id)
    except Job.DoesNotExist:
        return

    if not job.webhook_url:
        return

    payload = {
        "jobId": str(job.id),
        "status": job.status,
        "module": job.module_slug,
        "action": job.action,
        "result": job.result_json,
        "error": job.error_json,
        "createdAt": job.created_at.isoformat() if job.created_at else None,
        "finishedAt": job.finished_at.isoformat() if job.finished_at else None,
    }

    job.webhook_attempts += 1
    job.save(update_fields=["webhook_attempts"])

    delivered = deliver_webhook(
        url=job.webhook_url,
        payload=payload,
        secret=job.webhook_secret_ref,
    )

    if delivered:
        if not job.first_webhook_retrieved_at:
            job.first_webhook_retrieved_at = timezone.now()
            job.save(update_fields=["first_webhook_retrieved_at"])
    else:
        if job.webhook_attempts < get_setting("FLOW_AUDITOR_WEBHOOK_MAX_RETRIES"):
            raise self.retry(exc=Exception("Webhook delivery failed"))


@shared_task
def archive_retention_task(retention_days: int | None = None) -> dict[str, Any]:
    """Archive expired job results into cold storage and clear result_json."""
    days = (
        retention_days if retention_days is not None else get_setting("FLOW_AUDITOR_RETENTION_DAYS")
    )
    cutoff = timezone.now() - datetime.timedelta(days=days)

    terminal_statuses = [
        JobStatus.COMPLETED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
        JobStatus.TIMED_OUT,
        JobStatus.DEAD_LETTER,
    ]

    candidates = Job.objects.filter(
        status__in=terminal_statuses,
        finished_at__lt=cutoff,
        result_cleared_at__isnull=True,
    )

    started_at = timezone.now()
    archived_count = 0

    for job in candidates.iterator(chunk_size=100):
        JobResultArchive.objects.update_or_create(
            job_id=job.id,
            defaults={
                "tenant_id": job.tenant_id,
                "module_slug": job.module_slug,
                "status": job.status,
                "result_json": job.result_json,
                "error_json": job.error_json,
                "source_finished_at": job.finished_at,
                "first_webhook_retrieved_at": job.first_webhook_retrieved_at,
                "archive_reason": f"retention_policy_{days}_days",
            },
        )
        job.result_json = None
        job.result_cleared_at = timezone.now()
        job.archived_at = timezone.now()
        job.save(update_fields=["result_json", "result_cleared_at", "archived_at"])
        archived_count += 1

    op = ArchiveOperation.objects.create(
        operation_type="retention_sweep",
        status="completed",
        rows_processed=archived_count,
        started_at=started_at,
        completed_at=timezone.now(),
        details={"retention_days": days, "cutoff": cutoff.isoformat()},
    )

    return {"operation_id": op.id, "rows_processed": archived_count}


@shared_task
def cleanup_expired_leases_task() -> int:
    """Detect stalled running jobs whose leases expired and reset or mark timed out."""
    now = timezone.now()
    stalled_jobs = Job.objects.filter(
        status=JobStatus.RUNNING,
        lease_expires_at__lt=now,
    )

    cleaned = 0
    for job in stalled_jobs:
        if job.attempts >= job.max_attempts:
            job.status = JobStatus.TIMED_OUT
            job.finished_at = now
            job.save(update_fields=["status", "finished_at"])
            JobEvent.objects.create(
                job=job,
                event_type="job.timed_out",
                actor_type=ActorType.SYSTEM,
                actor_id="cleanup-leases",
            )
        else:
            job.status = JobStatus.QUEUED
            job.lease_owner = None
            job.lease_expires_at = None
            job.save(update_fields=["status", "lease_owner", "lease_expires_at"])
            execute_job_task.delay(str(job.id))
        cleaned += 1

    return cleaned
