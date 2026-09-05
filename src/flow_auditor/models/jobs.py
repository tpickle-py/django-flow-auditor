"""Job and JobEvent ORM models for flow_auditor."""

from __future__ import annotations

import uuid

from django.db import models


class JobStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    CANCEL_REQUESTED = "cancel_requested", "Cancel Requested"
    CANCELLED = "cancelled", "Cancelled"
    TIMED_OUT = "timed_out", "Timed Out"
    DEAD_LETTER = "dead_letter", "Dead Letter"


class ActorType(models.TextChoices):
    SYSTEM = "system", "System"
    USER = "user", "User"
    ADMIN = "admin", "Admin"
    WORKER = "worker", "Worker"


class Job(models.Model):
    """Represents a firewall configuration audit or parsing job."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant_id = models.CharField(max_length=255, default="default", db_index=True)
    requested_by = models.CharField(max_length=255, default="anonymous")
    module_slug = models.CharField(max_length=100, db_index=True)
    action = models.CharField(max_length=100, null=True, blank=True)
    request_json = models.JSONField(default=dict)
    normalized_hash = models.CharField(max_length=64, db_index=True)
    idempotency_key = models.CharField(max_length=255, null=True, blank=True, db_index=True)

    status = models.CharField(
        max_length=32,
        choices=JobStatus.choices,
        default=JobStatus.QUEUED,
        db_index=True,
    )
    priority = models.PositiveSmallIntegerField(default=5)
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=3)

    progress_percent = models.PositiveSmallIntegerField(default=0)
    progress_stage = models.CharField(max_length=100, null=True, blank=True)
    progress_message = models.TextField(null=True, blank=True)

    result_json = models.JSONField(null=True, blank=True)
    error_json = models.JSONField(null=True, blank=True)

    webhook_url = models.URLField(max_length=1024, null=True, blank=True)
    webhook_secret_ref = models.CharField(max_length=255, null=True, blank=True)
    webhook_attempts = models.PositiveIntegerField(default=0)

    lease_owner = models.CharField(max_length=255, null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    heartbeat_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    queued_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)

    first_webhook_retrieved_at = models.DateTimeField(null=True, blank=True)
    result_cleared_at = models.DateTimeField(null=True, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "-created_at"], name="idx_jobs_status_created"),
            models.Index(fields=["module_slug", "status"], name="idx_jobs_mod_status"),
            models.Index(fields=["tenant_id", "-created_at"], name="idx_jobs_tenant_created"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(priority__gte=0, priority__lte=9),
                name="jobs_priority_range",
            ),
            models.CheckConstraint(
                condition=models.Q(progress_percent__gte=0, progress_percent__lte=100),
                name="jobs_progress_percent_range",
            ),
            models.UniqueConstraint(
                fields=["tenant_id", "idempotency_key"],
                name="uniq_jobs_tenant_idempotency",
                condition=models.Q(idempotency_key__isnull=False),
            ),
        ]

    def __str__(self) -> str:
        return f"Job {self.id} ({self.module_slug}, status={self.status})"


class JobEvent(models.Model):
    """Lifecycle event emitted during job processing."""

    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name="events")
    event_type = models.CharField(max_length=100)
    actor_type = models.CharField(max_length=32, choices=ActorType.choices)
    actor_id = models.CharField(max_length=255, null=True, blank=True)
    payload = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["job", "created_at"], name="idx_job_events_job_time"),
        ]

    def __str__(self) -> str:
        return f"JobEvent({self.job_id}, {self.event_type}, {self.created_at})"
