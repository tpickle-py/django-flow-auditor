"""Archival models for retention policy management."""

from __future__ import annotations

from django.db import models


class JobResultArchive(models.Model):
    """Cold storage for completed/failed job results after retention expiry."""

    job_id = models.UUIDField(unique=True, db_index=True)
    tenant_id = models.CharField(max_length=255, db_index=True)
    module_slug = models.CharField(max_length=100)
    status = models.CharField(max_length=32)
    result_json = models.JSONField(null=True, blank=True)
    error_json = models.JSONField(null=True, blank=True)
    source_finished_at = models.DateTimeField(null=True, blank=True)
    first_webhook_retrieved_at = models.DateTimeField(null=True, blank=True)
    archived_at = models.DateTimeField(auto_now_add=True, db_index=True)
    archive_reason = models.CharField(max_length=255)
    archive_metadata = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ["-archived_at"]
        indexes = [
            models.Index(fields=["tenant_id", "module_slug"], name="idx_archive_tenant_mod"),
        ]

    def __str__(self) -> str:
        return f"JobResultArchive({self.job_id}, reason={self.archive_reason})"


class ArchiveOperation(models.Model):
    """Record of an archive or retention sweep operation."""

    operation_type = models.CharField(max_length=100)
    status = models.CharField(max_length=32)
    rows_processed = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    details = models.JSONField(null=True, blank=True)
    error_text = models.TextField(null=True, blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"ArchiveOperation({self.operation_type}, status={self.status})"
