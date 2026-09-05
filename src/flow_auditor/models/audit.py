"""Audit logging model for administrative operations."""

from __future__ import annotations

from django.db import models


class AdminAuditLog(models.Model):
    """Log of administrative actions taken on jobs, users, or configuration."""

    actor_id = models.CharField(max_length=255, db_index=True)
    actor_role = models.CharField(max_length=100)
    action = models.CharField(max_length=100)
    target_type = models.CharField(max_length=100)
    target_id = models.CharField(max_length=255)
    payload = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["target_type", "target_id", "-created_at"], name="idx_audit_target_time"
            ),
            models.Index(fields=["actor_id", "-created_at"], name="idx_audit_actor_time"),
        ]

    def __str__(self) -> str:
        return f"AdminAuditLog({self.actor_id}, {self.action}, {self.target_type}:{self.target_id})"
