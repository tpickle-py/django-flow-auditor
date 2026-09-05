"""DRF serializers for Job submission, tracking, and events."""

from __future__ import annotations

from typing import Any

from rest_framework import serializers

from flow_auditor.models import Job, JobEvent


class JobSubmitSerializer(serializers.Serializer):
    """Serializer for submitting an asynchronous audit job."""

    module = serializers.CharField(max_length=100, required=True)
    action = serializers.CharField(max_length=100, required=False, allow_null=True)
    config = serializers.CharField(required=True)
    options = serializers.DictField(required=False, default=dict)
    filter = serializers.DictField(required=False, default=dict)
    priority = serializers.IntegerField(min_value=0, max_value=9, default=5)
    idempotencyKey = serializers.CharField(max_length=255, required=False, allow_null=True)
    webhook = serializers.DictField(required=False, allow_null=True)

    def validate_webhook(self, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value:
            url = value.get("url")
            if not url or not isinstance(url, str):
                raise serializers.ValidationError(
                    "Webhook url is required when webhook object is provided."
                )
        return value


class JobEventSerializer(serializers.ModelSerializer):
    """Serializer for job lifecycle events."""

    eventId = serializers.IntegerField(source="id", read_only=True)
    jobId = serializers.UUIDField(source="job.id", read_only=True)
    eventType = serializers.CharField(source="event_type", read_only=True)
    actorType = serializers.CharField(source="actor_type", read_only=True)
    actorId = serializers.CharField(source="actor_id", read_only=True)
    createdAt = serializers.DateTimeField(source="created_at", read_only=True)

    class Meta:
        model = JobEvent
        fields = [
            "eventId",
            "jobId",
            "eventType",
            "actorType",
            "actorId",
            "payload",
            "createdAt",
        ]


class JobDetailSerializer(serializers.ModelSerializer):
    """Serializer for detailed Job status and result output."""

    jobId = serializers.UUIDField(source="id", read_only=True)
    tenantId = serializers.CharField(source="tenant_id", read_only=True)
    requestedBy = serializers.CharField(source="requested_by", read_only=True)
    module = serializers.CharField(source="module_slug", read_only=True)
    maxAttempts = serializers.IntegerField(source="max_attempts", read_only=True)
    progress = serializers.SerializerMethodField()
    result = serializers.JSONField(source="result_json", read_only=True)
    error = serializers.JSONField(source="error_json", read_only=True)
    createdAt = serializers.DateTimeField(source="created_at", read_only=True)
    queuedAt = serializers.DateTimeField(source="queued_at", read_only=True)
    startedAt = serializers.DateTimeField(source="started_at", read_only=True)
    finishedAt = serializers.DateTimeField(source="finished_at", read_only=True)
    cancelledAt = serializers.DateTimeField(source="cancelled_at", read_only=True)
    statusUrl = serializers.SerializerMethodField()

    class Meta:
        model = Job
        fields = [
            "jobId",
            "tenantId",
            "requestedBy",
            "module",
            "action",
            "status",
            "attempts",
            "maxAttempts",
            "priority",
            "progress",
            "result",
            "error",
            "createdAt",
            "queuedAt",
            "startedAt",
            "finishedAt",
            "cancelledAt",
            "statusUrl",
        ]

    def get_progress(self, obj: Job) -> dict[str, Any]:
        return {
            "percent": obj.progress_percent,
            "stage": obj.progress_stage,
            "message": obj.progress_message,
        }

    def get_statusUrl(self, obj: Job) -> str:
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(f"/api/flow-auditor/jobs/{obj.id}/")
        return f"/api/flow-auditor/jobs/{obj.id}/"
