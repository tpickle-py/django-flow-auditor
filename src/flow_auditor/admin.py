"""Django admin registration for flow_auditor models."""

from django.contrib import admin

from flow_auditor.models import (
    AdminAuditLog,
    ArchiveOperation,
    Job,
    JobEvent,
    JobResultArchive,
)


class JobEventInline(admin.TabularInline):
    model = JobEvent
    extra = 0
    readonly_fields = ["event_type", "actor_type", "actor_id", "payload", "created_at"]
    can_delete = False


@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "module_slug",
        "tenant_id",
        "requested_by",
        "status",
        "priority",
        "attempts",
        "created_at",
        "finished_at",
    ]
    list_filter = ["status", "module_slug", "tenant_id", "created_at"]
    search_fields = ["id", "module_slug", "requested_by", "idempotency_key"]
    readonly_fields = [
        "id",
        "normalized_hash",
        "created_at",
        "queued_at",
        "started_at",
        "finished_at",
        "cancelled_at",
        "first_webhook_retrieved_at",
        "result_cleared_at",
        "archived_at",
    ]
    inlines = [JobEventInline]


@admin.register(JobEvent)
class JobEventAdmin(admin.ModelAdmin):
    list_display = ["id", "job", "event_type", "actor_type", "actor_id", "created_at"]
    list_filter = ["event_type", "actor_type", "created_at"]
    search_fields = ["job__id", "actor_id", "event_type"]


@admin.register(JobResultArchive)
class JobResultArchiveAdmin(admin.ModelAdmin):
    list_display = ["job_id", "tenant_id", "module_slug", "status", "archived_at", "archive_reason"]
    list_filter = ["status", "module_slug", "archived_at"]
    search_fields = ["job_id", "tenant_id", "archive_reason"]


@admin.register(ArchiveOperation)
class ArchiveOperationAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "operation_type",
        "status",
        "rows_processed",
        "started_at",
        "completed_at",
    ]
    list_filter = ["operation_type", "status", "started_at"]


@admin.register(AdminAuditLog)
class AdminAuditLogAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "actor_id",
        "actor_role",
        "action",
        "target_type",
        "target_id",
        "created_at",
    ]
    list_filter = ["action", "actor_role", "target_type", "created_at"]
    search_fields = ["actor_id", "target_id", "action"]
