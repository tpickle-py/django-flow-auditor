"""Admin operations views for job statistics, retries, and retention execution."""

from __future__ import annotations

from typing import Any

from django.db.models import Count
from django.utils import timezone
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from flow_auditor.conf import get_permission_classes
from flow_auditor.models import ActorType, AdminAuditLog, Job, JobEvent, JobStatus
from flow_auditor.serializers.jobs import JobDetailSerializer
from flow_auditor.tasks import archive_retention_task, execute_job_task


class AdminJobStatsView(APIView):
    """Aggregate statistics on job execution, queue lengths, and error rates."""

    def get_permissions(self) -> list[Any]:
        return [permission() for permission in get_permission_classes(admin=True)]

    def get(self, request: Request) -> Response:
        status_counts = dict(
            Job.objects.values("status")
            .annotate(count=Count("status"))
            .values_list("status", "count")
        )
        module_counts = dict(
            Job.objects.values("module_slug")
            .annotate(count=Count("module_slug"))
            .values_list("module_slug", "count")
        )
        total_jobs = Job.objects.count()

        return Response(
            {
                "success": True,
                "data": {
                    "totalJobs": total_jobs,
                    "byStatus": status_counts,
                    "byModule": module_counts,
                    "timestamp": timezone.now().isoformat(),
                },
            }
        )


class AdminJobRetryView(APIView):
    """Retry a failed or dead-letter job."""

    def get_permissions(self) -> list[Any]:
        return [permission() for permission in get_permission_classes(admin=True)]

    def post(self, request: Request, pk: str) -> Response:
        try:
            job = Job.objects.get(id=pk)
        except Job.DoesNotExist:
            return Response(
                {"success": False, "error": {"code": "NOT_FOUND", "message": "Job not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        if job.status not in (JobStatus.FAILED, JobStatus.DEAD_LETTER, JobStatus.TIMED_OUT):
            return Response(
                {
                    "success": False,
                    "error": {
                        "code": "INVALID_STATE",
                        "message": f"Only failed/timed_out jobs can be retried. Current status is '{job.status}'.",
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        actor_id = str(request.user) if request.user and request.user.is_authenticated else "admin"

        job.status = JobStatus.QUEUED
        job.attempts = 0
        job.error_json = None
        job.lease_owner = None
        job.lease_expires_at = None
        job.finished_at = None
        job.queued_at = timezone.now()
        job.save()

        JobEvent.objects.create(
            job=job,
            event_type="job.retried",
            actor_type=ActorType.ADMIN,
            actor_id=actor_id,
        )

        AdminAuditLog.objects.create(
            actor_id=actor_id,
            actor_role="admin",
            action="job.retry",
            target_type="job",
            target_id=str(job.id),
        )

        execute_job_task.delay(str(job.id))

        detail = JobDetailSerializer(job, context={"request": request}).data
        return Response({"success": True, "job": detail})


class AdminRetentionTriggerView(APIView):
    """Trigger manual retention sweep to archive old job results."""

    def get_permissions(self) -> list[Any]:
        return [permission() for permission in get_permission_classes(admin=True)]

    def post(self, request: Request) -> Response:
        actor_id = str(request.user) if request.user and request.user.is_authenticated else "admin"
        days_param = request.data.get("days")
        days = int(days_param) if days_param else None

        result = archive_retention_task(retention_days=days)

        AdminAuditLog.objects.create(
            actor_id=actor_id,
            actor_role="admin",
            action="retention.sweep",
            target_type="archive_operation",
            target_id=str(result["operation_id"]),
            payload=result,
        )

        return Response({"success": True, "data": result})
