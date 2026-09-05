"""DRF views for Job submission, querying, cancellation, and event logging."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from django.utils import timezone
from rest_framework import status
from rest_framework.generics import ListCreateAPIView, RetrieveAPIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from flow_auditor.conf import get_permission_classes
from flow_auditor.models import ActorType, Job, JobEvent, JobStatus
from flow_auditor.serializers.jobs import (
    JobDetailSerializer,
    JobEventSerializer,
    JobSubmitSerializer,
)
from flow_auditor.services.registry import get_default_registry
from flow_auditor.tasks import execute_job_task


class JobListView(ListCreateAPIView):
    """List jobs with filtering, or submit a new background job."""

    serializer_class = JobDetailSerializer

    def get_permissions(self) -> list[Any]:
        return [permission() for permission in get_permission_classes(admin=False)]

    def get_queryset(self) -> Any:
        qs = Job.objects.all()
        status_param = self.request.query_params.get("status")
        module_param = self.request.query_params.get("module")
        tenant_param = self.request.query_params.get("tenantId") or self.request.query_params.get(
            "tenant"
        )

        if status_param:
            qs = qs.filter(status=status_param)
        if module_param:
            qs = qs.filter(module_slug=module_param)
        if tenant_param:
            qs = qs.filter(tenant_id=tenant_param)

        return qs.order_by("-created_at")

    def create(self, request: Request, *_args: Any, **_kwargs: Any) -> Response:
        serializer = JobSubmitSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {
                    "success": False,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Invalid request body.",
                        "details": serializer.errors,
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = serializer.validated_data
        module_slug = data["module"]
        registry = get_default_registry()
        adapter = registry.get(module_slug)
        if not adapter:
            return Response(
                {
                    "success": False,
                    "error": {
                        "code": "MODULE_NOT_FOUND",
                        "message": f"Module '{module_slug}' is not registered.",
                    },
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        tenant_id = getattr(request, "tenant_id", "default")
        requested_by = (
            str(request.user) if request.user and request.user.is_authenticated else "anonymous"
        )
        idempotency_key = request.headers.get("Idempotency-Key") or data.get("idempotencyKey")

        # Check idempotency
        if idempotency_key:
            existing = Job.objects.filter(
                tenant_id=tenant_id, idempotency_key=idempotency_key
            ).first()
            if existing:
                detail = JobDetailSerializer(existing, context={"request": request}).data
                return Response(
                    {"success": True, "job": detail, "idempotentReplay": True},
                    status=status.HTTP_200_OK,
                )

        config_str = data["config"]
        req_hash = hashlib.sha256(config_str.encode("utf-8")).hexdigest()
        job_id = uuid.uuid4()

        webhook_info = data.get("webhook")
        webhook_url = webhook_info.get("url") if webhook_info else None
        webhook_secret = webhook_info.get("secretRef") if webhook_info else None

        job = Job.objects.create(
            id=job_id,
            tenant_id=tenant_id,
            requested_by=requested_by,
            module_slug=adapter.slug,
            action=data.get("action"),
            priority=data.get("priority", 5),
            idempotency_key=idempotency_key,
            request_json={
                "config": config_str,
                "options": data.get("options", {}),
                "filter": data.get("filter", {}),
                "query": dict(request.query_params),
            },
            normalized_hash=req_hash,
            webhook_url=webhook_url,
            webhook_secret_ref=webhook_secret,
            status=JobStatus.QUEUED,
            queued_at=timezone.now(),
        )

        JobEvent.objects.create(
            job=job,
            event_type="job.created",
            actor_type=ActorType.USER
            if request.user and request.user.is_authenticated
            else ActorType.SYSTEM,
            actor_id=requested_by,
        )

        execute_job_task.delay(str(job.id))

        detail = JobDetailSerializer(job, context={"request": request}).data
        return Response(
            {"success": True, "job": detail, "idempotentReplay": False},
            status=status.HTTP_201_CREATED,
        )


class JobDetailView(RetrieveAPIView):
    """Retrieve detailed status, progress, and result of a specific job."""

    queryset = Job.objects.all()
    serializer_class = JobDetailSerializer

    def get_permissions(self) -> list[Any]:
        return [permission() for permission in get_permission_classes(admin=False)]


class JobCancelView(APIView):
    """Request cancellation of an active or queued job."""

    def get_permissions(self) -> list[Any]:
        return [permission() for permission in get_permission_classes(admin=False)]

    def post(self, request: Request, pk: str) -> Response:
        try:
            job = Job.objects.get(id=pk)
        except Job.DoesNotExist:
            return Response(
                {"success": False, "error": {"code": "NOT_FOUND", "message": "Job not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        actor_id = (
            str(request.user) if request.user and request.user.is_authenticated else "anonymous"
        )

        if job.status in (
            JobStatus.COMPLETED,
            JobStatus.FAILED,
            JobStatus.DEAD_LETTER,
            JobStatus.CANCELLED,
        ):
            return Response(
                {
                    "success": False,
                    "error": {
                        "code": "CANNOT_CANCEL",
                        "message": f"Job is in terminal state '{job.status}' and cannot be cancelled.",
                    },
                },
                status=status.HTTP_409_CONFLICT,
            )

        if job.status == JobStatus.QUEUED:
            job.status = JobStatus.CANCELLED
            job.cancelled_at = timezone.now()
            job.save(update_fields=["status", "cancelled_at"])
            JobEvent.objects.create(
                job=job,
                event_type="job.cancelled",
                actor_type=ActorType.USER
                if request.user and request.user.is_authenticated
                else ActorType.SYSTEM,
                actor_id=actor_id,
            )
        else:
            job.status = JobStatus.CANCEL_REQUESTED
            job.save(update_fields=["status"])
            JobEvent.objects.create(
                job=job,
                event_type="job.cancel_requested",
                actor_type=ActorType.USER
                if request.user and request.user.is_authenticated
                else ActorType.SYSTEM,
                actor_id=actor_id,
            )

        detail = JobDetailSerializer(job, context={"request": request}).data
        return Response({"success": True, "job": detail}, status=status.HTTP_200_OK)


class JobEventsView(APIView):
    """Retrieve audit timeline events for a given job."""

    def get_permissions(self) -> list[Any]:
        return [permission() for permission in get_permission_classes(admin=False)]

    def get(self, request: Request, pk: str) -> Response:
        try:
            job = Job.objects.get(id=pk)
        except Job.DoesNotExist:
            return Response(
                {"success": False, "error": {"code": "NOT_FOUND", "message": "Job not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        events = job.events.all()
        serializer = JobEventSerializer(events, many=True)
        return Response({"success": True, "jobId": str(job.id), "events": serializer.data})
