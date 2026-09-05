"""DRF Parse API view supporting sync parse and automatic async thresholding."""

from __future__ import annotations

import hashlib
import time
import uuid

from django.utils import timezone
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from flow_auditor.conf import get_setting
from flow_auditor.models import ActorType, Job, JobEvent, JobStatus
from flow_auditor.serializers.parse import ParseRequestSerializer
from flow_auditor.services.registry import execute_module, get_default_registry
from flow_auditor.tasks import execute_job_task


class ParseAPIView(APIView):
    """API view to parse or audit firewall rules with a specified adapter module."""

    def post(self, request: Request, module: str) -> Response:
        registry = get_default_registry()
        adapter = registry.get(module)
        if not adapter:
            return Response(
                {
                    "success": False,
                    "error": {
                        "code": "MODULE_NOT_FOUND",
                        "message": f"Module '{module}' is not registered.",
                    },
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = ParseRequestSerializer(data=request.data)
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
        config_str = data["config"]
        content_size_bytes = len(config_str.encode("utf-8"))
        threshold_bytes = get_setting("FLOW_AUDITOR_ASYNC_THRESHOLD_BYTES")

        force_async = request.query_params.get("async", "").lower() in ("true", "1")

        # Async branch: payload exceeds threshold or client requested async
        if force_async or (threshold_bytes and content_size_bytes > threshold_bytes):
            req_hash = hashlib.sha256(config_str.encode("utf-8")).hexdigest()
            job_id = uuid.uuid4()
            tenant_id = getattr(request, "tenant_id", "default")
            requested_by = (
                str(request.user) if request.user and request.user.is_authenticated else "anonymous"
            )

            job = Job.objects.create(
                id=job_id,
                tenant_id=tenant_id,
                requested_by=requested_by,
                module_slug=adapter.slug,
                action=request.query_params.get("action"),
                request_json={
                    "config": config_str,
                    "options": data.get("options", {}),
                    "filter": data.get("filter", {}),
                    "query": dict(request.query_params),
                },
                normalized_hash=req_hash,
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

            status_url = request.build_absolute_uri(f"/api/flow-auditor/jobs/{job.id}/")
            return Response(
                {
                    "success": True,
                    "module": adapter.slug,
                    "data": {
                        "jobId": str(job.id),
                        "status": "queued",
                        "statusUrl": status_url,
                        "createdAt": job.created_at.isoformat(),
                        "mode": "async",
                        "reason": "content_size_threshold_exceeded"
                        if not force_async
                        else "client_requested",
                        "thresholdBytes": threshold_bytes,
                        "contentSizeBytes": content_size_bytes,
                    },
                    "meta": {
                        "adapter": adapter.adapter_name,
                        "timestamp": timezone.now().isoformat(),
                    },
                },
                status=status.HTTP_202_ACCEPTED,
            )

        # Synchronous execution branch
        start_time = time.time()
        try:
            result = execute_module(
                slug=adapter.slug,
                config=config_str,
                options=data.get("options"),
                filter_params=data.get("filter"),
                query=dict(request.query_params),
            )
            duration_ms = round((time.time() - start_time) * 1000, 2)
            return Response(
                {
                    "success": True,
                    "module": adapter.slug,
                    "data": result.get("data"),
                    "meta": {
                        "durationMs": duration_ms,
                        "timestamp": timezone.now().isoformat(),
                        "adapter": adapter.adapter_name,
                        "exportUsed": result.get("exportUsed"),
                    },
                },
                status=status.HTTP_200_OK,
            )
        except Exception as exc:
            return Response(
                {
                    "success": False,
                    "module": adapter.slug,
                    "error": {
                        "code": "PARSE_ERROR",
                        "message": str(exc),
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
