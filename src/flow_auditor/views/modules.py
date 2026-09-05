"""DRF view for cataloging registered adapter modules."""

from __future__ import annotations

from typing import Any

from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from flow_auditor.conf import get_permission_classes
from flow_auditor.services.registry import get_default_registry


class ModulesListView(APIView):
    """List available modules and their supported actions."""

    def get_permissions(self) -> list[Any]:
        return [permission() for permission in get_permission_classes(admin=False)]

    def get(self, request: Request) -> Response:
        registry = get_default_registry()
        modules = registry.list_modules()
        return Response({"success": True, "data": {"modules": modules}})
