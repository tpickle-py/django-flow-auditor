"""DRF serializers for module catalog and metadata."""

from __future__ import annotations

from rest_framework import serializers


class ModuleMetadataSerializer(serializers.Serializer):
    """Metadata serializer for an available adapter engine module."""

    slug = serializers.CharField()
    adapter = serializers.CharField()
    description = serializers.CharField()
    status = serializers.CharField()
    actions = serializers.DictField()
