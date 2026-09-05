"""DRF serializers for parse request and response payloads."""

from __future__ import annotations

from rest_framework import serializers


class ParseRequestSerializer(serializers.Serializer):
    """Payload serializer for parse requests."""

    config = serializers.CharField(required=True)
    options = serializers.DictField(required=False, default=dict)
    filter = serializers.DictField(required=False, default=dict)


class ParseResponseSerializer(serializers.Serializer):
    """Response serializer for synchronous parse."""

    success = serializers.BooleanField(default=True)
    module = serializers.CharField()
    data = serializers.JSONField()
    meta = serializers.DictField(required=False)


class AsyncAcceptedSerializer(serializers.Serializer):
    """Response serializer when payload exceeds size threshold and returns 202."""

    success = serializers.BooleanField(default=True)
    module = serializers.CharField()
    data = serializers.DictField()
    meta = serializers.DictField(required=False)
