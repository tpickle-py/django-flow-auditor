"""Webhook delivery service with HMAC signing and retry policy."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Generate SHA256 HMAC signature for webhook payload."""
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def deliver_webhook(
    url: str,
    payload: dict[str, Any],
    secret: str | None = None,
    timeout_seconds: float = 10.0,
) -> bool:
    """Deliver a JSON webhook to the destination URL with optional HMAC signature."""
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "django-flow-auditor/1.0.0",
        "X-Job-ID": str(payload.get("jobId", "")),
    }

    if secret:
        headers["X-Webhook-Signature"] = sign_payload(payload_bytes, secret)
        headers["X-Hub-Signature-256"] = sign_payload(payload_bytes, secret)

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = client.post(url, content=payload_bytes, headers=headers)
            resp.raise_for_status()
            logger.info("Webhook successfully delivered to %s (status=%d)", url, resp.status_code)
            return True
    except Exception as exc:
        logger.warning("Webhook delivery to %s failed: %s", url, exc)
        return False
