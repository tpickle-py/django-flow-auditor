"""Tests for webhook signing and delivery."""

from unittest.mock import MagicMock, patch

from flow_auditor.services.webhooks import deliver_webhook, sign_payload


def test_sign_payload():
    payload_bytes = b'{"event": "job.completed"}'
    secret = "test-secret"
    sig = sign_payload(payload_bytes, secret)
    assert sig.startswith("sha256=")
    assert len(sig) == 7 + 64  # 'sha256=' + 64-char hex digest


@patch("flow_auditor.services.webhooks.httpx.Client")
def test_deliver_webhook_success(mock_client_cls):
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status.return_value = None
    mock_client.post.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_client

    success = deliver_webhook(
        "https://example.com/webhook",
        {"jobId": "test-id", "status": "completed"},
        secret="secret-key",
    )
    assert success is True
    mock_client.post.assert_called_once()


@patch("flow_auditor.services.webhooks.httpx.Client")
def test_deliver_webhook_http_error(mock_client_cls):
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.raise_for_status.side_effect = Exception("500 Server Error")
    mock_client.post.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_client

    success = deliver_webhook("https://example.com/webhook", {"status": "completed"})
    assert success is False
