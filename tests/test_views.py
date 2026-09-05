"""Tests for DRF API endpoints."""

import pytest
from rest_framework import status
from rest_framework.test import APIClient

from flow_auditor.models import Job, JobStatus


@pytest.fixture
def api_client():
    return APIClient()


@pytest.mark.django_db
def test_parse_api_sync(api_client):
    url = "/parse/cisco-asa-parser/"
    payload = {"config": "access-list TEST extended permit tcp any any eq 443"}
    response = api_client.post(url, payload, format="json")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]) == 1
    assert data["data"][0]["acl"] == "TEST"


@pytest.mark.django_db
def test_parse_api_force_async(api_client):
    url = "/parse/cisco-asa-parser/?async=true"
    payload = {"config": "access-list TEST extended permit tcp any any eq 443"}
    response = api_client.post(url, payload, format="json")
    assert response.status_code == status.HTTP_202_ACCEPTED
    data = response.json()
    assert data["success"] is True
    assert "jobId" in data["data"]
    assert data["data"]["status"] == "queued"


@pytest.mark.django_db
def test_modules_list_view(api_client):
    url = "/modules/"
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["success"] is True
    assert len(data["data"]["modules"]) >= 5


@pytest.mark.django_db
def test_job_submission_and_detail(api_client):
    submit_url = "/jobs/"
    payload = {
        "module": "flowdiff",
        "config": '{"flowsA": [], "flowsB": []}',
        "priority": 7,
    }
    response = api_client.post(submit_url, payload, format="json")
    assert response.status_code == status.HTTP_201_CREATED
    job_data = response.json()["job"]
    job_id = job_data["jobId"]

    # Detail
    detail_url = f"/jobs/{job_id}/"
    detail_resp = api_client.get(detail_url)
    assert detail_resp.status_code == status.HTTP_200_OK
    assert detail_resp.json()["jobId"] == job_id


@pytest.mark.django_db
def test_job_idempotency_replay(api_client):
    submit_url = "/jobs/"
    payload = {
        "module": "cisco-asa-parser",
        "config": "access-list T extended permit ip any any",
        "idempotencyKey": "test-key-100",
    }
    resp1 = api_client.post(submit_url, payload, format="json")
    assert resp1.status_code == status.HTTP_201_CREATED

    resp2 = api_client.post(submit_url, payload, format="json")
    assert resp2.status_code == status.HTTP_200_OK
    assert resp2.json()["idempotentReplay"] is True


@pytest.mark.django_db
def test_job_cancellation(api_client):
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.QUEUED,
        normalized_hash="test-hash",
    )
    cancel_url = f"/jobs/{job.id}/cancel/"
    response = api_client.post(cancel_url)
    assert response.status_code == status.HTTP_200_OK
    job.refresh_from_db()
    assert job.status == JobStatus.CANCELLED


@pytest.mark.django_db
def test_admin_stats_view(api_client):
    url = "/admin/stats/"
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "totalJobs" in data["data"]


@pytest.mark.django_db
def test_admin_retention_trigger(api_client):
    url = "/admin/retention/trigger/"
    response = api_client.post(url, {"days": 30}, format="json")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["success"] is True
