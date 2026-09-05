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


@pytest.fixture
def admin_user(db):
    from django.contrib.auth.models import User

    return User.objects.create_superuser(
        username="admin", password="password", email="admin@example.com"
    )


@pytest.mark.django_db
def test_admin_stats_view(api_client, admin_user):
    url = "/admin/stats/"
    # Unauthenticated should be 403 Forbidden
    unauth_resp = api_client.get(url)
    assert unauth_resp.status_code == status.HTTP_403_FORBIDDEN

    # Authenticated staff user should be 200 OK
    api_client.force_authenticate(user=admin_user)
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "totalJobs" in data["data"]


@pytest.mark.django_db
def test_admin_retention_trigger(api_client, admin_user):
    url = "/admin/retention/trigger/"
    api_client.force_authenticate(user=admin_user)
    response = api_client.post(url, {"days": 30}, format="json")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["success"] is True


@pytest.mark.django_db
def test_job_list_filtering(api_client):
    Job.objects.create(
        module_slug="cisco-asa-parser",
        tenant_id="tenant-a",
        status=JobStatus.QUEUED,
        normalized_hash="hash1",
    )
    Job.objects.create(
        module_slug="juniper-srx-parser",
        tenant_id="tenant-b",
        status=JobStatus.COMPLETED,
        normalized_hash="hash2",
    )

    resp = api_client.get("/jobs/?status=queued")
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert len(data) == 1
    assert data[0]["module"] == "cisco-asa-parser"

    resp2 = api_client.get("/jobs/?module=juniper-srx-parser")
    assert resp2.status_code == status.HTTP_200_OK
    assert len(resp2.json()) == 1

    resp3 = api_client.get("/jobs/?tenant=tenant-a")
    assert resp3.status_code == status.HTTP_200_OK
    assert len(resp3.json()) == 1


@pytest.mark.django_db
def test_job_cancel_edge_cases(api_client):
    # Non-existent
    resp = api_client.post("/jobs/00000000-0000-0000-0000-000000000000/cancel/")
    assert resp.status_code == status.HTTP_404_NOT_FOUND

    # Already completed
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.COMPLETED,
        normalized_hash="hash3",
    )
    resp = api_client.post(f"/jobs/{job.id}/cancel/")
    assert resp.status_code == status.HTTP_409_CONFLICT

    # Running job request cancel
    job.status = JobStatus.RUNNING
    job.save()
    resp = api_client.post(f"/jobs/{job.id}/cancel/")
    assert resp.status_code == status.HTTP_200_OK
    job.refresh_from_db()
    assert job.status == JobStatus.CANCEL_REQUESTED


@pytest.mark.django_db
def test_job_events_view(api_client):
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.QUEUED,
        normalized_hash="hash4",
    )
    from flow_auditor.models import ActorType, JobEvent

    JobEvent.objects.create(
        job=job,
        event_type="job.created",
        actor_type=ActorType.SYSTEM,
        actor_id="system",
    )

    resp = api_client.get(f"/jobs/{job.id}/events/")
    assert resp.status_code == status.HTTP_200_OK
    events = resp.json()["events"]
    assert len(events) == 1

    resp_404 = api_client.get("/jobs/00000000-0000-0000-0000-000000000000/events/")
    assert resp_404.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_admin_job_retry_view(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    # Non-existent
    resp = api_client.post("/admin/jobs/00000000-0000-0000-0000-000000000000/retry/")
    assert resp.status_code == status.HTTP_404_NOT_FOUND

    # Not failed
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.COMPLETED,
        normalized_hash="hash5",
    )
    resp = api_client.post(f"/admin/jobs/{job.id}/retry/")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST

    # Failed job retry
    job.status = JobStatus.FAILED
    job.request_json = {"config": "access-list T extended permit ip any any"}
    job.save()
    resp = api_client.post(f"/admin/jobs/{job.id}/retry/")
    assert resp.status_code == status.HTTP_200_OK
    job.refresh_from_db()
    assert job.status == JobStatus.COMPLETED


@pytest.mark.django_db
def test_parse_view_errors(api_client):
    # Unknown module
    resp = api_client.post("/parse/unknown-module/", {"config": "test"}, format="json")
    assert resp.status_code == status.HTTP_404_NOT_FOUND

    # Invalid request body (missing config)
    resp2 = api_client.post("/parse/cisco-asa-parser/", {}, format="json")
    assert resp2.status_code == status.HTTP_400_BAD_REQUEST

    # Parse exception in sync execution
    resp3 = api_client.post("/parse/flowdiff/", {"config": "{}"}, format="json")
    assert resp3.status_code == status.HTTP_400_BAD_REQUEST
    assert resp3.json()["error"]["code"] == "PARSE_ERROR"


@pytest.mark.django_db
def test_job_submit_validation_and_not_found(api_client):
    # Invalid serializer body
    resp = api_client.post("/jobs/", {}, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST

    # Unknown module
    resp2 = api_client.post(
        "/jobs/",
        {"module": "unknown-module", "config": "test"},
        format="json",
    )
    assert resp2.status_code == status.HTTP_404_NOT_FOUND
