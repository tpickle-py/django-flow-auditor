# django-flow-auditor

A reusable, installable Django application providing network flow parsing, configuration diffing, and security approval auditing across Cisco ASA, Juniper SRX, and custom firewall rules.

`django-flow-auditor` consolidates and modernizes the services formerly implemented across individual n8n node packages and Node.js microservices into a unified Python package designed for seamless installation into any Django project via `uv`.

---

## Features

- **Cisco ASA ACL Parser**: Complete two-pass parser with network and service object/group resolution, name lookups, remark association, and command-mode hitcount parsing.
- **Juniper SRX Security Policy Parser**: Parses JunOS configurations in both `set` command syntax and hierarchical `{ ... }` stanza format, resolving global and zone address books and application sets.
- **FlowDiff Engine**: In-memory Cartesian expansion and tuple-based diffing detecting granted access, revoked access, and ACL renames/splits/merges.
- **Flow Approval Checker**: Evaluates candidate network flows against approved security records (e.g. ServiceNow tickets), outputting `approved`, `partial`, or `not_approved` status with detailed field-level match explanations.
- **ZoneAny Resolver & Advisor**: Replaces overly permissive `any` src/dst keywords with specific subnets based on zone matching, and calculates minimal CIDR aggregation recommendations with permissiveness scoring.
- **Dual-Mode REST API (DRF)**: Synchronous responses for interactive workflows, with automatic 202 Accepted + Celery background task handoff when payload size exceeds configurable thresholds.
- **Celery Background Processing**: Robust asynchronous job execution with worker leases, heartbeats, cancellation checkpoints, retry backoff, dead-lettering, and HMAC-signed webhook delivery.
- **Result Archival & Retention**: Automated retention tasks to archive expired job results and clear operational databases.

---

## Installation

Install `django-flow-auditor` into your Django project using `uv`:

```bash
uv add git+https://gitlab.travispickle.work/tpickle/django-flow-auditor.git
```

Or with standard `pip`:

```bash
pip install git+https://gitlab.travispickle.work/tpickle/django-flow-auditor.git
```

---

## Integration into Host Django Project

### 1. Update `INSTALLED_APPS`
Add `rest_framework` and `flow_auditor` to your project's `settings.py`:

```python
INSTALLED_APPS = [
    # ... Django core apps
    "rest_framework",
    "flow_auditor",
]
```

### 2. Apply Migrations
Run Django migrations to create the required database tables:

```bash
python manage.py migrate
```

### 3. Mount URLs
Include the app's URLconf in your root `urls.py`:

```python
from django.urls import path, include

urlpatterns = [
    # ... your existing endpoints
    path("api/flow-auditor/", include("flow_auditor.urls")),
]
```

### 4. Configure Celery Autodiscovery
In your project's `celery.py`, enable task autodiscovery:

```python
import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")

app = Celery("myproject")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
```

### 5. Optional Configuration Settings
Customize default behavior by setting any of the following variables in `settings.py`:

```python
# Content size in bytes above which POST /parse/ automatically returns 202 Accepted
FLOW_AUDITOR_ASYNC_THRESHOLD_BYTES = 500_000  # Default: 500 KB

# Default execution timeout in milliseconds for background jobs
FLOW_AUDITOR_DEFAULT_TIMEOUT_MS = 60_000      # Default: 60 seconds

# Max automated worker retry attempts before dead-lettering
FLOW_AUDITOR_MAX_ATTEMPTS = 3                 # Default: 3 attempts

# Max webhook delivery retry attempts
FLOW_AUDITOR_WEBHOOK_MAX_RETRIES = 3          # Default: 3 attempts

# Worker lease heartbeat TTL in seconds
FLOW_AUDITOR_LEASE_TTL_SECONDS = 60           # Default: 60 seconds

# Days before terminal job results are moved to cold storage
FLOW_AUDITOR_RETENTION_DAYS = 30              # Default: 30 days
```

---

## API Reference

All endpoints are mounted under the prefix defined in your root `urls.py` (e.g. `/api/flow-auditor/`):

### 1. `POST /parse/<module_slug>/`
Runs parsing or diffing synchronously for normal configs, or returns `202 Accepted` with a `jobId` if the request body exceeds `FLOW_AUDITOR_ASYNC_THRESHOLD_BYTES` or if `?async=true` is supplied.

**Request Body**:
```json
{
  "config": "access-list OUTSIDE extended permit tcp any host 10.0.0.1 eq 443",
  "options": {
    "includeRaw": false,
    "groupByAcl": false
  },
  "filter": {
    "action": "permit"
  }
}
```

**Synchronous Response (200 OK)**:
```json
{
  "success": true,
  "module": "cisco-asa-parser",
  "data": [
    {
      "acl": "OUTSIDE",
      "action": "permit",
      "source": ["any"],
      "dest": ["10.0.0.1/32"],
      "services": ["tcp/443"]
    }
  ],
  "meta": {
    "durationMs": 4.12,
    "adapter": "cisco-asa",
    "exportUsed": "parseAsaConfig"
  }
}
```

**Asynchronous Response (202 Accepted)**:
```json
{
  "success": true,
  "module": "cisco-asa-parser",
  "data": {
    "jobId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "status": "queued",
    "statusUrl": "https://api.example.com/api/flow-auditor/jobs/a1b2c3d4-e5f6-7890-abcd-ef1234567890/",
    "createdAt": "2026-09-05T00:00:00Z",
    "mode": "async",
    "reason": "content_size_threshold_exceeded",
    "thresholdBytes": 500000,
    "contentSizeBytes": 750230
  }
}
```

### 2. `POST /jobs/`
Explicitly submit an asynchronous background job with priority, idempotency, and optional webhook notification.

**Request Body**:
```json
{
  "module": "flowdiff",
  "config": "{\"flowsA\": [...], \"flowsB\": [...]}",
  "priority": 7,
  "idempotencyKey": "audit-job-2026-09-05-v1",
  "webhook": {
    "url": "https://callback.example.com/hooks/flow-audit",
    "secretRef": "my-hmac-secret-key"
  }
}
```

**Response (201 Created)**:
```json
{
  "success": true,
  "job": {
    "jobId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "status": "queued",
    "priority": 7,
    "progress": {
      "percent": 0,
      "stage": null,
      "message": null
    },
    "result": null,
    "error": null,
    "statusUrl": "https://api.example.com/api/flow-auditor/jobs/a1b2c3d4-e5f6-7890-abcd-ef1234567890/"
  },
  "idempotentReplay": false
}
```

### 3. `GET /jobs/<job_id>/`
Retrieve the real-time progress, status, and result of an async job.

### 4. `POST /jobs/<job_id>/cancel/`
Request cancellation of an active or queued job. Workers detect cancellation at multiple execution checkpoints.

### 5. `GET /modules/`
List all registered firewall and audit adapter engines, their supported actions, and operational status.

---

## Python API (Direct Service Usage)

All core business logic is implemented as pure, framework-agnostic Python functions that can be imported and invoked directly without spinning up Django views or Celery workers:

```python
from flow_auditor.services import (
    parse_asa_config,
    parse_srx_config,
    diff_flows,
    check_flow_approvals,
    process_items,
    advise,
)

# Parse Cisco ASA configuration
cisco_flows = parse_asa_config(asa_config_text, options={"groupByAcl": True})

# Parse Juniper SRX configuration (hierarchical or set syntax)
srx_flows = parse_srx_config(srx_config_text)

# Diff two flow lists
diff_result = diff_flows(cisco_flows, srx_flows, options={"detectRenames": True})

# Audit candidate flows against approved ServiceNow records
audit_results = check_flow_approvals(approved_flows, candidate_flows)
```

---

## Development & Testing

Set up development dependencies:
```bash
uv sync --all-groups
```

Run test suite:
```bash
uv run pytest
```

Run linter and formatter:
```bash
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
```

Run dead-code sweep:
```bash
uv run vulture src/
```

---

## License

MIT License. Copyright (c) Travis Pickle.
