# CLAUDE.md — Agent & Developer Guide for django-flow-auditor

## Package Overview & Purpose
`django-flow-auditor` is a reusable, self-contained Django application providing network flow parsing, diffing, and security approval auditing. It unifies five formerly separate TypeScript/JavaScript packages into idiomatic Python services with Django REST Framework (DRF) API endpoints and Celery background task processing.

---

## Source Mapping (Original npm / GitLab Repos → Python Modules)

| Original Source | Original Layer | Ported Python Module | New Layer | Description |
| :--- | :--- | :--- | :--- | :--- |
| `n8n-nodes-cisco-asa-parser` (`asaParser.js`) | n8n custom node / JS parser | `flow_auditor.services.cisco_asa` | **Pure Service** | Two-pass Cisco ASA ACL parser with object/object-group resolution, remark tracking, and command-mode hitcnt parsing. |
| `n8n-nodes-juniper-srx-parser` (`srxParser.js`) | n8n custom node / JS parser | `flow_auditor.services.juniper_srx` | **Pure Service** | Two-pass Juniper JunOS SRX parser supporting both `set` syntax and hierarchical `{ ... }` stanzas, resolving address books and application sets. |
| `n8n-nodes-flowdiff` (`diffEngine.js`) | n8n custom node / JS diff engine | `flow_auditor.services.flowdiff` | **Pure Service** | In-memory Cartesian expansion and tuple-based diffing engine detecting `access_granted`, `access_revoked`, and ACL renames/splits/merges. |
| `n8n-nodes-flow-approval-checker` (`FlowApprovalChecker.node.js`) | n8n custom node / JS matcher | `flow_auditor.services.approval` | **Pure Service** | CIDR and named-service matching engine checking candidate flows against approved flows; outputs `approved`, `partial`, or `not_approved`. |
| `n8n-nodes-zone-any-resolver` (`ZoneAnyResolver.node.js`) | n8n custom node / JS resolver | `flow_auditor.services.zone_resolver` | **Pure Service** | Zone-aware replacement of `any` src/dst keywords with specific subnets based on regex pattern matching. |
| `n8n-nodes-zone-any-resolver` (`ZoneRuleAdvisor.node.js`) | n8n custom node / JS advisor | `flow_auditor.services.zone_advisor` | **Pure Service** | Bitwise IP prefix aggregation and enclosing supernet analyzer recommending tight CIDR boundaries for overly permissive `any` rules. |
| `@network-flow/adapters` (`registry.ts`, `normalize.ts`) | TypeScript adapter gateway | `flow_auditor.services.registry`, `flow_auditor.common.*` | **Service & Shared** | Dynamic module registry, shared `ip_utils`, shared `services_map`, and parameter normalization. |
| `apps/api-gateway` (Fastify routes, PG schema) | Node.js Fastify API server | `flow_auditor.views.*`, `flow_auditor.models.*` | **API & ORM Models** | DRF API views (`ParseAPIView`, `JobListView`, `JobDetailView`, `JobCancelView`, `ModulesListView`) and Django ORM models (`Job`, `JobEvent`, `JobResultArchive`, `ArchiveOperation`, `AdminAuditLog`). |
| `apps/job-worker` (BullMQ worker, executor) | Node.js background worker | `flow_auditor.tasks` | **Celery Tasks** | `@shared_task` Celery tasks for asynchronous execution, retry backoff, webhook delivery, and retention archiving. |

---

## Integration into Host Django Projects

### 1. Installation
Install the package using `uv`:
```bash
uv add git+https://gitlab.travispickle.work/tpickle/django-flow-auditor.git
```

### 2. Configure `INSTALLED_APPS`
In the host project's `settings.py`:
```python
INSTALLED_APPS = [
    # Django core apps ...
    "rest_framework",
    "flow_auditor",
]
```

### 3. Run Migrations
Apply database migrations for the app's models (`Job`, `JobEvent`, `JobResultArchive`, `ArchiveOperation`, `AdminAuditLog`):
```bash
uv run python manage.py migrate
```

### 4. Include URLconf
In the host project's root `urls.py`:
```python
from django.urls import path, include

urlpatterns = [
    # ... other routes
    path("api/flow-auditor/", include("flow_auditor.urls")),
]
```

### 5. Celery Configuration
The app uses Celery's `@shared_task`. Ensure the host project's `celery.py` includes task autodiscovery:
```python
import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")

app = Celery("myproject")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
```

### 6. Optional Settings (and Defaults)
Host projects can customize behavior in `settings.py`:
```python
# Content size threshold (in bytes) above which POST /parse/ returns 202 and runs async in Celery
FLOW_AUDITOR_ASYNC_THRESHOLD_BYTES = 500_000  # 500 KB

# Default execution timeout for background jobs (milliseconds)
FLOW_AUDITOR_DEFAULT_TIMEOUT_MS = 60_000

# Max automatic worker retries before dead-lettering
FLOW_AUDITOR_MAX_ATTEMPTS = 3

# Max webhook delivery retry attempts
FLOW_AUDITOR_WEBHOOK_MAX_RETRIES = 3

# Worker lease heartbeat TTL in seconds
FLOW_AUDITOR_LEASE_TTL_SECONDS = 60

# Days before terminal job results are moved to cold archive
FLOW_AUDITOR_RETENTION_DAYS = 30
```

---

## Developer Workflow & Commands

### Running Tests
Execute the complete pytest test suite:
```bash
uv run pytest
```
Run specific module tests:
```bash
uv run pytest tests/test_cisco_asa.py
uv run pytest tests/test_views.py
uv run pytest tests/test_tasks.py
```

### Code Formatting & Linting
Check lint rules with Ruff:
```bash
uv run ruff check src/ tests/
```
Auto-fix lint issues:
```bash
uv run ruff check --fix src/ tests/
```
Check code formatting:
```bash
uv run ruff format --check src/ tests/
```
Format all code:
```bash
uv run ruff format src/ tests/
```

### Dead-Code Sweep
Run Vulture to detect unused functions, classes, or variables:
```bash
uv run vulture src/
```
*Rule: Ensure vulture exits with code 0 before submitting any Pull Request.*

---

## How to Extend the Application

### Adding a New Parser or Engine
1. Implement the pure parsing/diffing logic in `src/flow_auditor/services/<new_engine>.py` (zero Django/DRF dependencies).
2. Register the module in `src/flow_auditor/services/registry.py` inside `EngineRegistry._register_builtins()`.
3. Add unit tests in `tests/test_<new_engine>.py`.

### Adding a New DRF Endpoint
1. Define any request/response serializers in `src/flow_auditor/serializers/`.
2. Create the API view in `src/flow_auditor/views/`.
3. Export from `src/flow_auditor/views/__init__.py` and bind the route in `src/flow_auditor/urls.py`.
4. Add API tests using DRF's `APIClient` in `tests/test_views.py`.

### Adding a New Background Task
1. Define the task with `@shared_task` in `src/flow_auditor/tasks.py`.
2. Add tests in `tests/test_tasks.py` leveraging eager task execution (`CELERY_TASK_ALWAYS_EAGER = True`).
