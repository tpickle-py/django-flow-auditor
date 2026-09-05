# Migration Notes: TypeScript/JavaScript Monorepo to Reusable Django App

This document details the migration from the `network-flow-auditor` monorepo and its five submodules into the standalone `django-flow-auditor` Python package.

---

## Source-by-Source Migration Mapping

### 1. `n8n-nodes-cisco-asa-parser`
- **Original Location**: `submodules/n8n-nodes-cisco-asa-parser/src/asaParser.js`
- **New Location**: `src/flow_auditor/services/cisco_asa.py`
- **New Architectural Layer**: **Pure Python Service** (no Django ORM or web framework dependencies)
- **Key Changes**:
  - Eliminated n8n node lifecycle boilerplate (`CiscoAsaParser.node.js`, `build.js`, `icon.svg`).
  - Consolidated IP address math (`maskToCIDR`, `isIp`, `ipToInt`) into `flow_auditor.common.ip_utils`.
  - Consolidated `PORT_MAP`, `ICMP_TYPES`, and `PROTO_NUMS` into `flow_auditor.common.services_map`.
  - Retained two-pass parsing architecture: Pass 1 object network/service/group collection, Pass 2 ACE line parsing with recursive resolution and command-mode hitcount parsing.
  - Added full Python type hints (`list[dict[str, Any]]`) and NumPy/Google-style docstrings.

---

### 2. `n8n-nodes-juniper-srx-parser`
- **Original Location**: `submodules/n8n-nodes-juniper-srx-parser/src/srxParser.js`
- **New Location**: `src/flow_auditor/services/juniper_srx.py`
- **New Architectural Layer**: **Pure Python Service**
- **Key Changes**:
  - Removed n8n wrapper classes (`JuniperSrxParser.node.js`).
  - Ported `detectFormat` and `stanzaToSetLines` to Python regex-based stack parser, faithfully supporting both `set` command strings and hierarchical JunOS `{ ... }` curly-brace stanzas.
  - Ported global and zone-scoped address-book and address-set resolvers.
  - Consolidated `JUNOS_APPS` into `flow_auditor.common.services_map`.

---

### 3. `n8n-nodes-flowdiff`
- **Original Location**: `submodules/n8n-nodes-flowdiff/src/diffEngine.js`
- **New Location**: `src/flow_auditor/services/flowdiff.py`
- **New Architectural Layer**: **Pure Python Service**
- **Key Changes**:
  - Removed n8n wrapper class (`FlowDiff.node.js`).
  - Preserved the Cartesian expansion algorithm (`expand_tuples`) generating atomic `(source, dest, service)` tuples.
  - Preserved rename/split/merge fingerprint matching between old and new ACLs.
  - Preserved peer context enrichment, change collapsing, and unresolved reference handling (`unresolved:object-name`).

---

### 4. `n8n-nodes-flow-approval-checker`
- **Original Location**: `submodules/n8n-nodes-flow-approval-checker/src/FlowApprovalChecker.node.js`
- **New Location**: `src/flow_auditor/services/approval.py`
- **New Architectural Layer**: **Pure Python Service**
- **Key Changes**:
  - Separated pure flow matching logic from n8n node execution context (`getInputData`, `getNodeParameter`).
  - Consolidated duplicate `ipToInt` and `ipInCidr` into `flow_auditor.common.ip_utils`.
  - Replaced ad-hoc JS cache benchmarks and experimental caching branches with clean, idiomatic Python set operations and normalized dictionary structures.
  - Cleaned up unused variable `flowActionField`.
  - Retained matching semantics: 3-field match -> `approved`, 2-field match -> `partial`, <2-field match -> `not_approved`.

---

### 5. `n8n-nodes-zone-any-resolver`
- **Original Locations**:
  - `submodules/n8n-nodes-zone-any-resolver/src/ZoneAnyResolver.node.js`
  - `submodules/n8n-nodes-zone-any-resolver/src/ZoneRuleAdvisor.node.js`
- **New Locations**:
  - `src/flow_auditor/services/zone_resolver.py`
  - `src/flow_auditor/services/zone_advisor.py`
- **New Architectural Layer**: **Pure Python Services**
- **Key Changes**:
  - Removed n8n node class definitions and build scripts.
  - Ported `process_items` for zone-regex matching and automatic `any` expansion.
  - Ported `advise`, `aggregate_cidrs`, `enclosing_supernet`, and `count_addresses` using Python 3 bitwise operations (`int.bit_length()`, `math.log2`), matching original recommendation algorithms and permissiveness scoring.

---

### 6. `@network-flow/adapters`
- **Original Location**: `packages/adapters/src/registry.ts`, `packages/adapters/src/normalize.ts`
- **New Locations**:
  - `src/flow_auditor/services/registry.py`
  - `src/flow_auditor/common/normalization.py`
- **New Architectural Layer**: **Service Layer & Common Utilities**
- **Key Changes**:
  - Replaced filesystem scanning and `requireFromHere` dynamic Node.js module loading with a clean Python `EngineRegistry` registry class.
  - Registered built-in handlers for all five engines with uniform execution signature `execute_module(slug, config, options, filter_params, query)`.

---

### 7. `apps/api-gateway`
- **Original Location**: `apps/api-gateway/src/routes/`, `apps/api-gateway/src/db/`
- **New Locations**:
  - `src/flow_auditor/views/` (`ParseAPIView`, `JobListView`, `JobDetailView`, `JobCancelView`, `ModulesListView`, `AdminJobStatsView`, `AdminJobRetryView`, `AdminRetentionTriggerView`)
  - `src/flow_auditor/serializers/` (`JobSubmitSerializer`, `JobDetailSerializer`, `ParseRequestSerializer`, etc.)
  - `src/flow_auditor/models/` (`Job`, `JobEvent`, `JobResultArchive`, `ArchiveOperation`, `AdminAuditLog`)
  - `src/flow_auditor/urls.py`
- **New Architectural Layer**: **Django ORM Models & Django REST Framework Views**
- **Key Changes**:
  - Replaced Fastify route handlers with DRF class-based views.
  - Replaced raw PostgreSQL schema migrations (`pg` client) with standard Django ORM models and migrations (`0001_initial.py`).
  - Decoupled authentication from a rigid custom `admin_users` table so the package installs cleanly into any host Django project using standard `request.user` authentication.
  - Maintained dual-mode parsing: synchronous execution for normal payloads, with automatic 202 Accepted + Celery background task dispatch if payload exceeds `FLOW_AUDITOR_ASYNC_THRESHOLD_BYTES`.

---

### 8. `apps/job-worker`
- **Original Location**: `apps/job-worker/src/worker.ts`, `apps/job-worker/src/executor.ts`
- **New Location**: `src/flow_auditor/tasks.py`
- **New Architectural Layer**: **Celery Tasks**
- **Key Changes**:
  - Replaced BullMQ and Redis connection management with Celery's standard `@shared_task` decorator.
  - Implemented lease ownership, heartbeat timestamps, and cancellation checkpoints directly within `execute_job_task`.
  - Implemented exponential backoff and retry policies for Celery workers.
  - Ported HMAC SHA-256 webhook delivery to `deliver_webhook_task` using Python's `httpx` client.
  - Ported retention sweeps and lease cleanup to scheduled Celery tasks (`archive_retention_task`, `cleanup_expired_leases_task`).

---

## Summary of Eliminated Dead Code

1. **Toolchain & Framework Artifacts**:
   - Removed `pnpm-workspace.yaml`, `tsconfig.base.json`, `Dockerfile.ci`, `Makefile`, and duplicate `package.json` files.
   - Eliminated `n8n-workflow` peer dependencies and node UI schemas.
2. **Duplicated Utility Code**:
   - Replaced 3 independent implementations of IP integer parsing and CIDR checking with `flow_auditor.common.ip_utils`.
   - Replaced 3 independent port/service lookup dictionaries with `flow_auditor.common.services_map`.
3. **Unused Fields & Experimental Code**:
   - Dropped unused `flowActionField` in approval checker.
   - Dropped experimental in-memory cache benchmark scripts (`benchmark/cache-benchmark.js`).
