"""App-level URLconf for flow_auditor.

Meant to be included in host Django project:
    path("api/flow-auditor/", include("flow_auditor.urls")),
"""

from django.urls import path

from flow_auditor.views import (
    AdminJobRetryView,
    AdminJobStatsView,
    AdminRetentionTriggerView,
    JobCancelView,
    JobDetailView,
    JobEventsView,
    JobListView,
    ModulesListView,
    ParseAPIView,
)

app_name = "flow_auditor"

urlpatterns = [
    # Parsing
    path("parse/<str:module>/", ParseAPIView.as_view(), name="parse"),
    # Jobs
    path("jobs/", JobListView.as_view(), name="job-list"),
    path("jobs/<uuid:pk>/", JobDetailView.as_view(), name="job-detail"),
    path("jobs/<uuid:pk>/cancel/", JobCancelView.as_view(), name="job-cancel"),
    path("jobs/<uuid:pk>/events/", JobEventsView.as_view(), name="job-events"),
    # Modules catalog
    path("modules/", ModulesListView.as_view(), name="modules-list"),
    # Administration
    path("admin/stats/", AdminJobStatsView.as_view(), name="admin-stats"),
    path("admin/jobs/<uuid:pk>/retry/", AdminJobRetryView.as_view(), name="admin-job-retry"),
    path(
        "admin/retention/trigger/",
        AdminRetentionTriggerView.as_view(),
        name="admin-retention-trigger",
    ),
]
