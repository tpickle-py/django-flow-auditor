"""AppConfig for flow_auditor Django application."""

from django.apps import AppConfig


class FlowAuditorConfig(AppConfig):
    """AppConfig for flow_auditor."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "flow_auditor"
    verbose_name = "Network Flow Auditor"

    def ready(self) -> None:
        """Hook called when Django starts up."""
        # Ensure registry is initialized
        from flow_auditor.services.registry import get_default_registry

        get_default_registry()
