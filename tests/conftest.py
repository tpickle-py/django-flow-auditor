"""Pytest configuration and test Celery app setup."""

import os

from celery import current_app

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")

# Configure the current default Celery app to use in-memory eager execution
current_app.conf.update(
    task_always_eager=True,
    task_eager_propagates=True,
    broker_url="memory://",
    result_backend="cache+memory://",
)
