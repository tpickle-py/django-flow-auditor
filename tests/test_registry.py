"""Tests for the engine registry and dynamic execution."""

import pytest

from flow_auditor.services.registry import execute_module, get_default_registry


def test_registry_list_modules():
    registry = get_default_registry()
    modules = registry.list_modules()
    slugs = [m["slug"] for m in modules]
    assert "cisco-asa-parser" in slugs
    assert "juniper-srx-parser" in slugs
    assert "flowdiff" in slugs
    assert "flow-approval-checker" in slugs
    assert "zone-any-resolver" in slugs


def test_registry_execution():
    cfg = "access-list TEST extended permit tcp any any eq 80"
    res = execute_module("cisco-asa-parser", cfg)
    assert "data" in res
    assert res["exportUsed"] == "parseAsaConfig"


def test_registry_unknown_module():
    with pytest.raises(ValueError):
        execute_module("non-existent-module", "config")
