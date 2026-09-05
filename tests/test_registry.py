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


def test_registry_cisco_and_juniper_objects():
    # Cisco ASA objects action
    cisco_cfg = "name 10.1.1.1 H1\nobject network N1\n host 1.1.1.1"
    res_c = execute_module("cisco-asa-parser", cisco_cfg, query={"action": "objects"})
    assert res_c["exportUsed"] == "parseObjects"
    assert "H1" in res_c["data"]["nameMap"]

    # Juniper SRX objects action and parse
    srx_cfg = "set security address-book global address H1 2.2.2.2/32"
    res_j_obj = execute_module("juniper-srx-parser", srx_cfg, query={"action": "objects"})
    assert res_j_obj["exportUsed"] == "parseObjects"
    assert "H1" in res_j_obj["data"]["globalBook"]

    res_j_parse = execute_module("juniper-srx-parser", srx_cfg)
    assert res_j_parse["exportUsed"] == "parseConfig"


def test_registry_flowdiff_and_errors():
    # Invalid diff input
    with pytest.raises(ValueError, match="flowdiff requires flowsA and flowsB"):
        execute_module("flowdiff", {"flowsA": "invalid"})

    # Valid diff input
    res = execute_module("flowdiff", {"flowsA": [], "flowsB": []})
    assert res["exportUsed"] == "diffFlows"


def test_registry_approval_and_errors():
    # Invalid approval input
    with pytest.raises(ValueError, match="flow-approval-checker requires"):
        execute_module("flow-approval-checker", {"approved_flows": "not-a-list"})

    # Valid approval input
    res = execute_module(
        "flow-approval-checker",
        {"approved_flows": [], "flows_to_check": []},
    )
    assert res["exportUsed"] == "check_flow_approvals"


def test_registry_zone_advise_and_resolve():
    # Zone advise
    res_advise = execute_module(
        "zone-any-resolver",
        {"allRules": [{"source": ["10.0.0.1/32"]}]},
        query={"action": "advise"},
    )
    assert res_advise["exportUsed"] == "advise"

    # Zone resolve
    res_resolve = execute_module(
        "zone-any-resolver",
        {"items": [{"source": "any", "dest": "10.0.0.1"}]},
    )
    assert res_resolve["exportUsed"] == "process_items"

    # Zone error invalid config
    with pytest.raises(ValueError, match="zone-any-resolver requires"):
        execute_module("zone-any-resolver", {"invalid": 123})
