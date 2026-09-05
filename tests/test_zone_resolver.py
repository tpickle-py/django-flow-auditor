"""Tests for ZoneAnyResolver ported from n8n-nodes-zone-any-resolver test suite."""

from flow_auditor.services.zone_resolver import process_items


def test_zone_any_resolver_expansion():
    rules = [
        {
            "match": {"acl": "OUTSIDE", "direction": "inbound"},
            "srcAny": ["203.0.113.0/24", "198.51.100.0/24"],
            "dstAny": ["10.1.0.0/16"],
        }
    ]
    items = [{"acl": "OUTSIDE", "direction": "inbound", "src_ip": "any", "dst_ip": "any"}]
    out = process_items(items, {"zoneRules": rules})
    assert "203.0.113.0/24" in out[0]["src_ip"]
    assert "10.1.0.0/16" in out[0]["dst_ip"]
    assert out[0]["_zoneMatch"] is True
    assert out[0]["_anyExpanded"] is True


def test_zone_any_resolver_no_match():
    rules = [{"match": {"acl": "OTHER"}, "srcAny": ["1.1.1.0/24"]}]
    items = [{"acl": "UNMATCHED", "src_ip": "any", "dst_ip": "10.0.0.1"}]
    out = process_items(items, {"zoneRules": rules})
    assert out[0]["src_ip"] == "0.0.0.0/0"
    assert out[0]["_zoneMatch"] is False


def test_zone_any_resolver_list_and_regex_error():
    rules = [
        {"match": {"acl": "[invalid(regex"}, "srcAny": ["10.0.0.0/8"]},
        {"match": {"acl": "LAN.*"}, "srcAny": ["192.168.0.0/16"], "dstAny": None},
    ]
    items = [{"acl": "LAN_1", "src_ip": ["any", "10.1.1.1"], "dst_ip": ["any"]}]
    out = process_items(items, {"zoneRules": rules})
    assert "192.168.0.0/16" in out[0]["src_ip"][0]
    assert out[0]["src_ip"][1] == "10.1.1.1"
    assert out[0]["dst_ip"][0] == "0.0.0.0/0"
