"""Tests for ZoneRuleAdvisor ported from n8n-nodes-zone-any-resolver test suite."""

from flow_auditor.services.zone_advisor import advise


def test_zone_rule_advisor_recommendation():
    rules = [
        {"acl": "DMZ", "src_ip": "10.0.1.0/24", "dst_ip": "192.168.1.10"},
        {"acl": "DMZ", "src_ip": "10.0.2.0/24", "dst_ip": "192.168.1.20"},
        {"acl": "DMZ", "src_ip": "any", "dst_ip": "192.168.1.30"},  # permissive
    ]
    advice = advise(rules, {"srcField": "src_ip", "dstField": "dst_ip", "zoneFields": ["acl"]})
    assert len(advice) == 1
    rec = advice[0]
    assert rec["field"] == "src"
    assert "recommendedCidrs" in rec
    assert rec["permissivenessScore"] >= 0.0


def test_zone_rule_advisor_no_explicit_siblings():
    rules = [{"acl": "ISOLATED", "src_ip": "any", "dst_ip": "any"}]
    advice = advise(rules)
    assert len(advice) == 2  # src and dst
    assert any(a.get("warning") == "no explicit siblings" for a in advice)
