"""Tests for Juniper SRX parser ported from n8n-nodes-juniper-srx-parser test suite."""

from flow_auditor.services.juniper_srx import parse_config, parse_objects


def test_juniper_set_global_address_book():
    cfg = """
set security address-book global address HOST-A 10.0.0.5/32
set security address-book global address NET-B 192.168.1.0/24
set security policies from-zone TRUST to-zone UNTRUST policy ALLOW-WEB match source-address HOST-A
set security policies from-zone TRUST to-zone UNTRUST policy ALLOW-WEB match destination-address NET-B
set security policies from-zone TRUST to-zone UNTRUST policy ALLOW-WEB match application junos-https
set security policies from-zone TRUST to-zone UNTRUST policy ALLOW-WEB then permit
"""
    flows = parse_config(cfg, {"includeRaw": False})
    assert len(flows) == 1
    assert flows[0]["acl"] == "TRUST::UNTRUST::ALLOW-WEB"
    assert flows[0]["source"] == ["10.0.0.5/32"]
    assert flows[0]["dest"] == ["192.168.1.0/24"]
    assert flows[0]["services"] == ["tcp/443"]


def test_juniper_hierarchical_stanza_format():
    cfg = """
security {
    policies {
        from-zone TRUST to-zone UNTRUST {
            policy PERMIT-HTTP {
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then {
                    permit;
                }
            }
        }
    }
}
"""
    flows = parse_config(cfg)
    assert len(flows) == 1
    assert flows[0]["acl"] == "TRUST::UNTRUST::PERMIT-HTTP"
    assert flows[0]["action"] == "permit"
    assert flows[0]["services"] == ["tcp/80"]


def test_juniper_group_by_acl():
    cfg = """
set security policies from-zone DMZ to-zone TRUST policy P1 match source-address any
set security policies from-zone DMZ to-zone TRUST policy P1 match destination-address 10.0.0.1/32
set security policies from-zone DMZ to-zone TRUST policy P1 match application junos-ssh
set security policies from-zone DMZ to-zone TRUST policy P1 then permit
"""
    grouped = parse_config(cfg, {"groupByAcl": True})
    assert len(grouped) == 1
    assert grouped[0]["acl"] == "DMZ::TRUST::P1"
    assert len(grouped[0]["rules"]) == 1


def test_juniper_parse_objects():
    cfg = """
set security address-book global address S1 1.1.1.1/32
"""
    objs = parse_objects(cfg)
    assert "S1" in objs["globalBook"]
