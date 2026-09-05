"""Tests for Cisco ASA parser ported from n8n-nodes-cisco-asa-parser test suite."""

from flow_auditor.services.cisco_asa import parse_asa_config, parse_objects


def test_cisco_asa_object_network():
    cfg = """
object network WEB_SERVER
 host 10.0.0.5
object network DB_NET
 subnet 192.168.1.0 255.255.255.0
access-list OUTSIDE extended permit tcp object WEB_SERVER object DB_NET eq 3306
"""
    flows = parse_asa_config(cfg, {"includeRaw": False})
    assert len(flows) == 1
    assert flows[0]["acl"] == "OUTSIDE"
    assert flows[0]["action"] == "permit"
    assert flows[0]["source"] == ["10.0.0.5/32"]
    assert flows[0]["dest"] == ["192.168.1.0/24"]
    assert flows[0]["services"] == ["tcp/3306"]


def test_cisco_asa_object_group_service():
    cfg = """
object-group service WEB_SERVICES tcp
 port-object eq 80
 port-object eq 443
access-list OUTSIDE extended permit tcp any any object-group WEB_SERVICES
"""
    flows = parse_asa_config(cfg)
    assert len(flows) == 1
    assert flows[0]["source"] == ["any"]
    assert flows[0]["dest"] == ["any"]
    assert "tcp/80" in flows[0]["services"]
    assert "tcp/443" in flows[0]["services"]


def test_cisco_asa_remarks_and_group_by_acl():
    cfg = """
access-list INSIDE remark Allow DNS out
access-list INSIDE extended permit udp any host 8.8.8.8 eq 53
access-list INSIDE extended permit tcp any host 8.8.8.8 eq 53
"""
    grouped = parse_asa_config(cfg, {"groupByAcl": True})
    assert len(grouped) == 1
    acl_entry = grouped[0]
    assert acl_entry["acl"] == "INSIDE"
    assert "8.8.8.8/32" in acl_entry["dest"]
    assert len(acl_entry["rules"]) == 2


def test_cisco_asa_command_mode():
    cfg = """
access-list OUTSIDE line 1 extended permit tcp any host 10.1.1.1 eq 443 (hitcnt=42) 0x1234abcd
"""
    flows = parse_asa_config(cfg, {"mode": "command"})
    assert len(flows) == 1
    assert flows[0]["lineNumber"] == 1
    assert flows[0]["hitcnt"] == 42
    assert flows[0]["hash"] == "0x1234abcd"


def test_cisco_asa_parse_objects():
    cfg = """
name 10.1.1.1 MY_HOST
object network NET1
 host 172.16.0.1
"""
    objs = parse_objects(cfg)
    assert objs["nameMap"]["MY_HOST"] == "10.1.1.1"
    assert "NET1" in objs["networkObjects"]
