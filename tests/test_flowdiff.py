"""Tests for FlowDiff engine ported from n8n-nodes-flowdiff test suite."""

from flow_auditor.services.flowdiff import diff_flows, expand_tuples, normalise_key


def test_expand_tuples_cartesian():
    flow = {
        "acl": "TEST",
        "action": "permit",
        "source": ["10.0.0.1/32", "10.0.0.2/32"],
        "dest": ["192.168.1.1/32"],
        "services": ["tcp/80", "tcp/443"],
        "line": "access-list TEST extended permit ...",
    }
    tuples = expand_tuples(flow)
    assert len(tuples) == 4  # 2 x 1 x 2
    assert all(t["acl"] == "TEST" for t in tuples)
    assert all(t["action"] == "permit" for t in tuples)


def test_normalise_key_asdm():
    assert (
        normalise_key("line 12 access-list FOO extended permit ip any any")
        == "access-list FOO extended permit ip any any"
    )


def test_diff_flows_granted_and_revoked():
    flows_a = [
        {
            "acl": "ACL1",
            "action": "permit",
            "source": ["10.0.0.1/32"],
            "dest": ["192.168.1.1/32"],
            "services": ["tcp/80"],
            "line": "line 1",
        }
    ]
    flows_b = [
        {
            "acl": "ACL1",
            "action": "permit",
            "source": ["10.0.0.1/32"],
            "dest": ["192.168.1.1/32"],
            "services": ["tcp/443"],
            "line": "line 2",
        }
    ]
    diff = diff_flows(flows_a, flows_b, {"detectRenames": False})
    summary = diff["summary"]
    assert summary["access_revoked"] == 1
    assert summary["access_granted"] == 1


def test_diff_flows_rename_detection():
    flows_a = [
        {
            "acl": "OLD_ACL",
            "action": "permit",
            "source": ["10.1.1.1/32"],
            "dest": ["10.2.2.2/32"],
            "services": ["tcp/22"],
            "line": "old line",
        }
    ]
    flows_b = [
        {
            "acl": "NEW_ACL",
            "action": "permit",
            "source": ["10.1.1.1/32"],
            "dest": ["10.2.2.2/32"],
            "services": ["tcp/22"],
            "line": "new line",
        }
    ]
    diff = diff_flows(flows_a, flows_b, {"detectRenames": True})
    assert len(diff["renames"]) == 1
    rename = diff["renames"][0]
    assert rename["old_acl"] == "OLD_ACL"
    assert rename["new_acl"] == "NEW_ACL"
    assert rename["change_type"] == "rename"


def test_group_by_acl():
    from flow_auditor.services.flowdiff import group_by_acl

    flows = [
        {
            "acl": "ACL1",
            "action": "permit",
            "source": ["10.0.0.1/32"],
            "dest": ["1.1.1.1/32"],
            "services": ["tcp/80"],
        },
        {
            "acl": "ACL1",
            "action": "permit",
            "source": ["10.0.0.2/32"],
            "dest": ["1.1.1.1/32"],
            "services": ["tcp/443"],
        },
    ]
    grouped = group_by_acl(flows)
    assert len(grouped) == 1
    assert len(grouped[0]["source"]) == 2
    assert len(grouped[0]["rules"]) == 2


def test_diff_flows_unchanged():
    flows = [
        {
            "acl": "ACL1",
            "action": "permit",
            "source": ["10.0.0.1/32"],
            "dest": ["1.1.1.1/32"],
            "services": ["tcp/80"],
            "line": "l1",
        }
    ]
    diff = diff_flows(flows, flows)
    assert diff["summary"]["total_changes"] == 0
    assert diff["summary"]["access_granted"] == 0
    assert diff["summary"]["access_revoked"] == 0


def test_diff_flows_collapse_and_ignore():
    flows_a = [
        {
            "acl": "ACL1",
            "action": "permit",
            "source": ["10.0.0.1/32"],
            "dest": ["1.1.1.1/32"],
            "services": ["tcp/80"],
        },
        {
            "acl": "IGNORE_ME",
            "action": "permit",
            "source": ["10.0.0.1/32"],
            "dest": ["1.1.1.1/32"],
            "services": ["tcp/80"],
        },
    ]
    flows_b = [
        {
            "acl": "ACL1",
            "action": "permit",
            "source": ["10.0.0.1/32"],
            "dest": ["1.1.1.1/32"],
            "services": ["tcp/443"],
        },
        {
            "acl": "IGNORE_ME",
            "action": "permit",
            "source": ["10.0.0.1/32"],
            "dest": ["1.1.1.1/32"],
            "services": ["tcp/8080"],
        },
    ]
    diff = diff_flows(
        flows_a,
        flows_b,
        {
            "collapse": True,
            "ignoreAcls": ["^IGNORE_"],
        },
    )
    # IGNORE_ME changes should be filtered out
    assert all("IGNORE_ME" not in c.get("acl", "") for c in diff["changes"])
    # Collapsed changes
    assert len(diff["changes"]) >= 2


def test_diff_flows_unresolved_modes():
    flows_a = [
        {
            "acl": "ACL1",
            "action": "permit",
            "source": ["unresolved:OBJ1"],
            "dest": ["1.1.1.1/32"],
            "services": ["tcp/80"],
        }
    ]
    flows_b = []

    # Segregate mode
    diff_seg = diff_flows(flows_a, flows_b, {"unresolvedMode": "segregate"})
    assert "unresolved" in diff_seg
    assert len(diff_seg["unresolved"]) == 1

    # Exclude mode
    diff_exc = diff_flows(flows_a, flows_b, {"unresolvedMode": "exclude"})
    assert len(diff_exc["changes"]) == 0
