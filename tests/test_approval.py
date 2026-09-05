"""Tests for FlowApprovalChecker ported from n8n-nodes-flow-approval-checker test suite."""

from flow_auditor.services.approval import check_flow_approvals


def test_approval_checker_full_match():
    approved = [
        {
            "src_ip": "10.0.0.0/24",
            "dst_ip": "192.168.1.0/24",
            "service": "tcp/443",
            "ticket": "CHG001",
        }
    ]
    flows_to_check = [{"source": "10.0.0.50", "dest": "192.168.1.100", "service": "https"}]
    results = check_flow_approvals(approved, flows_to_check)
    assert len(results) == 1
    res = results[0]["results"]
    assert res["match_status"] == "approved"
    assert results[0].get("ticket") == "CHG001"


def test_approval_checker_partial_match():
    approved = [{"src_ip": "10.0.0.0/24", "dst_ip": "192.168.1.0/24", "service": "tcp/443"}]
    # Wrong service (ssh instead of https)
    flows_to_check = [{"source": "10.0.0.50", "dest": "192.168.1.100", "service": "ssh"}]
    results = check_flow_approvals(approved, flows_to_check)
    assert len(results) == 1
    res = results[0]["results"]
    assert res["match_status"] == "partial"
    assert "service did not match" in res["match_detail"]["note"]


def test_approval_checker_not_approved():
    approved = [{"src_ip": "10.0.0.0/24", "dst_ip": "192.168.1.0/24", "service": "tcp/443"}]
    flows_to_check = [{"source": "172.16.0.1", "dest": "8.8.8.8", "service": "dns"}]
    results = check_flow_approvals(approved, flows_to_check)
    assert len(results) == 1
    res = results[0]["results"]
    assert res["match_status"] == "not_approved"
