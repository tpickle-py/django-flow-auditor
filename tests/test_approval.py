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


def test_approval_helpers_and_edge_cases():
    from flow_auditor.services.approval import (
        match_ip_list,
        match_single_ip,
        match_single_service,
        split_field_values,
    )

    # split_field_values
    assert split_field_values(None) == []
    assert split_field_values("") == []
    assert split_field_values(["10.0.0.1, 10.0.0.2", "10.0.0.3;10.0.0.4"]) == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "10.0.0.4",
    ]

    # match_single_ip
    assert match_single_ip("any", "any") is True
    assert match_single_ip("any", "10.0.0.0/24") is False
    assert match_single_ip("my-host.domain", "my-host.domain") is True
    assert match_single_ip("10.0.0.5/32", "10.0.0.0/24") is True

    # match_ip_list
    assert match_ip_list([], ["10.0.0.0/24"]) is False
    assert match_ip_list(["10.0.0.1"], []) is False

    # match_single_service with tcp-udp and ranges
    cand_tcp = {"proto": "tcp", "port": 8080}
    appr_tcp_udp = {"proto": "tcp-udp", "port": 8080}
    assert match_single_service(cand_tcp, appr_tcp_udp) is True

    appr_range = {"proto": "tcp", "start_port": 8000, "end_port": 9000}
    assert match_single_service(cand_tcp, appr_range) is True
    assert match_single_service({"proto": "tcp", "port": 7000}, appr_range) is False


def test_approval_custom_field_mappings():
    approved = [{"src_net": "10.1.0.0/16", "dst_net": "10.2.0.0/16", "port_spec": "tcp/80"}]
    flows = [{"src": "10.1.5.5", "dst": "10.2.10.10", "proto_port": "http"}]
    params = {
        "srcField": "src_net",
        "dstField": "dst_net",
        "svcField": "port_spec",
        "flowSrcField": "src",
        "flowDstField": "dst",
        "flowSvcField": "proto_port",
    }
    res = check_flow_approvals(approved, flows, params)
    assert len(res) == 1
    assert res[0]["results"]["match_status"] == "approved"
