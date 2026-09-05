"""Targeted tests to push coverage beyond 95%."""

import pytest

from flow_auditor.models import Job, JobStatus
from flow_auditor.services.approval import (
    check_flow_approvals,
    match_single_ip,
    match_single_service,
)
from flow_auditor.services.cisco_asa import (
    parse_asa_config,
    parse_port_spec,
    parse_service_subcommand,
)
from flow_auditor.services.juniper_srx import parse_config
from flow_auditor.tasks import deliver_webhook_task, execute_job_task


def test_cisco_asa_subcommand_and_port_specs():
    # ICMP type numeric and string
    assert parse_service_subcommand(["icmp", "echo"]) == ["icmp/8"]
    assert parse_service_subcommand(["icmp", "3"]) == ["icmp/3"]
    assert parse_service_subcommand(["icmp"]) == ["icmp/any"]

    # Protocol numbers and names
    assert parse_service_subcommand(["ospf"]) == ["ip/89"]
    assert parse_service_subcommand(["88"]) == ["ip/88"]
    assert parse_service_subcommand(["customproto"]) == ["customproto/any"]

    # Direct port operations in parse_service_subcommand
    assert "tcp/80" in parse_service_subcommand(["tcp", "eq", "80"])
    assert "tcp/1000-2000" in parse_service_subcommand(["tcp", "range", "1000", "2000"])

    # parse_port_spec
    ports_range, i = parse_port_spec(["range", "80", "88"], 0, "tcp")
    assert ports_range == ["tcp/80-88"]
    assert i == 3

    ports_gt, i2 = parse_port_spec(["gt", "1024"], 0, "udp")
    assert ports_gt == ["udp/gt 1024"]
    assert i2 == 2

    ports_neq, i3 = parse_port_spec(["neq", "22"], 0, "tcp")
    assert ports_neq == ["tcp/neq 22"]
    assert i3 == 2


def test_juniper_nested_sets_and_empty_endpoints():
    cfg = """
set security address-book global address H1 10.1.1.1/32
set security address-book global address H2 10.1.1.2/32
set security address-book global address-set INNER address H1
set security address-book global address-set OUTER address-set INNER
set security address-book global address-set OUTER address H2

set applications application APP1 protocol udp
set applications application APP1 destination-port 5353
set applications application-set SET_INNER application APP1
set applications application-set SET_OUTER application-set SET_INNER

set security policies from-zone TRUST to-zone UNTRUST policy NESTED match source-address OUTER
set security policies from-zone TRUST to-zone UNTRUST policy NESTED match destination-address any
set security policies from-zone TRUST to-zone UNTRUST policy NESTED match application SET_OUTER
set security policies from-zone TRUST to-zone UNTRUST policy NESTED then permit

set security policies from-zone DMZ to-zone TRUST policy EMPTY then permit
"""
    flows = parse_config(cfg)
    assert len(flows) == 2

    nested_flow = flows[0]
    assert "10.1.1.1/32" in nested_flow["source"]
    assert "10.1.1.2/32" in nested_flow["source"]
    assert "udp/5353" in nested_flow["services"]

    empty_flow = flows[1]
    assert empty_flow["source"] == ["any"]
    assert empty_flow["dest"] == ["any"]
    assert empty_flow["services"] == ["any/any"]


def test_approval_spread_and_string_service_overrides():
    # String JSON serviceOverrides
    overrides_json = '{"web-custom": [{"proto": "tcp", "port": 8888}]}'
    approved = [{"src_ip": "10.0.0.0/24", "dst_ip": "10.1.0.0/24", "service": "web-custom"}]
    flows = [{"source": "10.0.0.1", "dest": "10.1.0.1", "service": "tcp/8888"}]
    res = check_flow_approvals(approved, flows, {"serviceOverrides": overrides_json})
    assert res[0]["results"]["match_status"] == "approved"

    # partialSpread = True
    appr_spread = [
        {"src_ip": "10.0.0.0/24", "dst_ip": "10.1.0.0/24", "service": "tcp/80"},
        {"src_ip": "10.0.0.0/24", "dst_ip": "10.2.0.0/24", "service": "tcp/443"},
    ]
    # Wrong dest for first, wrong service for second -> partial matches
    flows_spread = [{"source": "10.0.0.5", "dest": "10.99.0.5", "service": "tcp/80"}]
    res_spread = check_flow_approvals(appr_spread, flows_spread, {"partialSpread": True})
    assert res_spread[0]["results"]["match_status"] == "partial"
    assert isinstance(res_spread[0]["results"]["match_detail"], dict)

    # String digit port matching
    assert (
        match_single_service(
            {"proto": "tcp", "port": "8080"},
            {"proto": "tcp", "start_port": 8000, "end_port": 9000},
        )
        is True
    )

    # Invalid CIDR fallback in match_single_ip
    assert match_single_ip("10.0.0.1", "invalid-cidr-mask") is False


@pytest.mark.django_db
def test_tasks_webhook_retry_and_cancellation_checkpoints(monkeypatch):
    # Test webhook delivery retry on failure
    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.COMPLETED,
        webhook_url="https://example.com/fail-hook",
        webhook_attempts=0,
        normalized_hash="wh-fail",
    )

    def mock_fail(*args, **kwargs):
        return False

    monkeypatch.setattr("flow_auditor.tasks.deliver_webhook", mock_fail)

    # Calling deliver_webhook_task directly when deliver_webhook fails triggers retry
    with pytest.raises(Exception, match="Webhook delivery failed"):
        deliver_webhook_task(str(job.id))

    # Test cancellation checkpoint in execute_job_task
    cancel_job = Job.objects.create(
        module_slug="cisco-asa-parser",
        request_json={"config": "access-list T extended permit ip any any"},
        status=JobStatus.QUEUED,
        normalized_hash="can-chk",
    )

    # Simulate cancellation during execution
    orig_execute = __import__("flow_auditor.tasks", fromlist=["execute_module"]).execute_module

    def mock_mid_cancel(*args, **kwargs):
        cancel_job.status = JobStatus.CANCEL_REQUESTED
        cancel_job.save(update_fields=["status"])
        return orig_execute(*args, **kwargs)

    monkeypatch.setattr("flow_auditor.tasks.execute_module", mock_mid_cancel)
    execute_job_task(str(cancel_job.id))
    cancel_job.refresh_from_db()
    assert cancel_job.status == JobStatus.CANCELLED


@pytest.mark.django_db
def test_serializers_webhook_and_status_url():

    from flow_auditor.serializers.jobs import JobDetailSerializer, JobSubmitSerializer

    # Valid webhook
    s_valid = JobSubmitSerializer(
        data={
            "module": "cisco-asa-parser",
            "config": "x",
            "webhook": {"url": "https://example.com"},
        }
    )
    assert s_valid.is_valid() is True

    # Invalid webhook missing url
    s_invalid = JobSubmitSerializer(
        data={"module": "cisco-asa-parser", "config": "x", "webhook": {"invalid": 1}}
    )
    assert s_invalid.is_valid() is False
    assert "webhook" in s_invalid.errors

    job = Job.objects.create(
        module_slug="cisco-asa-parser",
        status=JobStatus.COMPLETED,
        normalized_hash="ser-hash",
    )
    # Context without request exercises line 109
    data = JobDetailSerializer(job, context={}).data
    assert data["statusUrl"] == f"/api/flow-auditor/jobs/{job.id}/"


def test_cisco_asa_grouped_with_objects_and_proto():
    cfg = """
object service S_HTTP
 service tcp destination eq 80
 description HTTP Service
object-group network G1
 description Net group 1
 network-object object S_HTTP
 network-object 10.0.0.1
object-group service S_GRP
 description Srv group
 service-object object S_HTTP
 group-object S_GRP2
object-group protocol P_GRP
 protocol-object tcp
 group-object P_SUB

access-list G1 extended permit ip any6 any6
access-list G1 extended permit icmp any any echo
access-list G1 extended permit esp any any
"""
    res = parse_asa_config(cfg, {"groupByAcl": True, "includeObjects": True, "includeRaw": False})
    assert "flows" in res
    assert "objects" in res
    assert len(res["flows"]) == 1


def test_approval_proto_mismatch_and_empty_lists():
    from flow_auditor.services.approval import match_service_list

    # Proto mismatch
    assert match_single_service({"proto": "tcp", "port": 80}, {"proto": "icmp"}) is False
    # Any cand_port vs concrete appr_port
    assert (
        match_single_service({"proto": "tcp", "port": "any"}, {"proto": "tcp", "port": 80}) is False
    )
    # match_service_list empty lists
    assert match_service_list([], ["tcp/80"]) is False
    assert match_service_list(["tcp/80"], []) is False
    # check_flow_approvals empty lists
    assert check_flow_approvals([], []) == []
