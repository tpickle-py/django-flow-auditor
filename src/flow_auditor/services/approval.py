"""Flow Approval Checker service.

Ported from n8n-nodes-flow-approval-checker (FlowApprovalChecker.node.js).
Evaluates candidate network flows against approved flows (e.g. from ServiceNow or security records),
determining approved, partial, or not_approved status with detailed field-level match explanations.
"""

from __future__ import annotations

import json
import re
from typing import Any

from flow_auditor.common.ip_utils import ip_in_cidr, is_ip
from flow_auditor.common.services_map import parse_service


def split_field_values(val: Any, delimiters: str = ",;") -> list[str]:
    """Split a string or list field value by delimiters into trimmed strings."""
    if val is None:
        return []
    if isinstance(val, list):
        out = []
        for x in val:
            out.extend(split_field_values(x, delimiters))
        return out
    s = str(val).strip()
    if not s:
        return []
    delim_pattern = "[" + re.escape(delimiters) + "]"
    return [p.strip() for p in re.split(delim_pattern, s) if p.strip()]


def match_single_ip(candidate_ip: str, approved_network: str) -> bool:
    """Check if candidate_ip matches approved_network (supports CIDR or exact IP)."""
    c = candidate_ip.strip().lower()
    a = approved_network.strip().lower()
    if a == "any" or a == "0.0.0.0/0":
        return True
    if c == "any" or c == "0.0.0.0/0":
        return a in ("any", "0.0.0.0/0")

    # If candidate has CIDR prefix e.g. "10.0.0.1/32", strip /32 if it is a host
    cand_ip = c.split("/")[0] if "/" in c else c
    if not is_ip(cand_ip):
        return cand_ip == a

    try:
        return ip_in_cidr(cand_ip, a)
    except Exception:
        return cand_ip == a


def match_ip_list(candidate_ips: list[str], approved_networks: list[str]) -> bool:
    """Return True if all candidate IPs are covered by approved networks."""
    if not candidate_ips:
        return False
    if not approved_networks:
        return False
    for c in candidate_ips:
        if not any(match_single_ip(c, a) for a in approved_networks):
            return False
    return True


def match_single_service(
    cand_svc: dict[str, Any],
    appr_svc: dict[str, Any],
) -> bool:
    """Check if a candidate service spec matches an approved service spec."""
    cand_proto = str(cand_svc.get("proto", "any")).lower()
    appr_proto = str(appr_svc.get("proto", "any")).lower()

    if appr_proto != "any" and cand_proto != "any":
        if appr_proto == "tcp-udp":
            if cand_proto not in ("tcp", "udp"):
                return False
        elif cand_proto != appr_proto:
            return False

    appr_port = appr_svc.get("port")
    cand_port = cand_svc.get("port")

    if appr_port == "any" or appr_port is None:
        return True
    if cand_port == "any" or cand_port is None:
        return False

    # Check port range
    if "start_port" in appr_svc and "end_port" in appr_svc:
        start_p = appr_svc["start_port"]
        end_p = appr_svc["end_port"]
        if isinstance(cand_port, int):
            return start_p <= cand_port <= end_p
        if isinstance(cand_port, str) and cand_port.isdigit():
            return start_p <= int(cand_port) <= end_p
        return False

    return str(cand_port).lower() == str(appr_port).lower()


def match_service_list(
    candidate_services: list[str],
    approved_services: list[str],
    service_overrides: dict[str, Any] | None = None,
) -> bool:
    """Return True if all candidate services match approved service entries."""
    if not candidate_services:
        return False
    if not approved_services:
        return False

    parsed_cand: list[dict[str, Any]] = []
    for cs in candidate_services:
        parsed_cand.extend(parse_service(cs, service_overrides))

    parsed_appr: list[dict[str, Any]] = []
    for asvc in approved_services:
        parsed_appr.extend(parse_service(asvc, service_overrides))

    for c in parsed_cand:
        if not any(match_single_service(c, a) for a in parsed_appr):
            return False
    return True


def check_flow_approvals(
    approved_flows: list[dict[str, Any]],
    flows_to_check: list[dict[str, Any]],
    params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Check a list of candidate flows against approved flow records."""
    p = params or {}
    flow_src_field = p.get("flowSrcField", "source")
    flow_dst_field = p.get("flowDstField", "dest")
    flow_svc_field = p.get("flowSvcField", "service")

    src_field = p.get("srcField", "src_ip")
    dst_field = p.get("dstField", "dst_ip")
    svc_field = p.get("svcField", "service")

    delimiters = p.get("delimiters", ",;")
    matched_by_mode = p.get("matchedByMode", "all")  # "all" or "first"
    partial_spread = bool(p.get("partialSpread", False))
    raw_overrides = p.get("serviceOverrides", {})
    if isinstance(raw_overrides, str):
        try:
            service_overrides = json.loads(raw_overrides) if raw_overrides.strip() else {}
        except Exception:
            service_overrides = {}
    else:
        service_overrides = raw_overrides or {}

    # Compile approved flows
    compiled_approved: list[dict[str, Any]] = []
    for row in approved_flows:
        src_vals = split_field_values(row.get(src_field), delimiters)
        dst_vals = split_field_values(row.get(dst_field), delimiters)
        svc_vals = split_field_values(row.get(svc_field), delimiters)
        compiled_approved.append(
            {
                "src_vals": src_vals,
                "dst_vals": dst_vals,
                "svc_vals": svc_vals,
                "_rawRecord": row,
            }
        )

    results: list[dict[str, Any]] = []

    for flow in flows_to_check:
        cand_src = split_field_values(flow.get(flow_src_field), delimiters)
        cand_dst = split_field_values(flow.get(flow_dst_field), delimiters)
        cand_svc = split_field_values(flow.get(flow_svc_field), delimiters)

        full_matches: list[dict[str, Any]] = []
        partial_matches: list[dict[str, Any]] = []

        for appr in compiled_approved:
            src_m = match_ip_list(cand_src, appr["src_vals"])
            dst_m = match_ip_list(cand_dst, appr["dst_vals"])
            svc_m = match_service_list(cand_svc, appr["svc_vals"], service_overrides)
            match_count = sum([1 for m in (src_m, dst_m, svc_m) if m])

            match_info = {
                **appr,
                "srcMatch": src_m,
                "dstMatch": dst_m,
                "svcMatch": svc_m,
            }

            if match_count == 3:
                full_matches.append(match_info)
            elif match_count == 2:
                partial_matches.append(match_info)

        if full_matches:
            match_status = "approved"
            chosen_matches = full_matches[:1] if matched_by_mode == "first" else full_matches
            approved_row = full_matches[0]["_rawRecord"]
            match_detail = {"srcMatch": True, "dstMatch": True, "svcMatch": True}
        elif partial_matches:
            match_status = "partial"
            chosen_matches = partial_matches[:1] if matched_by_mode == "first" else partial_matches
            approved_row = partial_matches[0]["_rawRecord"] if partial_spread else None
            best = partial_matches[0]
            notes = []
            if not best["srcMatch"]:
                notes.append("source did not match")
            if not best["dstMatch"]:
                notes.append("destination did not match")
            if not best["svcMatch"]:
                notes.append("service did not match")
            match_detail = {
                "srcMatch": best["srcMatch"],
                "dstMatch": best["dstMatch"],
                "svcMatch": best["svcMatch"],
                "note": "; ".join(notes),
            }
        else:
            match_status = "not_approved"
            chosen_matches = []
            approved_row = None
            match_detail = {"srcMatch": False, "dstMatch": False, "svcMatch": False}

        matched_by = [m["_rawRecord"] for m in chosen_matches if "_rawRecord" in m]
        output_results = {
            "match_status": match_status,
            "match_detail": match_detail,
            "matched_by": matched_by,
        }

        merged_item = dict(flow)
        if approved_row:
            merged_item.update(approved_row)
        merged_item["results"] = output_results

        results.append(merged_item)

    return results
