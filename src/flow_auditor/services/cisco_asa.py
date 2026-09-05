"""Cisco ASA ACL to structured flow parser with object resolution.

Ported from n8n-nodes-cisco-asa-parser (asaParser.js).
Two-pass: Pass 1 collects all objects and name mappings, Pass 2 parses ACEs with resolution.
"""

from __future__ import annotations

import re
from typing import Any

from flow_auditor.common.ip_utils import is_ip, mask_to_cidr
from flow_auditor.common.services_map import (
    ICMP_TYPES,
    PROTO_NUMS,
    resolve_port,
)

TRAILING_IGNORE = {
    "log",
    "log-input",
    "inactive",
    "established",
    "fragments",
    "time-range",
    "dscp",
    "precedence",
}


def _unique(items: list[Any]) -> list[Any]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def parse_service_subcommand(toks: list[str]) -> list[str]:
    """Parse a service sub-command token list (e.g. ['tcp', 'destination', 'eq', '80'])."""
    raw_proto = (toks[0] if toks else "ip").lower()
    protos = ["tcp", "udp"] if raw_proto == "tcp-udp" else [raw_proto]
    results: list[str] = []

    if raw_proto in ("icmp", "icmp6"):
        type_token = (toks[1] if len(toks) > 1 else "").lower()
        if type_token and type_token not in ("destination", "source"):
            t: int | str = (
                ICMP_TYPES[type_token]
                if type_token in ICMP_TYPES
                else (int(type_token) if type_token.isdigit() else type_token)
            )
            results.append(f"icmp/{t}")
        else:
            results.append("icmp/any")
        return results

    if raw_proto not in ("tcp", "udp", "tcp-udp"):
        pn = PROTO_NUMS.get(raw_proto)
        if pn is None and raw_proto.isdigit():
            pn = int(raw_proto)
        results.append(f"ip/{pn}" if pn is not None else f"{raw_proto}/any")
        return results

    dst_port = "any"
    j = 1
    while j < len(toks):
        kw = toks[j]
        if kw in ("destination", "source"):
            target = kw
            j += 1
            op = toks[j] if j < len(toks) else ""
            if op == "eq":
                j += 1
                val = resolve_port(toks[j] if j < len(toks) else "")
                if target == "destination":
                    dst_port = val or "any"
            elif op == "range":
                j += 1
                lo = resolve_port(toks[j] if j < len(toks) else "")
                j += 1
                hi = resolve_port(toks[j] if j < len(toks) else "")
                if target == "destination":
                    dst_port = f"{lo}-{hi}"
            elif op == "neq":
                j += 1
                val = resolve_port(toks[j] if j < len(toks) else "")
                if target == "destination":
                    dst_port = f"!={val}"
            elif op in ("gt", "lt"):
                j += 1
                val = resolve_port(toks[j] if j < len(toks) else "")
                if target == "destination":
                    dst_port = f"{op} {val}"
        elif kw == "eq":
            j += 1
            dst_port = resolve_port(toks[j] if j < len(toks) else "") or "any"
        elif kw == "range":
            j += 1
            lo = resolve_port(toks[j] if j < len(toks) else "")
            j += 1
            hi = resolve_port(toks[j] if j < len(toks) else "")
            dst_port = f"{lo}-{hi}"
        j += 1

    for p in protos:
        results.append(f"{p}/{dst_port}")
    return results


def collect_objects(lines: list[str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    """Pass 1: Collect networkObjects, serviceObjects, and nameMap."""
    network_objects: dict[str, Any] = {}
    service_objects: dict[str, Any] = {}
    name_map: dict[str, str] = {}

    current_obj: dict[str, Any] | None = None
    current_type: str | None = None

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue

        toks = re.split(r"\s+", line)

        if toks[0] == "name" and len(toks) >= 3 and is_ip(toks[1]):
            name_map[toks[2]] = toks[1]
            continue

        if toks[0] == "object" and len(toks) >= 3:
            current_type = toks[1]
            name = toks[2]
            if current_type == "network":
                current_obj = {
                    "name": name,
                    "type": "network",
                    "subType": None,
                    "values": [],
                    "description": "",
                }
                network_objects[name] = current_obj
            elif current_type == "service":
                current_obj = {"name": name, "type": "service", "services": [], "description": ""}
                service_objects[name] = current_obj
            else:
                current_obj = None
            continue

        if toks[0] == "object-group" and len(toks) >= 3:
            current_type = f"group-{toks[1]}"
            name = toks[2]
            if toks[1] == "network":
                current_obj = {
                    "name": name,
                    "type": "group-network",
                    "values": [],
                    "groupRefs": [],
                    "description": "",
                }
                network_objects[name] = current_obj
            elif toks[1] == "service":
                proto_hint = toks[3].lower() if len(toks) >= 4 else "mixed"
                current_obj = {
                    "name": name,
                    "type": "group-service",
                    "protoHint": proto_hint,
                    "services": [],
                    "groupRefs": [],
                    "description": "",
                }
                service_objects[name] = current_obj
            elif toks[1] in ("protocol", "icmp-type"):
                current_obj = {
                    "name": name,
                    "type": f"group-{toks[1]}",
                    "services": [],
                    "groupRefs": [],
                    "description": "",
                }
                service_objects[name] = current_obj
            else:
                current_obj = None
            continue

        if current_obj and (raw.startswith(" ") or raw.startswith("\t")):
            c_type = current_obj.get("type")
            if c_type == "network":
                if toks[0] == "host" and len(toks) >= 2:
                    current_obj["subType"] = "host"
                    current_obj["values"].append(toks[1])
                elif toks[0] == "subnet" and len(toks) >= 3:
                    current_obj["subType"] = "subnet"
                    cidr = mask_to_cidr(toks[2])
                    current_obj["values"].append(
                        f"{toks[1]}/{cidr}" if cidr is not None else toks[1]
                    )
                elif toks[0] == "range" and len(toks) >= 3:
                    current_obj["subType"] = "range"
                    current_obj["values"].append(f"{toks[1]}-{toks[2]}")
                elif toks[0] == "fqdn":
                    fqdn = toks[2] if toks[1] == "v4" and len(toks) >= 3 else toks[1]
                    current_obj["subType"] = "fqdn"
                    current_obj["values"].append(fqdn)
                elif toks[0] == "description":
                    current_obj["description"] = " ".join(toks[1:])

            elif c_type == "service":
                if toks[0] == "service" and len(toks) >= 2:
                    parsed = parse_service_subcommand(toks[1:])
                    current_obj["services"].extend(parsed)
                elif toks[0] == "description":
                    current_obj["description"] = " ".join(toks[1:])

            elif c_type == "group-network":
                if toks[0] == "network-object":
                    if toks[1] == "host" and len(toks) >= 3:
                        current_obj["values"].append(toks[2])
                    elif toks[1] == "object" and len(toks) >= 3:
                        current_obj["groupRefs"].append(toks[2])
                    elif len(toks) >= 3 and is_ip(toks[1]) and is_ip(toks[2]):
                        cidr = mask_to_cidr(toks[2])
                        current_obj["values"].append(
                            f"{toks[1]}/{cidr}" if cidr is not None else toks[1]
                        )
                    elif len(toks) >= 2:
                        current_obj["values"].append(toks[1])
                elif toks[0] == "group-object" and len(toks) >= 2:
                    current_obj["groupRefs"].append(toks[1])
                elif toks[0] == "description":
                    current_obj["description"] = " ".join(toks[1:])

            elif c_type == "group-service":
                if toks[0] == "port-object":
                    op = toks[1]
                    proto = current_obj.get("protoHint")
                    protos = ["tcp", "udp"] if proto in ("tcp-udp", "mixed") else [proto]
                    if op == "eq" and len(toks) >= 3:
                        p = resolve_port(toks[2])
                        for pr in protos:
                            current_obj["services"].append(f"{pr}/{p}")
                    elif op == "range" and len(toks) >= 4:
                        lo = resolve_port(toks[2])
                        hi = resolve_port(toks[3])
                        for pr in protos:
                            current_obj["services"].append(f"{pr}/{lo}-{hi}")
                    elif op in ("gt", "lt", "neq") and len(toks) >= 3:
                        p = resolve_port(toks[2])
                        for pr in protos:
                            current_obj["services"].append(f"{pr}/{op} {p}")
                elif toks[0] == "service-object":
                    if toks[1] == "object" and len(toks) >= 3:
                        current_obj["groupRefs"].append(toks[2])
                    else:
                        parsed = parse_service_subcommand(toks[1:])
                        current_obj["services"].extend(parsed)
                elif toks[0] == "group-object" and len(toks) >= 2:
                    current_obj["groupRefs"].append(toks[1])
                elif toks[0] == "description":
                    current_obj["description"] = " ".join(toks[1:])

            elif c_type == "group-protocol":
                if toks[0] == "protocol-object" and len(toks) >= 2:
                    p = toks[1].lower()
                    pn = PROTO_NUMS.get(p)
                    current_obj["services"].append(f"ip/{pn}" if pn is not None else f"{p}/any")
                elif toks[0] == "group-object" and len(toks) >= 2:
                    current_obj["groupRefs"].append(toks[1])

            elif c_type == "group-icmp-type":
                if toks[0] == "icmp-object" and len(toks) >= 2:
                    t = toks[1].lower()
                    tn = ICMP_TYPES.get(t, t)
                    current_obj["services"].append(f"icmp/{tn}")
            continue

        if not raw.startswith(" ") and not raw.startswith("\t"):
            current_obj = None

    return network_objects, service_objects, name_map


def resolve_network_token(
    tok: str,
    network_objects: dict[str, Any],
    name_map: dict[str, str],
    visited: set[str] | None = None,
) -> list[str]:
    """Recursively resolve a network token against network_objects and name_map."""
    if visited is None:
        visited = set()

    if tok in visited:
        return []
    visited.add(tok)

    if tok.lower() == "any" or tok == "any4":
        return ["any"]
    if tok == "any6":
        return ["any6"]
    if is_ip(tok):
        return [f"{tok}/32"]
    if "/" in tok and is_ip(tok.split("/")[0]):
        return [tok]

    if tok in name_map:
        return [f"{name_map[tok]}/32"]

    obj = network_objects.get(tok)
    if not obj:
        return [f"unresolved:{tok}"]

    results: list[str] = []
    o_type = obj.get("type")
    if o_type == "network":
        sub_type = obj.get("subType")
        for v in obj.get("values", []):
            if sub_type == "host":
                results.append(f"{v}/32" if is_ip(v) else v)
            elif sub_type in ("subnet", "range", "fqdn"):
                results.append(v)
            else:
                results.append(v)
    elif o_type == "group-network":
        for v in obj.get("values", []):
            if is_ip(v):
                results.append(f"{v}/32")
            else:
                results.extend(resolve_network_token(v, network_objects, name_map, visited))
        for ref in obj.get("groupRefs", []):
            results.extend(resolve_network_token(ref, network_objects, name_map, visited))

    return _unique(results)


def resolve_service_token(
    tok: str,
    service_objects: dict[str, Any],
    proto_hint: str = "tcp",
    visited: set[str] | None = None,
) -> list[str]:
    """Recursively resolve a service token against service_objects."""
    if visited is None:
        visited = set()

    if tok in visited:
        return []
    visited.add(tok)

    obj = service_objects.get(tok)
    if not obj:
        port = resolve_port(tok)
        if port is not None:
            return [f"{proto_hint}/{port}"]
        return [f"unresolved:{tok}"]

    results: list[str] = []
    for s in obj.get("services", []):
        results.append(s)
    for ref in obj.get("groupRefs", []):
        results.extend(resolve_service_token(ref, service_objects, proto_hint, visited))

    return _unique(results)


def parse_endpoint(
    toks: list[str],
    i: int,
    network_objects: dict[str, Any],
    name_map: dict[str, str],
) -> tuple[list[str], int]:
    """Parse a source or destination endpoint starting at tokens[i]."""
    if i >= len(toks):
        return ["any"], i

    kw = toks[i]
    if kw in ("any", "any4"):
        return ["any"], i + 1
    if kw == "any6":
        return ["any6"], i + 1

    if kw == "host":
        val = toks[i + 1] if i + 1 < len(toks) else ""
        addrs = (
            [f"{val}/32"] if is_ip(val) else resolve_network_token(val, network_objects, name_map)
        )
        return addrs, i + 2

    if kw in ("object", "object-group"):
        val = toks[i + 1] if i + 1 < len(toks) else ""
        addrs = resolve_network_token(val, network_objects, name_map)
        return addrs, i + 2

    if is_ip(kw):
        next_tok = toks[i + 1] if i + 1 < len(toks) else ""
        if is_ip(next_tok):
            cidr = mask_to_cidr(next_tok)
            return [f"{kw}/{cidr}" if cidr is not None else kw], i + 2
        return [f"{kw}/32"], i + 1

    # Named reference
    addrs = resolve_network_token(kw, network_objects, name_map)
    return addrs, i + 1


def parse_port_spec(toks: list[str], i: int, proto: str) -> tuple[list[str], int]:
    """Parse port spec (operator and port value(s)) at tokens[i]."""
    if i >= len(toks):
        return [], i
    op = toks[i]
    if op == "eq" and i + 1 < len(toks):
        p = resolve_port(toks[i + 1])
        return [f"{proto}/{p}"], i + 2
    if op == "range" and i + 2 < len(toks):
        lo = resolve_port(toks[i + 1])
        hi = resolve_port(toks[i + 2])
        return [f"{proto}/{lo}-{hi}"], i + 3
    if op in ("gt", "lt", "neq") and i + 1 < len(toks):
        p = resolve_port(toks[i + 1])
        return [f"{proto}/{op} {p}"], i + 2
    return [], i


def parse_command_line_metadata(raw_line: str) -> dict[str, Any]:
    """Extract line number, hitcnt, and hash from 'access-list ... <line 123> (hitcnt=10) 0x1234abcd'."""
    line = raw_line.strip()
    result: dict[str, Any] = {"normalizedLine": line}

    # line number
    m_line = re.search(r"\bline\s+(\d+)\b", line, re.IGNORECASE)
    if m_line:
        result["lineNumber"] = int(m_line.group(1))

    # hitcnt
    m_hit = re.search(r"\(hitcnt=(\d+)\)", line, re.IGNORECASE)
    if m_hit:
        result["hitcnt"] = int(m_hit.group(1))

    # hash
    m_hash = re.search(r"\b(0x[0-9a-fA-F]+)\b", line)
    if m_hash:
        result["hash"] = m_hash.group(1)

    # Normalize line
    cleaned = re.sub(r"\bline\s+\d+\b", "", line, flags=re.IGNORECASE)
    cleaned = re.sub(r"\(hitcnt=\d+\)", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b0x[0-9a-fA-F]+\b", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    result["normalizedLine"] = cleaned
    return result


def parse_ace(
    raw_line: str,
    network_objects: dict[str, Any],
    service_objects: dict[str, Any],
    name_map: dict[str, str],
) -> dict[str, Any] | None:
    """Pass 2: Parse a single access-list line."""
    line = raw_line.strip()
    if not line or line.startswith("!") or line.startswith("#"):
        return None

    toks = re.split(r"\s+", line)
    if toks[0] != "access-list":
        return None

    acl = toks[1]
    i = 2
    if i < len(toks) and toks[i] == "extended":
        i += 1
    if i < len(toks) and toks[i] == "standard":
        i += 1

    if i >= len(toks):
        return None
    action = toks[i].lower()
    if action not in ("permit", "deny"):
        return None
    i += 1

    if i >= len(toks):
        return None
    raw_proto = toks[i].lower()
    i += 1

    proto_is_service_group = False
    proto_group_services: list[str] = []

    if raw_proto in ("object-group", "service-object"):
        proto_is_service_group = True
        grp_name = toks[i] if i < len(toks) else ""
        i += 1
        proto_group_services = resolve_service_token(grp_name, service_objects)
        proto = "mixed"
    elif raw_proto == "object":
        proto_is_service_group = True
        obj_name = toks[i] if i < len(toks) else ""
        i += 1
        proto_group_services = resolve_service_token(obj_name, service_objects)
        proto = "mixed"
    else:
        proto = raw_proto

    src_addrs, i = parse_endpoint(toks, i, network_objects, name_map)

    # Optional source port
    if i < len(toks) and toks[i] in ("eq", "range", "gt", "lt", "neq"):
        _, i = parse_port_spec(toks, i, proto)
    elif i < len(toks) and toks[i] == "object-group":
        i += 2

    dst_addrs, i = parse_endpoint(toks, i, network_objects, name_map)

    services: list[str] = []
    if proto_is_service_group:
        services = list(proto_group_services)
    elif proto in ("tcp", "udp"):
        if i < len(toks):
            kw = toks[i]
            if kw == "object-group" and i + 1 < len(toks):
                grp_name = toks[i + 1]
                i += 2
                services = resolve_service_token(grp_name, service_objects, proto)
            elif kw in ("eq", "range", "gt", "lt", "neq"):
                ports, i = parse_port_spec(toks, i, proto)
                services = ports
            else:
                port = resolve_port(kw)
                if port is not None and kw not in TRAILING_IGNORE:
                    services = [f"{proto}/{port}"]
                    i += 1
                else:
                    services = [f"{proto}/any"]
        else:
            services = [f"{proto}/any"]
    elif proto in ("icmp", "icmp6"):
        if i < len(toks):
            kw = toks[i].lower()
            if kw not in TRAILING_IGNORE:
                t = ICMP_TYPES.get(kw, kw)
                services = [f"icmp/{t}"]
                i += 1
            else:
                services = ["icmp/any"]
        else:
            services = ["icmp/any"]
    elif proto in ("ip", "ip4", "ipv4"):
        services = ["ip/any"]
    else:
        pn = PROTO_NUMS.get(proto)
        services = [f"ip/{pn}" if pn is not None else f"{proto}/any"]

    return {
        "acl": acl,
        "action": action,
        "source": _unique(src_addrs),
        "dest": _unique(dst_addrs),
        "services": _unique(services),
        "line": line,
    }


def collapse_command_flows(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse indented expanded command flows into their parent flow."""
    result: list[dict[str, Any]] = []
    for f in flows:
        if not f.get("__commandIndented"):
            cleaned = dict(f)
            cleaned.pop("__commandIndented", None)
            result.append(cleaned)
        else:
            if result:
                parent = result[-1]
                for s in f.get("source", []):
                    if s not in parent["source"]:
                        parent["source"].append(s)
                for d in f.get("dest", []):
                    if d not in parent["dest"]:
                        parent["dest"].append(d)
                for sv in f.get("services", []):
                    if sv not in parent["services"]:
                        parent["services"].append(sv)
            else:
                cleaned = dict(f)
                cleaned.pop("__commandIndented", None)
                result.append(cleaned)
    return result


def parse_asa_config(
    config: str,
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Parse Cisco ASA configuration string into structured flow records."""
    opts = options or {}
    group_by_acl = bool(opts.get("groupByAcl", False))
    include_objects = bool(opts.get("includeObjects", False))
    include_raw = opts.get("includeRaw", True)
    if isinstance(include_raw, str):
        include_raw = include_raw.lower() not in ("false", "0", "no")
    mode = opts.get("mode", "config")

    raw_lines = config.splitlines()
    network_objects, service_objects, name_map = collect_objects(raw_lines)

    flows: list[dict[str, Any]] = []
    last_remark = ""

    for raw in raw_lines:
        trimmed = raw.strip()
        if not trimmed:
            continue

        command_meta: dict[str, Any] | None = None
        command_indented = False
        ace_line = trimmed

        if mode == "command":
            if not re.match(r"^access-list\s+", trimmed, re.IGNORECASE):
                continue
            command_indented = bool(re.match(r"^\s+access-list\s+", raw, re.IGNORECASE))
            command_meta = parse_command_line_metadata(trimmed)
            ace_line = command_meta["normalizedLine"]

        if re.match(r"^access-list\s+\S+\s+remark\s+", ace_line, re.IGNORECASE):
            last_remark = re.sub(
                r"^access-list\s+\S+\s+remark\s+", "", ace_line, flags=re.IGNORECASE
            ).strip()
            continue

        flow = parse_ace(ace_line, network_objects, service_objects, name_map)
        if not flow:
            continue

        if mode == "command" and command_meta:
            if "lineNumber" in command_meta:
                flow["lineNumber"] = command_meta["lineNumber"]
            if "hitcnt" in command_meta:
                flow["hitcnt"] = command_meta["hitcnt"]
            if "hash" in command_meta:
                flow["hash"] = command_meta["hash"]
            flow["__commandIndented"] = command_indented

        if last_remark:
            flow["remark"] = last_remark
            last_remark = ""
        else:
            last_remark = ""

        if not include_raw:
            flow.pop("line", None)

        flows.append(flow)

    normalized_flows = collapse_command_flows(flows) if mode == "command" else flows

    object_summary = (
        {
            "networkObjects": network_objects,
            "serviceObjects": service_objects,
            "nameMap": name_map,
        }
        if include_objects
        else None
    )

    if not group_by_acl:
        if include_objects:
            return {"flows": normalized_flows, "objects": object_summary}
        return normalized_flows

    by_acl: dict[str, dict[str, Any]] = {}
    for f in normalized_flows:
        acl = f["acl"]
        if acl not in by_acl:
            by_acl[acl] = {"acl": acl, "source": [], "dest": [], "services": [], "rules": []}
        entry = by_acl[acl]
        for s in f.get("source", []):
            if s not in entry["source"]:
                entry["source"].append(s)
        for d in f.get("dest", []):
            if d not in entry["dest"]:
                entry["dest"].append(d)
        for sv in f.get("services", []):
            if sv not in entry["services"]:
                entry["services"].append(sv)

        rule: dict[str, Any] = {
            "action": f["action"],
            "source": f.get("source", []),
            "dest": f.get("dest", []),
            "services": f.get("services", []),
        }
        if mode == "command":
            for k in ("lineNumber", "hitcnt", "hash", "line"):
                if k in f:
                    rule[k] = f[k]
        entry["rules"].append(rule)

    grouped = list(by_acl.values())
    if include_objects:
        return {"flows": grouped, "objects": object_summary}
    return grouped


def parse_objects(config: str) -> dict[str, Any]:
    """Extract object definitions and name mappings without parsing ACEs."""
    network_objects, service_objects, name_map = collect_objects(config.splitlines())
    return {
        "networkObjects": network_objects,
        "serviceObjects": service_objects,
        "nameMap": name_map,
    }
