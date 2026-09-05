"""Juniper SRX / JunOS Security Policy Parser.

Ported from n8n-nodes-juniper-srx-parser (srxParser.js).
Supports: set notation AND hierarchical stanza format (auto-detect).
Two-pass: Pass 1 -> address books + application objects, Pass 2 -> security policies.
"""

from __future__ import annotations

import re
from typing import Any

from flow_auditor.common.ip_utils import is_ip
from flow_auditor.common.services_map import JUNOS_APPS


def _unique(items: list[Any]) -> list[Any]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def detect_format(config: str) -> str:
    """Detect whether configuration is set commands or hierarchical stanza."""
    lines = [line.strip() for line in config.splitlines() if line.strip()]
    set_count = sum(1 for line in lines if line.startswith("set "))
    brace_count = sum(1 for line in lines if "{" in line or "}" in line)
    return "set" if set_count >= brace_count else "stanza"


def stanza_to_set_lines(config: str) -> list[str]:
    """Convert hierarchical JunOS stanza format to equivalent set command lines."""
    set_lines: list[str] = []
    path_stack: list[str] = []
    raw_lines = config.splitlines()

    for raw in raw_lines:
        line = raw.strip()
        if not line or line.startswith("/*") or line.startswith("#") or line.startswith("//"):
            continue

        # Strip inline comments
        line = re.sub(r"/\*.*?\*/", "", line).strip()
        line = re.sub(r"#.*$", "", line).strip()
        if not line:
            continue

        if line == "}":
            if path_stack:
                path_stack.pop()
            continue

        if line.endswith("{"):
            header = line[:-1].strip()
            path_stack.append(header)
            continue

        if line.endswith("};"):
            if path_stack:
                path_stack.pop()
            continue

        if line.endswith(";"):
            stmt = line[:-1].strip()
            # Handle closing braces attached at the end
            while stmt.endswith("}"):
                stmt = stmt[:-1].strip()
                if path_stack:
                    path_stack.pop()

            if stmt:
                prefix = "set " + " ".join(path_stack)
                if "[" in stmt and "]" in stmt:
                    m = re.match(r"^(.*?)\s*\[(.*?)\]$", stmt)
                    if m:
                        stem = m.group(1).strip()
                        items = re.split(r"\s+", m.group(2).strip())
                        for item in items:
                            if item:
                                set_lines.append(f"{prefix} {stem} {item}".strip())
                    else:
                        set_lines.append(f"{prefix} {stmt}".strip())
                else:
                    set_lines.append(f"{prefix} {stmt}".strip())
            continue

        # Line without semicolon or braces
        parts = re.split(r"\s+", line)
        prefix = "set " + " ".join(path_stack)
        set_lines.append(f"{prefix} {' '.join(parts)}".strip())

    return set_lines


def collect_objects(
    set_lines: list[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, list[str]], dict[str, list[str]]]:
    """Pass 1: Collect address books, application definitions, and sets."""
    global_book: dict[str, list[str]] = {}
    zone_books: dict[str, dict[str, list[str]]] = {}
    resolved_apps: dict[str, list[str]] = dict(JUNOS_APPS)
    app_sets: dict[str, list[str]] = {}
    app_defs: dict[str, dict[str, Any]] = {}

    for raw in set_lines:
        line = raw.strip()
        if not line.startswith("set "):
            continue
        toks = re.split(r"\s+", line)

        # Global address book: set security address-book global address <name> <ip/cidr>
        if (
            len(toks) >= 6
            and toks[1] == "security"
            and toks[2] == "address-book"
            and toks[3] == "global"
            and toks[4] == "address"
        ):
            name = toks[5]
            val = toks[6] if len(toks) >= 7 else ""
            if val:
                if is_ip(val):
                    val = f"{val}/32"
                global_book.setdefault(name, []).append(val)
            continue

        # Global address-set: set security address-book global address-set <name> address <member>
        if (
            len(toks) >= 8
            and toks[1] == "security"
            and toks[2] == "address-book"
            and toks[3] == "global"
            and toks[4] == "address-set"
            and toks[6] in ("address", "address-set")
        ):
            set_name = toks[5]
            member = toks[7]
            global_book.setdefault(f"set:{set_name}", []).append(member)
            continue

        # Zone-scoped address book
        if (
            len(toks) >= 6
            and toks[1] == "security"
            and toks[2] == "zones"
            and toks[3] == "security-zone"
        ):
            zone_name = toks[4].lower()
            if zone_name not in zone_books:
                zone_books[zone_name] = {}
            zb = zone_books[zone_name]

            # set security zones security-zone <zone> address-book address <name> <ip/cidr>
            if len(toks) >= 8 and toks[5] == "address-book" and toks[6] == "address":
                name = toks[7]
                val = toks[8] if len(toks) >= 9 else ""
                if val:
                    if is_ip(val):
                        val = f"{val}/32"
                    zb.setdefault(name, []).append(val)
                continue

            # set security zones security-zone <zone> address-book address-set <set> address <member>
            if (
                len(toks) >= 10
                and toks[5] == "address-book"
                and toks[6] == "address-set"
                and toks[8] in ("address", "address-set")
            ):
                set_name = toks[7]
                member = toks[9]
                zb.setdefault(f"set:{set_name}", []).append(member)
                continue

        # Applications: set applications application <name> ...
        if len(toks) >= 4 and toks[1] == "applications" and toks[2] == "application":
            app_name = toks[3]
            if app_name not in app_defs:
                app_defs[app_name] = {"proto": None, "ports": []}
            ad = app_defs[app_name]

            if len(toks) >= 6 and toks[4] == "protocol":
                ad["proto"] = toks[5].lower()
            elif len(toks) >= 6 and toks[4] in ("destination-port", "port"):
                ad["ports"].append(toks[5])
            continue

        # Application-set: set applications application-set <name> application <app>
        if (
            len(toks) >= 6
            and toks[1] == "applications"
            and toks[2] == "application-set"
            and toks[4] in ("application", "application-set")
        ):
            set_name = toks[3]
            member = toks[5]
            app_sets.setdefault(set_name, []).append(member)
            continue

    # Resolve custom application definitions into protocol/port
    for app_name, ad in app_defs.items():
        proto = ad["proto"] or "tcp"
        ports = ad["ports"]
        if ports:
            resolved_apps[app_name] = [f"{proto}/{p}" for p in ports]
        else:
            resolved_apps[app_name] = [f"{proto}/any"]

    return global_book, zone_books, resolved_apps, app_sets


def resolve_address(
    name: str,
    zone_book: dict[str, list[str]] | None,
    global_book: dict[str, list[str]],
    visited: set[str] | None = None,
) -> list[str]:
    """Resolve an address or address-set name using zone-scoped and global address books."""
    if visited is None:
        visited = set()

    if name in visited:
        return []
    visited.add(name)

    if name.lower() == "any":
        return ["any"]
    if is_ip(name):
        return [f"{name}/32"]
    if "/" in name and is_ip(name.split("/")[0]):
        return [name]

    # Look in zone book first, then global book
    book = (
        zone_book
        if (zone_book and (name in zone_book or f"set:{name}" in zone_book))
        else global_book
    )

    if f"set:{name}" in book:
        members = book[f"set:{name}"]
        out: list[str] = []
        for m in members:
            out.extend(resolve_address(m, zone_book, global_book, visited))
        return _unique(out)

    if name in book:
        vals = book[name]
        out: list[str] = []
        for v in vals:
            out.extend(resolve_address(v, zone_book, global_book, visited))
        return _unique(out)

    return [name]


def resolve_application(
    app_name: str,
    resolved_apps: dict[str, list[str]],
    app_sets: dict[str, list[str]],
    visited: set[str] | None = None,
) -> list[str]:
    """Resolve an application or application-set name to list of service strings."""
    if visited is None:
        visited = set()

    if app_name in visited:
        return []
    visited.add(app_name)

    if app_name.lower() == "any":
        return ["any/any"]

    if app_name in app_sets:
        out: list[str] = []
        for member in app_sets[app_name]:
            out.extend(resolve_application(member, resolved_apps, app_sets, visited))
        return _unique(out)

    if app_name in resolved_apps:
        return resolved_apps[app_name]

    # Check for junos- prefix alias
    junos_name = f"junos-{app_name}"
    if junos_name in resolved_apps:
        return resolved_apps[junos_name]

    return [app_name]


def parse_policies(
    set_lines: list[str],
    global_book: dict[str, list[str]],
    zone_books: dict[str, dict[str, list[str]]],
    resolved_apps: dict[str, list[str]],
    app_sets: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Pass 2: Parse security policies and build flow records."""
    policy_map: dict[str, dict[str, Any]] = {}
    policy_order: list[str] = []

    for raw in set_lines:
        line = raw.strip()
        if not line.startswith("set "):
            continue
        toks = re.split(r"\s+", line)

        # set security policies from-zone <from> to-zone <to> policy <name> ...
        if (
            len(toks) >= 8
            and toks[1] == "security"
            and toks[2] == "policies"
            and toks[3] == "from-zone"
            and toks[5] == "to-zone"
            and toks[7] == "policy"
        ):
            from_zone = toks[4]
            to_zone = toks[6]
            policy_name = toks[8]
            key = f"{from_zone}::{to_zone}::{policy_name}".lower()

            if key not in policy_map:
                policy_map[key] = {
                    "fromZone": from_zone,
                    "toZone": to_zone,
                    "policyName": policy_name,
                    "sources": [],
                    "dests": [],
                    "apps": [],
                    "action": None,
                    "description": None,
                }
                policy_order.append(key)

            pol = policy_map[key]
            rest = toks[9:]
            if not rest:
                continue

            if rest[0] == "match" and len(rest) >= 3:
                match_type = rest[1]
                match_val = rest[2]
                if match_type == "source-address":
                    pol["sources"].append(match_val)
                elif match_type == "destination-address":
                    pol["dests"].append(match_val)
                elif match_type in ("application", "dynamic-application"):
                    pol["apps"].append(match_val)
            elif rest[0] == "then" and len(rest) >= 2:
                act = rest[1].lower()
                if act in ("permit", "deny", "reject"):
                    pol["action"] = "permit" if act == "permit" else "deny"
            elif rest[0] == "description" and len(rest) >= 2:
                pol["description"] = " ".join(rest[1:])

    flows: list[dict[str, Any]] = []

    for lower_key in policy_order:
        pol = policy_map[lower_key]
        if not pol["action"]:
            continue

        from_zone = pol["fromZone"].lower()
        to_zone = pol["toZone"].lower()

        src_zone_book = zone_books.get(from_zone)
        dst_zone_book = zone_books.get(to_zone)

        # Resolve sources
        if not pol["sources"]:
            src_addrs = ["any"]
        else:
            resolved_src = []
            for name in pol["sources"]:
                resolved_src.extend(resolve_address(name, src_zone_book, global_book))
            src_addrs = _unique(resolved_src)

        # Resolve dests
        if not pol["dests"]:
            dst_addrs = ["any"]
        else:
            resolved_dst = []
            for name in pol["dests"]:
                resolved_dst.extend(resolve_address(name, dst_zone_book, global_book))
            dst_addrs = _unique(resolved_dst)

        # Resolve apps
        if not pol["apps"]:
            services = ["any/any"]
        else:
            resolved_svc = []
            for app in pol["apps"]:
                resolved_svc.extend(resolve_application(app, resolved_apps, app_sets))
            services = _unique(resolved_svc)

        acl = f"{pol['fromZone']}::{pol['toZone']}::{pol['policyName']}"
        flow: dict[str, Any] = {
            "acl": acl,
            "action": pol["action"],
            "source": src_addrs,
            "dest": dst_addrs,
            "services": services,
            "line": f"from-zone {pol['fromZone']} to-zone {pol['toZone']} policy {pol['policyName']}",
        }
        if pol.get("description"):
            flow["description"] = pol["description"]

        flows.append(flow)

    return flows


def parse_config(
    config: str,
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Parse Juniper SRX configuration string into structured flow records."""
    opts = options or {}
    group_by_acl = bool(opts.get("groupByAcl", False))
    include_raw = opts.get("includeRaw", True)
    if isinstance(include_raw, str):
        include_raw = include_raw.lower() not in ("false", "0", "no")

    fmt = detect_format(config)
    set_lines = (
        [line.strip() for line in config.splitlines() if line.strip().startswith("set ")]
        if fmt == "set"
        else stanza_to_set_lines(config)
    )

    global_book, zone_books, resolved_apps, app_sets = collect_objects(set_lines)
    flows = parse_policies(set_lines, global_book, zone_books, resolved_apps, app_sets)

    if not include_raw:
        for f in flows:
            f.pop("line", None)

    if not group_by_acl:
        return flows

    by_acl: dict[str, dict[str, Any]] = {}
    for f in flows:
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

        entry["rules"].append(
            {
                "action": f["action"],
                "source": f.get("source", []),
                "dest": f.get("dest", []),
                "services": f.get("services", []),
            }
        )

    return list(by_acl.values())


def parse_objects(config: str) -> dict[str, Any]:
    """Extract Juniper SRX objects (address books, application definitions) without policy flows."""
    fmt = detect_format(config)
    set_lines = (
        [line.strip() for line in config.splitlines() if line.strip().startswith("set ")]
        if fmt == "set"
        else stanza_to_set_lines(config)
    )
    global_book, zone_books, resolved_apps, app_sets = collect_objects(set_lines)
    return {
        "globalBook": global_book,
        "zoneBooks": zone_books,
        "resolvedApps": resolved_apps,
        "appSets": app_sets,
    }
