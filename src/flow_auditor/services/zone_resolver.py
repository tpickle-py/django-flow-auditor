"""Zone-aware any resolver service.

Ported from n8n-nodes-zone-any-resolver (ZoneAnyResolver.node.js).
Expands 'any' src/dst keywords in firewall rules based on zone rules and subnets.
"""

from __future__ import annotations

import re
from typing import Any


def _process_field(
    item: dict[str, Any], field_name: str, expansion: list[str] | str | None
) -> bool:
    expanded = False
    val = item.get(field_name)
    if isinstance(val, list):
        new_list = []
        for v in val:
            if v == "any":
                if isinstance(expansion, list) and expansion:
                    expanded = True
                    new_list.append(", ".join(expansion))
                else:
                    new_list.append("0.0.0.0/0")
            else:
                new_list.append(v)
        item[field_name] = new_list
    elif val == "any":
        if isinstance(expansion, list) and expansion:
            item[field_name] = ", ".join(expansion)
            expanded = True
        else:
            item[field_name] = "0.0.0.0/0"
    return expanded


def process_items(
    items: list[dict[str, Any]],
    params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Process a list of rule items, expanding 'any' based on matching zoneRules."""
    p = params or {}
    src_field = p.get("srcField", "src_ip")
    dst_field = p.get("dstField", "dst_ip")
    zone_rules = p.get("zoneRules", [])
    output_zone_tag = p.get("outputZoneTag", True)

    out_items: list[dict[str, Any]] = []

    for orig in items:
        item = dict(orig)
        matched_rule: dict[str, Any] | None = None

        for rule in zone_rules:
            m = rule.get("match", {})
            ok = True
            for field_name, regex_str in m.items():
                val = item.get(field_name)
                v_str = "" if val is None else str(val)
                try:
                    if not re.search(str(regex_str), v_str, re.IGNORECASE):
                        ok = False
                        break
                except re.error:
                    ok = False
                    break
            if ok:
                matched_rule = rule
                break

        expanded_src = _process_field(
            item, src_field, matched_rule.get("srcAny") if matched_rule else None
        )
        expanded_dst = _process_field(
            item, dst_field, matched_rule.get("dstAny") if matched_rule else None
        )
        expanded = expanded_src or expanded_dst

        if output_zone_tag:
            item["_zoneMatch"] = bool(matched_rule is not None)
            item["_anyExpanded"] = expanded

        out_items.append(item)

    return out_items
