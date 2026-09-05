"""Zone Rule Advisor service.

Ported from n8n-nodes-zone-any-resolver (ZoneRuleAdvisor.node.js).
Analyzes firewall rules with 'any' src/dst and recommends CIDR replacements
based on sibling rules in the same zone.
"""

from __future__ import annotations

import json
from typing import Any

from flow_auditor.common.ip_utils import (
    aggregate_cidrs,
    count_addresses,
    enclosing_supernet,
    parse_cidr,
)


def zone_key_from_fields(item: dict[str, Any], zone_fields: list[str]) -> str:
    """Extract a stable JSON string key for the zone fields."""
    key = {f: item.get(f) for f in zone_fields}
    return json.dumps(key, sort_keys=True)


def advise(
    all_rules: list[dict[str, Any]],
    params: dict[str, Any] | None = None,
    rules_to_advise: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Generate CIDR replacement advice for rules containing 'any' src/dst."""
    p = params or {}
    src_field = p.get("srcField", "src_ip")
    dst_field = p.get("dstField", "dst_ip")
    zone_fields = p.get("zoneFields", ["acl"])
    any_value = p.get("anyValue", "any")
    aggregation_prefix = int(p.get("aggregationPrefix", 24))

    groups: dict[str, list[dict[str, Any]]] = {}
    for r in all_rules:
        k = zone_key_from_fields(r, zone_fields)
        groups.setdefault(k, []).append(r)

    targets = (
        rules_to_advise
        if rules_to_advise is not None and isinstance(rules_to_advise, list)
        else [
            r for r in all_rules if r.get(src_field) == any_value or r.get(dst_field) == any_value
        ]
    )

    out: list[dict[str, Any]] = []

    for permissive in targets:
        k = zone_key_from_fields(permissive, zone_fields)
        zone_key_obj = json.loads(k)
        group = groups.get(k, [])

        for field in [src_field, dst_field]:
            if permissive.get(field) != any_value:
                continue

            sibling_cidrs: list[str] = []
            for s in group:
                if s is permissive:
                    continue
                val = s.get(field)
                if val and val != any_value:
                    if isinstance(val, list):
                        sibling_cidrs.extend([str(x).strip() for x in val if str(x).strip()])
                    else:
                        parts = [x.strip() for x in str(val).split(",") if x.strip()]
                        sibling_cidrs.extend(parts)

            field_label = "src" if field == src_field else "dst"

            if not sibling_cidrs:
                out.append(
                    {
                        "zoneKey": zone_key_obj,
                        "permissiveRule": permissive,
                        "field": field_label,
                        "warning": "no explicit siblings",
                    }
                )
                continue

            recommended_cidrs = aggregate_cidrs(sibling_cidrs, aggregation_prefix)
            enclosing = enclosing_supernet(recommended_cidrs)
            agg_count = count_addresses(recommended_cidrs)

            _, enc_prefix = parse_cidr(enclosing)
            supernet_count = 1 << (32 - enc_prefix)

            score = 1.0 - (agg_count / supernet_count) if supernet_count > 0 else 0.0

            out.append(
                {
                    "zoneKey": zone_key_obj,
                    "permissiveRule": permissive,
                    "field": field_label,
                    "siblingCidrs": sibling_cidrs,
                    "recommendedCidrs": recommended_cidrs,
                    "enclosingSupernet": enclosing,
                    "permissivenessScore": round(score, 6),
                    "recommendation": (
                        f"Replace {field} any with {json.dumps(recommended_cidrs)} "
                        f"(derived from {len(sibling_cidrs)} sibling entries)"
                    ),
                }
            )

    return out
