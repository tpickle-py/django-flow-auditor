"""Cisco ASA / Network Flow Diff Engine.

Ported from n8n-nodes-flowdiff (diffEngine.js).
Expands flow rules into atomic (src, dst, svc) tuples, diffs configurations,
detects renames, splits, merges, and partial matches across ACL names.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any


def normalise_key(line: str | None) -> str:
    """Strip ASDM 'line N ' prefix."""
    return re.sub(r"^line\s+\d+\s+", "", (line or "").strip(), flags=re.IGNORECASE).strip()


def tuple_fingerprint(t: dict[str, Any]) -> str:
    """Fingerprint a tuple by everything EXCEPT the ACL name (for rename detection)."""
    return ":::".join(
        [
            (t.get("action") or "").lower(),
            (t.get("source") or "").lower(),
            (t.get("dest") or "").lower(),
            (t.get("service") or "").lower(),
        ]
    )


def tuple_key(acl: str, action: str, src: str, dst: str, svc: str) -> str:
    """Build a stable lowercased string key for an atomic flow tuple."""
    return ":::".join(
        [
            (acl or "").lower(),
            (action or "").lower(),
            (src or "").lower(),
            (dst or "").lower(),
            (svc or "").lower(),
        ]
    )


def expand_tuples(flow: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand a flow rule into an array of atomic (src, dst, svc) tuples."""
    acl = flow.get("acl", "")
    action = flow.get("action", "")
    line = flow.get("line", "")
    sources = flow.get("source", []) or ["any"]
    dests = flow.get("dest", []) or ["any"]
    services = flow.get("services", []) or ["any/any"]

    tuples = []
    for s in sources:
        for d in dests:
            for sv in services:
                tuples.append(
                    {
                        "acl": acl,
                        "action": action,
                        "source": s,
                        "dest": d,
                        "service": sv,
                        "line": line,
                    }
                )
    return tuples


def is_unresolved(value: Any) -> bool:
    """Return True if a source/dest/service string is an unresolved object reference."""
    return isinstance(value, str) and value.startswith("unresolved:")


def has_unresolved_field(item: dict[str, Any]) -> bool:
    """Return True if any field of a change/rename item contains an unresolved value."""
    return (
        is_unresolved(item.get("source"))
        or is_unresolved(item.get("dest"))
        or is_unresolved(item.get("service"))
    )


def project_unresolved(item: dict[str, Any]) -> dict[str, Any]:
    """Project a change item to {line, <field>: <unresolved>}."""
    out: dict[str, Any] = {"line": item.get("line", "")}
    if is_unresolved(item.get("source")):
        out["source"] = item["source"]
    if is_unresolved(item.get("dest")):
        out["dest"] = item["dest"]
    if is_unresolved(item.get("service")):
        out["service"] = item["service"]
    return out


def build_ignore_filter(patterns: list[str] | None) -> Callable[[str], bool]:
    """Compile an array of ACL name patterns into a predicate function."""
    if not patterns:
        return lambda _acl: False

    regexes = []
    for s in patterns:
        s_clean = str(s).strip()
        if not s_clean:
            continue
        try:
            regexes.append(re.compile(s_clean, re.IGNORECASE))
        except re.error:
            regexes.append(re.compile(re.escape(s_clean), re.IGNORECASE))

    if not regexes:
        return lambda _acl: False

    return lambda acl: any(rx.search(acl or "") for rx in regexes)


def build_peer_index(
    tuples: list[dict[str, Any]],
) -> dict[str, dict[str, set[str]]]:
    """Build index from normalise_key(line) -> {sources, dests, services}."""
    idx: dict[str, dict[str, set[str]]] = {}
    for t in tuples:
        k = normalise_key(t.get("line", ""))
        if k not in idx:
            idx[k] = {"sources": set(), "dests": set(), "services": set()}
        entry = idx[k]
        if t.get("source"):
            entry["sources"].add(t["source"])
        if t.get("dest"):
            entry["dests"].add(t["dest"])
        if t.get("service"):
            entry["services"].add(t["service"])
    return idx


def truncate_peers(items: list[str], max_n: int = 5) -> list[str]:
    """Truncate a peer list if it exceeds max_n items."""
    s = sorted(items)
    if len(s) <= max_n:
        return s
    return s[:max_n] + [f"...+{len(s) - max_n} more"]


def enrich_change(
    c: dict[str, Any],
    peer_index: dict[str, dict[str, set[str]]],
    max_peers: int = 5,
) -> dict[str, Any]:
    """Attach peer context to a change record."""
    k = normalise_key(c.get("line", ""))
    peers = peer_index.get(k)
    all_src = sorted(peers["sources"]) if peers else [c.get("source", "")]
    all_dst = sorted(peers["dests"]) if peers else [c.get("dest", "")]
    all_svc = sorted(peers["services"]) if peers else [c.get("service", "")]

    return {
        **c,
        "all_sources": truncate_peers(all_src, max_peers),
        "all_destinations": truncate_peers(all_dst, max_peers),
        "all_services": truncate_peers(all_svc, max_peers),
    }


def detect_renames(
    revoked: list[dict[str, Any]],
    granted: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Cross-match revoked and granted tuples to detect renames, splits, merges, and partials."""
    rev_by_fp: dict[str, list[dict[str, Any]]] = {}
    for r in revoked:
        fp = tuple_fingerprint(r)
        rev_by_fp.setdefault(fp, []).append(r)

    matched_rev_indices = set()
    matched_gra_indices = set()
    renames: list[dict[str, Any]] = []

    for g_idx, g in enumerate(granted):
        fp = tuple_fingerprint(g)
        candidates = rev_by_fp.get(fp, [])
        match_r: dict[str, Any] | None = None
        match_r_idx: int | None = None

        for r in candidates:
            r_idx = revoked.index(r)
            if r_idx not in matched_rev_indices and r.get("acl") != g.get("acl"):
                match_r = r
                match_r_idx = r_idx
                break

        if match_r and match_r_idx is not None:
            matched_rev_indices.add(match_r_idx)
            matched_gra_indices.add(g_idx)
            renames.append(
                {
                    "change_type": "rename",
                    "old_acl": match_r.get("acl", ""),
                    "new_acl": g.get("acl", ""),
                    "action": g.get("action", ""),
                    "source": g.get("source", ""),
                    "dest": g.get("dest", ""),
                    "service": g.get("service", ""),
                    "old_line": match_r.get("line", ""),
                    "new_line": g.get("line", ""),
                }
            )

    unmatched_rev = [r for i, r in enumerate(revoked) if i not in matched_rev_indices]
    unmatched_gra = [g for i, g in enumerate(granted) if i not in matched_gra_indices]
    return renames, unmatched_rev, unmatched_gra


def collapse_changes(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Recombine atomic change items back into ACL-level summary objects."""
    by_key: dict[str, dict[str, Any]] = {}
    for c in changes:
        k = ":::".join([c.get("change_type", ""), c.get("acl", ""), c.get("action", "")])
        if k not in by_key:
            by_key[k] = {
                "change_type": c.get("change_type"),
                "acl": c.get("acl"),
                "action": c.get("action"),
                "sources": set(),
                "destinations": set(),
                "services": set(),
                "lines": set(),
                "tuple_count": 0,
            }
        entry = by_key[k]
        entry["sources"].add(c.get("source"))
        entry["destinations"].add(c.get("dest"))
        entry["services"].add(c.get("service"))
        if c.get("line"):
            entry["lines"].add(c["line"])
        entry["tuple_count"] += 1

    out: list[dict[str, Any]] = []
    for entry in by_key.values():
        out.append(
            {
                "change_type": entry["change_type"],
                "acl": entry["acl"],
                "action": entry["action"],
                "sources": sorted(filter(None, entry["sources"])),
                "destinations": sorted(filter(None, entry["destinations"])),
                "services": sorted(filter(None, entry["services"])),
                "lines": sorted(filter(None, entry["lines"])),
                "tuple_count": entry["tuple_count"],
            }
        )
    return out


def group_by_acl(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group flat flow rules by ACL name."""
    by_acl: dict[str, dict[str, Any]] = {}
    for f in flows:
        acl = f.get("acl", "")
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
                "action": f.get("action"),
                "source": f.get("source", []),
                "dest": f.get("dest", []),
                "services": f.get("services", []),
                "line": f.get("line"),
            }
        )
    return list(by_acl.values())


def diff_flows(
    flows_a: list[dict[str, Any]],
    flows_b: list[dict[str, Any]],
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Diff two parsed flow lists (flows_a = before, flows_b = after)."""
    opts = options or {}
    do_detect_renames = opts.get("detectRenames", True)
    ignore_filter = build_ignore_filter(opts.get("ignorePatterns") or opts.get("ignoreAcls"))
    collapse = opts.get("collapse", False)
    unresolved_mode = opts.get("unresolvedMode", "include")  # "include", "exclude", "segregate"
    max_peers = opts.get("maxPeers", 5)

    # 1. Expand all rules into atomic tuples
    tuples_a = []
    for f in flows_a:
        tuples_a.extend(expand_tuples(f))

    tuples_b = []
    for f in flows_b:
        tuples_b.extend(expand_tuples(f))

    # Build peer context indices
    peers_a = build_peer_index(tuples_a)
    peers_b = build_peer_index(tuples_b)

    # 2. Build set of keys
    map_a: dict[str, dict[str, Any]] = {}
    for t in tuples_a:
        if not ignore_filter(t.get("acl", "")):
            k = tuple_key(t["acl"], t["action"], t["source"], t["dest"], t["service"])
            map_a[k] = t

    map_b: dict[str, dict[str, Any]] = {}
    for t in tuples_b:
        if not ignore_filter(t.get("acl", "")):
            k = tuple_key(t["acl"], t["action"], t["source"], t["dest"], t["service"])
            map_b[k] = t

    # 3. Compute revoked (in A not B) and granted (in B not A)
    raw_revoked: list[dict[str, Any]] = []
    for k, t in map_a.items():
        if k not in map_b:
            raw_revoked.append({**t, "change_type": "access_revoked"})

    raw_granted: list[dict[str, Any]] = []
    for k, t in map_b.items():
        if k not in map_a:
            raw_granted.append({**t, "change_type": "access_granted"})

    # 4. Rename detection
    renames: list[dict[str, Any]] = []
    if do_detect_renames:
        renames, final_revoked, final_granted = detect_renames(raw_revoked, raw_granted)
    else:
        final_revoked = raw_revoked
        final_granted = raw_granted

    # 5. Enrich with peer context
    enriched_revoked = [enrich_change(c, peers_a, max_peers) for c in final_revoked]
    enriched_granted = [enrich_change(c, peers_b, max_peers) for c in final_granted]
    all_changes = enriched_revoked + enriched_granted

    # 6. Unresolved filtering / segregation
    segregated_unresolved: list[dict[str, Any]] = []
    if unresolved_mode == "exclude":
        all_changes = [c for c in all_changes if not has_unresolved_field(c)]
        renames = [r for r in renames if not has_unresolved_field(r)]
    elif unresolved_mode == "segregate":
        clean_changes = []
        for c in all_changes:
            if has_unresolved_field(c):
                segregated_unresolved.append(project_unresolved(c))
            else:
                clean_changes.append(c)
        all_changes = clean_changes

    # 7. Collapse if requested
    output_changes = collapse_changes(all_changes) if collapse else all_changes

    # Sort deterministic
    def _change_sort_key(x: dict[str, Any]) -> tuple:
        return (
            x.get("acl", ""),
            0 if x.get("change_type") == "access_revoked" else 1,
            x.get("line", ""),
            x.get("source", ""),
            x.get("dest", ""),
        )

    output_changes.sort(key=_change_sort_key)

    result: dict[str, Any] = {
        "changes": output_changes,
        "renames": renames,
        "summary": {
            "access_revoked": len(enriched_revoked),
            "access_granted": len(enriched_granted),
            "renames": len(renames),
            "total_changes": len(output_changes),
        },
    }
    if unresolved_mode == "segregate":
        result["unresolved"] = segregated_unresolved

    return result
