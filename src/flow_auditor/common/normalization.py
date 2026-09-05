"""Request normalization and parameter merging utilities."""

from __future__ import annotations

import json
from typing import Any

ASA_QUERY_OPTION_KEYS = (
    "mode",
    "groupByAcl",
    "includeObjects",
    "includeRaw",
)


def merged_filter(
    payload_filter: dict[str, Any] | None,
    query_overrides: dict[str, Any] | None,
) -> dict[str, Any]:
    """Merge payload filter dictionary with query parameter overrides."""
    base: dict[str, Any] = dict(payload_filter or {})
    if not query_overrides:
        return base

    action = query_overrides.get("action")
    if action is not None:
        base["action"] = action

    proto = query_overrides.get("proto")
    if proto is not None:
        base["proto"] = proto

    return base


def merged_options(
    payload_options: dict[str, Any] | None,
    query_overrides: dict[str, Any] | None,
) -> dict[str, Any]:
    """Merge payload options dictionary with query parameter overrides."""
    base: dict[str, Any] = dict(payload_options or {})
    if not query_overrides:
        return base

    for key in ASA_QUERY_OPTION_KEYS:
        val = query_overrides.get(key)
        if val is not None:
            # Cast string booleans if necessary
            if isinstance(val, str):
                if val.lower() in ("true", "1", "yes"):
                    base[key] = True
                elif val.lower() in ("false", "0", "no"):
                    base[key] = False
                else:
                    base[key] = val
            else:
                base[key] = val

    return base


def parse_json_config(config: str | Any) -> Any:
    """Safely parse JSON configuration string or return input if already dict/list."""
    if isinstance(config, (dict, list)):
        return config
    if not isinstance(config, str):
        return config
    return json.loads(config)
