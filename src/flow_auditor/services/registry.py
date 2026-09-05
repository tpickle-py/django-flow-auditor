"""Registry mapping module slugs to pure Python adapter engines."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from flow_auditor.common.normalization import merged_filter, merged_options, parse_json_config
from flow_auditor.services.approval import check_flow_approvals
from flow_auditor.services.cisco_asa import parse_asa_config
from flow_auditor.services.cisco_asa import parse_objects as parse_asa_objects
from flow_auditor.services.flowdiff import diff_flows
from flow_auditor.services.juniper_srx import parse_config as parse_srx_config
from flow_auditor.services.juniper_srx import parse_objects as parse_srx_objects
from flow_auditor.services.zone_advisor import advise
from flow_auditor.services.zone_resolver import process_items


@dataclass
class ModuleAdapter:
    slug: str
    adapter_name: str
    description: str
    actions: dict[str, str] = field(default_factory=dict)
    status: str = "ok"
    handler: Callable[[Any, dict[str, Any], dict[str, Any], dict[str, Any]], dict[str, Any]] = None  # type: ignore


class EngineRegistry:
    """Registry holding all available firewall and audit adapter engines."""

    def __init__(self) -> None:
        self._modules: dict[str, ModuleAdapter] = {}
        self._register_builtins()

    def register(self, module: ModuleAdapter) -> None:
        self._modules[module.slug] = module
        if module.adapter_name != module.slug:
            self._modules[module.adapter_name] = module

    def get(self, slug: str) -> ModuleAdapter | None:
        return self._modules.get(slug)

    def list_modules(self) -> list[dict[str, Any]]:
        seen = set()
        out = []
        for mod in self._modules.values():
            if mod.slug in seen:
                continue
            seen.add(mod.slug)
            out.append(
                {
                    "slug": mod.slug,
                    "adapter": mod.adapter_name,
                    "description": mod.description,
                    "status": mod.status,
                    "actions": mod.actions,
                }
            )
        return out

    def _register_builtins(self) -> None:
        # Cisco ASA
        def _run_cisco(
            config: Any,
            options: dict[str, Any],
            filter_params: dict[str, Any],
            query: dict[str, Any],
        ) -> dict[str, Any]:
            action = str(query.get("action") or filter_params.get("action") or "parse").lower()
            merged_opts = {
                "mode": "config",
                **filter_params,
                **options,
            }
            config_str = config if isinstance(config, str) else json.dumps(config)
            if action == "objects":
                return {"data": parse_asa_objects(config_str), "exportUsed": "parseObjects"}
            return {
                "data": parse_asa_config(config_str, merged_opts),
                "exportUsed": "parseAsaConfig",
            }

        self.register(
            ModuleAdapter(
                slug="cisco-asa-parser",
                adapter_name="cisco-asa",
                description="Parses Cisco ASA ACL configurations into normalized network flow records",
                actions={"parse": "parseAsaConfig", "objects": "parseObjects"},
                handler=_run_cisco,
            )
        )

        # Juniper SRX
        def _run_juniper(
            config: Any,
            options: dict[str, Any],
            filter_params: dict[str, Any],
            query: dict[str, Any],
        ) -> dict[str, Any]:
            action = str(query.get("action") or filter_params.get("action") or "parse").lower()
            merged_opts = {
                **options,
                **filter_params,
            }
            config_str = config if isinstance(config, str) else json.dumps(config)
            if action == "objects":
                return {"data": parse_srx_objects(config_str), "exportUsed": "parseObjects"}
            return {"data": parse_srx_config(config_str, merged_opts), "exportUsed": "parseConfig"}

        self.register(
            ModuleAdapter(
                slug="juniper-srx-parser",
                adapter_name="juniper-srx",
                description="Parses Juniper SRX / JunOS security policies into normalized network flow records",
                actions={"parse": "parseConfig", "objects": "parseObjects"},
                handler=_run_juniper,
            )
        )

        # FlowDiff
        def _run_flowdiff(
            config: Any,
            options: dict[str, Any],
            filter_params: dict[str, Any],
            query: dict[str, Any],
        ) -> dict[str, Any]:
            parsed = parse_json_config(config) if isinstance(config, str) else config
            flows_a = options.get("flowsA") or (
                parsed.get("flowsA") if isinstance(parsed, dict) else None
            )
            flows_b = options.get("flowsB") or (
                parsed.get("flowsB") if isinstance(parsed, dict) else None
            )
            diff_opts = options.get("diffOptions") or (
                parsed.get("options") if isinstance(parsed, dict) else {}
            )

            if not isinstance(flows_a, list) or not isinstance(flows_b, list):
                raise ValueError(
                    "flowdiff requires flowsA and flowsB lists in config JSON or options"
                )

            return {"data": diff_flows(flows_a, flows_b, diff_opts), "exportUsed": "diffFlows"}

        self.register(
            ModuleAdapter(
                slug="flowdiff",
                adapter_name="flowdiff",
                description="Diffs two sets of network flows to detect added, removed, and renamed access rules",
                actions={"diff": "diffFlows"},
                handler=_run_flowdiff,
            )
        )

        # Flow Approval Checker
        def _run_approval(
            config: Any,
            options: dict[str, Any],
            filter_params: dict[str, Any],
            query: dict[str, Any],
        ) -> dict[str, Any]:
            parsed = parse_json_config(config) if isinstance(config, str) else config
            approved = (
                options.get("approved_flows")
                or (parsed.get("approved_flows") if isinstance(parsed, dict) else None)
                or []
            )
            to_check = (
                options.get("flows_to_check")
                or (parsed.get("flows_to_check") if isinstance(parsed, dict) else None)
                or []
            )
            if not isinstance(approved, list) or not isinstance(to_check, list):
                raise ValueError(
                    "flow-approval-checker requires approved_flows and flows_to_check arrays"
                )

            params = options.get("params") or {}
            return {
                "data": check_flow_approvals(approved, to_check, params),
                "exportUsed": "check_flow_approvals",
            }

        self.register(
            ModuleAdapter(
                slug="flow-approval-checker",
                adapter_name="flow-approval-checker",
                description="Checks candidate flows against approved flows, returning approved, partial, or not_approved",
                actions={"check": "check_flow_approvals"},
                handler=_run_approval,
            )
        )

        # Zone Any Resolver & Advisor
        def _run_zone(
            config: Any,
            options: dict[str, Any],
            filter_params: dict[str, Any],
            query: dict[str, Any],
        ) -> dict[str, Any]:
            action = str(query.get("action") or filter_params.get("action") or "parse").lower()
            parsed = parse_json_config(config) if isinstance(config, str) else config

            if action == "advise":
                all_rules = (
                    parsed.get("allRules")
                    if isinstance(parsed, dict)
                    else (parsed if isinstance(parsed, list) else [])
                )
                rules_to_advise = parsed.get("rulesToAdvise") if isinstance(parsed, dict) else None
                return {"data": advise(all_rules, options, rules_to_advise), "exportUsed": "advise"}

            items = (
                parsed
                if isinstance(parsed, list)
                else (parsed.get("items") if isinstance(parsed, dict) else None)
            )
            if not isinstance(items, list):
                raise ValueError(
                    "zone-any-resolver requires config to be a list or {'items': [...]}"
                )

            zone_opts = {
                "srcField": "source",
                "dstField": "dest",
                **options,
            }
            return {"data": process_items(items, zone_opts), "exportUsed": "process_items"}

        self.register(
            ModuleAdapter(
                slug="zone-any-resolver",
                adapter_name="zone-any-resolver",
                description="Zone-aware any resolver and rule advisor for firewall flow approval",
                actions={"parse": "process_items", "advise": "advise"},
                handler=_run_zone,
            )
        )


_default_registry = EngineRegistry()


def get_default_registry() -> EngineRegistry:
    """Return the singleton default registry."""
    return _default_registry


def execute_module(
    slug: str,
    config: Any,
    options: dict[str, Any] | None = None,
    filter_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a module by slug with normalized options and query parameters."""
    reg = get_default_registry()
    adapter = reg.get(slug)
    if not adapter:
        raise ValueError(f"Unknown module slug: '{slug}'")

    context_query = query or {}
    context_filter = merged_filter(filter_params, context_query)
    context_options = merged_options(options, context_query)

    return adapter.handler(config, context_options, context_filter, context_query)
