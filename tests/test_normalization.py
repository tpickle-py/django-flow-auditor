"""Tests for flow input normalization."""

from flow_auditor.common.normalization import merged_filter, merged_options, parse_json_config


def test_merged_filter_empty():
    assert merged_filter(None, None) == {}
    assert merged_filter({"action": "permit"}, None) == {"action": "permit"}


def test_merged_filter_with_overrides():
    res = merged_filter(
        {"action": "deny", "other": 123},
        {"action": "permit", "proto": "tcp"},
    )
    assert res == {"action": "permit", "other": 123, "proto": "tcp"}


def test_merged_options_parsing():
    base = {"mode": "grouped"}
    overrides = {
        "mode": "flat",
        "groupByAcl": "true",
        "includeObjects": "0",
        "includeRaw": "yes",
    }
    merged = merged_options(base, overrides)
    assert merged["mode"] == "flat"
    assert merged["groupByAcl"] is True
    assert merged["includeObjects"] is False
    assert merged["includeRaw"] is True


def test_parse_json_config():
    assert parse_json_config({"a": 1}) == {"a": 1}
    assert parse_json_config([1, 2]) == [1, 2]
    assert parse_json_config('{"key": "value"}') == {"key": "value"}
    assert parse_json_config(123) == 123
