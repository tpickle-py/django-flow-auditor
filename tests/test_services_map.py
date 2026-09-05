"""Tests for services, protocols, and port mappings."""

from flow_auditor.common.services_map import parse_service, resolve_port


def test_resolve_port():
    assert resolve_port("http") == "80"
    assert resolve_port("www") == "80"
    assert resolve_port("https") == "443"
    assert resolve_port("ssh") == "22"
    assert resolve_port("8080") == "8080"
    assert resolve_port("unknown-token") == "unknown-token"
    assert resolve_port(None) is None


def test_parse_service():
    assert parse_service("tcp/443") == [{"proto": "tcp", "port": 443}]
    assert parse_service("http") == [{"proto": "tcp", "port": 80}]
    assert parse_service("any") == [{"proto": "any", "port": "any"}]
    assert parse_service("tcp/80-85") == [
        {"proto": "tcp", "start_port": 80, "end_port": 85, "port": "80-85"}
    ]

    # Overrides
    overrides = {"custom-app": {"proto": "tcp", "port": 9999}}
    assert parse_service("custom-app", overrides) == [{"proto": "tcp", "port": 9999}]
