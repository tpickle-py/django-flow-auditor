"""Tests for common IP and CIDR utilities."""

import pytest

from flow_auditor.common.ip_utils import (
    aggregate_cidrs,
    cidr_range,
    count_addresses,
    enclosing_supernet,
    int_to_ip,
    ip_in_cidr,
    ip_to_int,
    is_ip,
    mask_for,
    mask_to_cidr,
    parse_cidr,
    range_to_cidrs,
)


def test_is_ip():
    assert is_ip("192.168.1.1") is True
    assert is_ip("10.0.0.1") is True
    assert is_ip("256.0.0.1") is False
    assert is_ip("any") is False
    assert is_ip(None) is False
    assert is_ip("") is False


def test_ip_to_int_and_int_to_ip():
    val = ip_to_int("192.168.1.1")
    assert int_to_ip(val) == "192.168.1.1"

    val0 = ip_to_int("0.0.0.0")
    assert val0 == 0
    assert int_to_ip(val0) == "0.0.0.0"

    with pytest.raises(ValueError):
        ip_to_int("invalid")


def test_mask_to_cidr():
    assert mask_to_cidr("255.255.255.0") == 24
    assert mask_to_cidr("255.255.0.0") == 16
    assert mask_to_cidr("255.0.0.0") == 8
    assert mask_to_cidr("255.255.255.255") == 32
    assert mask_to_cidr("0.0.0.0") == 0
    assert mask_to_cidr("0.0.0.255") == 24  # Wildcard mask


def test_parse_cidr_and_range():
    base, prefix = parse_cidr("10.0.0.0/24")
    assert prefix == 24
    start, end = cidr_range(base, prefix)
    assert int_to_ip(start) == "10.0.0.0"
    assert int_to_ip(end) == "10.0.0.255"

    base_host, prefix_host = parse_cidr("192.168.1.50")
    assert prefix_host == 32
    assert int_to_ip(base_host) == "192.168.1.50"


def test_ip_in_cidr():
    assert ip_in_cidr("10.0.0.5", "10.0.0.0/24") is True
    assert ip_in_cidr("10.0.1.5", "10.0.0.0/24") is False
    assert ip_in_cidr("10.0.0.5", "any") is True
    assert ip_in_cidr("192.168.1.1", "192.168.1.1") is True
    assert ip_in_cidr("192.168.1.2", "192.168.1.1") is False


def test_range_to_cidrs():
    start = ip_to_int("10.0.0.0")
    end = ip_to_int("10.0.0.255")
    cidrs = range_to_cidrs(start, end)
    assert cidrs == ["10.0.0.0/24"]


def test_aggregate_cidrs():
    inputs = ["10.0.0.0/25", "10.0.0.128/25"]
    agg = aggregate_cidrs(inputs, 24)
    assert "10.0.0.0/24" in agg


def test_enclosing_supernet():
    inputs = ["192.168.1.0/24", "192.168.2.0/24"]
    supernet = enclosing_supernet(inputs)
    assert supernet in ("192.168.0.0/22", "192.168.0.0/23")


def test_count_addresses():
    assert count_addresses(["10.0.0.0/24"]) == 256
    assert count_addresses(["10.0.0.0/24", "192.168.1.0/24"]) == 512


def test_ip_utils_boundary_and_invalid_inputs():
    # Invalid mask_to_cidr
    assert mask_to_cidr("255.255.255") is None
    assert mask_to_cidr("256.0.0.0") is None
    assert mask_to_cidr("abc.def.ghi.jkl") is None

    # Invalid ip_to_int
    with pytest.raises(ValueError):
        ip_to_int("1.2.3.4.5")
    with pytest.raises(ValueError):
        ip_to_int("1.2.3.300")
    with pytest.raises(ValueError):
        ip_to_int("1.2.3.abc")

    # Aggregate CIDRs empty and non-contiguous runs
    assert aggregate_cidrs([], 24) == []
    non_contig = aggregate_cidrs(["10.0.0.0/24", "10.0.2.0/24"], 24)
    assert len(non_contig) == 2

    # Enclosing supernet empty
    assert enclosing_supernet([]) == "0.0.0.0/0"

    # Full 0 to 2^32-1 range and inverted range
    all_ip = range_to_cidrs(0, 0xFFFFFFFF)
    assert all_ip == ["0.0.0.0/0"]
    assert range_to_cidrs(100, 50) == []

    # Large range aggregation (preventing memory leaks/blowups)
    assert aggregate_cidrs(["0.0.0.0/0"], 24) == ["0.0.0.0/0"]
    assert aggregate_cidrs(["10.0.0.0/8"], 16) == ["10.0.0.0/8"]
    assert aggregate_cidrs(["10.0.0.0/24", "10.0.1.0/24"], 24) == ["10.0.0.0/23"]

    # mask_for prefix checks
    assert mask_for(0) == 0
    assert mask_for(24) == 0xFFFFFF00
    assert mask_for(32) == 0xFFFFFFFF

    # Non-contiguous mask returns None
    assert mask_to_cidr("255.0.255.0") is None

    # Invalid ip_in_cidr returns False
    assert ip_in_cidr("not-an-ip", "10.0.0.0/24") is False

    # Invalid CIDR prefix and non-IPv4
    with pytest.raises(ValueError):
        parse_cidr("10.0.0.0/35")
    with pytest.raises(ValueError):
        parse_cidr("2001:db8::/32")
