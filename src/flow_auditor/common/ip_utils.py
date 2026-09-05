"""IP and CIDR utilities for firewall rules and flow auditing using netaddr."""

from __future__ import annotations

import re

import netaddr

IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_ip(s: str | None) -> bool:
    """Return True if s is a valid IPv4 string format."""
    if not s or not isinstance(s, str):
        return False
    return netaddr.valid_ipv4(s.strip())


def ip_to_int(ip: str) -> int:
    """Parse an IPv4 address string into a 32-bit unsigned integer."""
    if not is_ip(ip):
        raise ValueError(f"Invalid IP address: '{ip}'")
    return int(netaddr.IPAddress(ip.strip(), 4))


def int_to_ip(i: int) -> str:
    """Convert a 32-bit unsigned integer to an IPv4 dotted string."""
    return str(netaddr.IPAddress(i & 0xFFFFFFFF, 4))


def mask_to_cidr(mask: str) -> int | None:
    """Convert a subnet mask (or wildcard mask) to a CIDR prefix length."""
    if not isinstance(mask, str) or not netaddr.valid_ipv4(mask.strip()):
        return None
    ip = netaddr.IPAddress(mask.strip(), 4)
    if ip.value == 0:
        return 0
    if ip.is_netmask():
        return ip.netmask_bits()
    if ip.is_hostmask():
        return netaddr.IPAddress(ip.value ^ 0xFFFFFFFF, 4).netmask_bits()
    return None


def mask_for(prefix: int) -> int:
    """Return 32-bit subnet mask for given CIDR prefix."""
    if prefix <= 0:
        return 0
    if prefix >= 32:
        return 0xFFFFFFFF
    return int(netaddr.IPNetwork(f"0.0.0.0/{prefix}").netmask.value)


def parse_cidr(s: str) -> tuple[int, int]:
    """Parse a CIDR or bare IP into (base_ip_int, prefix_len)."""
    s = s.strip()
    try:
        net = netaddr.IPNetwork(s)
        if net.version != 4:
            raise ValueError(f"Not an IPv4 CIDR: '{s}'")
        return int(net.network), net.prefixlen
    except Exception as err:
        raise ValueError(f"Invalid CIDR format: '{s}'") from err


def cidr_range(base_int: int, prefix: int) -> tuple[int, int]:
    """Return (start_int, end_int) for a given base and prefix."""
    net = netaddr.IPNetwork(f"{int_to_ip(base_int)}/{prefix}")
    return int(net.first), int(net.last)


def ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if ip falls within the network described by cidr."""
    normalized = cidr.strip().lower()
    if normalized in ("any", "0.0.0.0/0"):
        return True
    try:
        net = netaddr.IPNetwork(normalized)
        addr = netaddr.IPAddress(ip.strip())
        return addr in net
    except Exception:
        return False


def range_to_cidrs(start: int, end: int) -> list[str]:
    """Convert an inclusive IP int range [start, end] into a minimal list of CIDRs."""
    start = start & 0xFFFFFFFF
    end = end & 0xFFFFFFFF
    if start > end:
        return []
    return [
        str(c)
        for c in netaddr.iprange_to_cidrs(netaddr.IPAddress(start, 4), netaddr.IPAddress(end, 4))
    ]


def aggregate_cidrs(cidr_strings: list[str], prefix_len: int) -> list[str]:
    """Aggregate CIDRs into blocks of size prefix_len and merge contiguous runs."""
    if not cidr_strings:
        return []
    block_size = 1 << (32 - prefix_len)
    intervals: list[tuple[int, int]] = []
    for s in cidr_strings:
        net = netaddr.IPNetwork(s.strip())
        start = int(net.first)
        end = int(net.last)
        start_aligned = (start // block_size) * block_size
        end_aligned = min(0xFFFFFFFF, (end // block_size) * block_size + block_size - 1)
        intervals.append((start_aligned, end_aligned))

    if not intervals:
        return []

    intervals.sort(key=lambda x: x[0])
    merged: list[tuple[int, int]] = []
    cur_start, cur_end = intervals[0]
    for nxt_start, nxt_end in intervals[1:]:
        if nxt_start <= cur_end + 1:
            cur_end = max(cur_end, nxt_end)
        else:
            merged.append((cur_start, cur_end))
            cur_start, cur_end = nxt_start, nxt_end
    merged.append((cur_start, cur_end))

    result: list[str] = []
    for s, e in merged:
        result.extend(
            str(c)
            for c in netaddr.iprange_to_cidrs(netaddr.IPAddress(s, 4), netaddr.IPAddress(e, 4))
        )
    return result


def enclosing_supernet(cidr_list: list[str]) -> str:
    """Find the smallest enclosing supernet containing all CIDRs in cidr_list."""
    if not cidr_list:
        return "0.0.0.0/0"
    networks = [netaddr.IPNetwork(s.strip()) for s in cidr_list]
    return str(netaddr.spanning_cidr(networks))


def count_addresses(cidr_list: list[str]) -> int:
    """Return total number of addresses represented by cidr_list."""
    return sum(len(netaddr.IPNetwork(s.strip())) for s in cidr_list)
